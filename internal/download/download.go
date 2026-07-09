package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/torob/mirror-sync/internal/httpx"
	"github.com/torob/mirror-sync/internal/publish"
	"github.com/torob/mirror-sync/internal/safe"
)

type Expected struct {
	RelPath string
	Size    int64
	SHA256  string
	Verify  func(path string) error
}

type ensureOneFunc func(context.Context, string, string, []*httpx.Client, Expected) error

func EnsureSynced(ctx context.Context, publishRoot, stagingRoot string, clients []*httpx.Client, expected []Expected) error {
	return ensureMany(ctx, publishRoot, stagingRoot, clients, expected, ensureSyncedOne)
}

func EnsureRepaired(ctx context.Context, publishRoot, stagingRoot string, clients []*httpx.Client, expected []Expected) error {
	return ensureMany(ctx, publishRoot, stagingRoot, clients, expected, ensureRepairedOne)
}

func ensureMany(ctx context.Context, publishRoot, stagingRoot string, clients []*httpx.Client, expected []Expected, ensureOne ensureOneFunc) error {
	workers := workerCount(clients, len(expected))
	if workers == 0 {
		return nil
	}

	g, ctx := errgroup.WithContext(ctx)
	jobs := make(chan Expected)
	for i := 0; i < workers; i++ {
		g.Go(func() error {
			for exp := range jobs {
				if err := ensureOne(ctx, publishRoot, stagingRoot, clients, exp); err != nil {
					return fmt.Errorf("package %s: %w", exp.RelPath, err)
				}
			}
			return nil
		})
	}

	for _, exp := range expected {
		select {
		case jobs <- exp:
		case <-ctx.Done():
			close(jobs)
			return g.Wait()
		}
	}
	close(jobs)
	return g.Wait()
}

func workerCount(clients []*httpx.Client, expected int) int {
	if expected == 0 {
		return 0
	}
	workers := 0
	for _, client := range clients {
		limit := client.Source().MaxInFlightRequests
		if limit <= 0 {
			limit = 1
		}
		workers += limit
	}
	if workers == 0 {
		workers = 1
	}
	if workers > expected {
		return expected
	}
	return workers
}

func ensureSyncedOne(ctx context.Context, publishRoot, stagingRoot string, clients []*httpx.Client, expected Expected) error {
	final, err := safe.Join(publishRoot, expected.RelPath)
	if err != nil {
		return err
	}
	if ok, err := publish.Verify(final, publish.WithSize(expected.Size)); err != nil {
		return err
	} else if ok {
		return nil
	}
	staged, err := safe.Join(filepath.Join(stagingRoot, "payloads"), expected.RelPath)
	if err != nil {
		return err
	}
	os.Remove(staged)
	return downloadAndPublish(ctx, publishRoot, clients, expected, staged, final)
}

func ensureRepairedOne(ctx context.Context, publishRoot, stagingRoot string, clients []*httpx.Client, expected Expected) error {
	final, err := safe.Join(publishRoot, expected.RelPath)
	if err != nil {
		return err
	}
	if ok, err := publish.Verify(final,
		publish.WithSize(expected.Size),
		publish.WithSHA256(expected.SHA256),
		publish.WithCheck(expected.Verify),
	); err != nil {
		return err
	} else if ok {
		return nil
	}
	staged, err := safe.Join(filepath.Join(stagingRoot, "payloads"), expected.RelPath)
	if err != nil {
		return err
	}
	if ok, err := publish.Verify(staged,
		publish.WithSize(expected.Size),
		publish.WithSHA256(expected.SHA256),
		publish.WithCheck(expected.Verify),
	); err != nil {
		return err
	} else if ok {
		return publish.PublishFile(publishRoot, staged, final)
	}
	os.Remove(staged)
	return downloadAndPublish(ctx, publishRoot, clients, expected, staged, final)
}

func downloadAndPublish(ctx context.Context, publishRoot string, clients []*httpx.Client, expected Expected, staged, final string) error {
	var failures []string
	for _, client := range clients {
		if err := downloadOne(ctx, client, expected, staged); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", client.URL(expected.RelPath), err))
			continue
		}
		if expected.Verify != nil {
			if err := expected.Verify(staged); err != nil {
				os.Remove(staged)
				failures = append(failures, fmt.Sprintf("%s verification: %v", client.URL(expected.RelPath), err))
				continue
			}
		}
		return publish.PublishFile(publishRoot, staged, final)
	}
	return fmt.Errorf("all sources failed for %s: %s", expected.RelPath, strings.Join(failures, "; "))
}

func downloadOne(ctx context.Context, client *httpx.Client, expected Expected, staged string) error {
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		return err
	}
	tmp := staged + ".partial"
	os.Remove(tmp)
	var out *os.File
	var h hash.Hash
	var written int64
	err := client.Do(ctx, expected.RelPath, func(resp *http.Response) error {
		var err error
		out, err = os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer out.Close()
		h = sha256.New()
		written, err = io.CopyBuffer(io.MultiWriter(out, h), resp.Body, make([]byte, 128*1024))
		if err != nil {
			return err
		}
		if err := out.Sync(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if expected.Size >= 0 && written != expected.Size {
		os.Remove(tmp)
		return fmt.Errorf("size mismatch got %d want %d", written, expected.Size)
	}
	if expected.SHA256 != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(got, expected.SHA256) {
			os.Remove(tmp)
			return fmt.Errorf("sha256 mismatch got %s want %s", got, expected.SHA256)
		}
	}
	if err := os.Rename(tmp, staged); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
