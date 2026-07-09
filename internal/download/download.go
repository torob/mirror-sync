package download

import (
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ulikunitz/xz"
	"golang.org/x/sync/errgroup"

	"github.com/torob/mirror-sync/internal/httpx"
	"github.com/torob/mirror-sync/internal/publish"
	"github.com/torob/mirror-sync/internal/safe"
)

type Source struct {
	RelPath    string
	Decompress string
}

type Expected struct {
	RelPath      string
	Size         int64
	SHA256       string
	Checksums    map[string]string
	Verify       func(path string) error
	VerifyOnSync bool
	Sources      []Source
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
					return fmt.Errorf("file %s: %w", exp.RelPath, err)
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
	options := []publish.VerifyOption{publish.WithSize(expected.Size)}
	if expected.VerifyOnSync {
		options = append(options, checksumVerifyOption(expected), publish.WithCheck(expected.Verify))
	}
	if ok, err := publish.Verify(final, options...); err != nil {
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
		checksumVerifyOption(expected),
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
		checksumVerifyOption(expected),
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
		if err := downloadFromClient(ctx, client, expected, staged); err != nil {
			failures = append(failures, err.Error())
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

func downloadFromClient(ctx context.Context, client *httpx.Client, expected Expected, staged string) error {
	var failures []string
	sources := expected.Sources
	if len(sources) == 0 {
		sources = []Source{{RelPath: expected.RelPath}}
	}
	for _, source := range sources {
		if source.RelPath == "" {
			source.RelPath = expected.RelPath
		}
		if err := downloadOne(ctx, client, expected, source, staged); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", client.URL(source.RelPath), err))
			continue
		}
		return nil
	}
	return fmt.Errorf("%s", strings.Join(failures, "; "))
}

func downloadOne(ctx context.Context, client *httpx.Client, expected Expected, source Source, staged string) error {
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		return err
	}
	tmp := staged + ".partial"
	os.Remove(tmp)
	var out *os.File
	checksumAlg, checksumHex := strongestChecksum(expected)
	var gotChecksum string
	var written int64
	err := client.Do(ctx, source.RelPath, func(resp *http.Response) error {
		var err error
		out, err = os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer out.Close()
		body, closeBody, err := decompressedBody(resp.Body, source.Decompress)
		if err != nil {
			return err
		}
		if closeBody {
			defer body.Close()
		}
		var h hash.Hash
		if checksumAlg != "" {
			h = newHash(checksumAlg)
		}
		writer := io.Writer(out)
		if h != nil {
			writer = io.MultiWriter(out, h)
		}
		written, err = io.CopyBuffer(writer, body, make([]byte, 128*1024))
		if err != nil {
			return err
		}
		if h != nil {
			gotChecksum = hex.EncodeToString(h.Sum(nil))
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
	if checksumAlg != "" {
		if !strings.EqualFold(gotChecksum, checksumHex) {
			os.Remove(tmp)
			return fmt.Errorf("%s mismatch got %s want %s", strings.ToLower(checksumAlg), gotChecksum, checksumHex)
		}
	}
	if err := os.Rename(tmp, staged); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func checksumVerifyOption(expected Expected) publish.VerifyOption {
	alg, hex := strongestChecksum(expected)
	if alg == "" {
		return nil
	}
	return publish.WithChecksum(alg, hex)
}

func strongestChecksum(expected Expected) (string, string) {
	checksums := expected.Checksums
	if len(checksums) == 0 && expected.SHA256 != "" {
		checksums = map[string]string{"SHA256": expected.SHA256}
	}
	for _, alg := range []string{"SHA512", "SHA256", "SHA1", "MD5Sum", "MD5"} {
		for name, value := range checksums {
			if strings.EqualFold(name, alg) && value != "" {
				return canonicalChecksumName(name), value
			}
		}
	}
	return "", ""
}

func canonicalChecksumName(name string) string {
	if strings.EqualFold(name, "MD5Sum") {
		return "MD5"
	}
	return strings.ToUpper(name)
}

func newHash(algorithm string) hash.Hash {
	switch strings.ToUpper(algorithm) {
	case "MD5", "MD5SUM":
		return md5.New()
	case "SHA1":
		return sha1.New()
	case "SHA256":
		return sha256.New()
	case "SHA512":
		return sha512.New()
	default:
		return nil
	}
}

func decompressedBody(body io.ReadCloser, compression string) (io.ReadCloser, bool, error) {
	switch compression {
	case "":
		return body, false, nil
	case "gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			return nil, false, err
		}
		return zr, true, nil
	case "xz":
		xzr, err := xz.NewReader(body)
		if err != nil {
			return nil, false, err
		}
		return io.NopCloser(xzr), true, nil
	default:
		return nil, false, fmt.Errorf("unsupported source decompression %q", compression)
	}
}
