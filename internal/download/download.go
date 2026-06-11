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

	"mirrorsync/internal/httpx"
	"mirrorsync/internal/publish"
	"mirrorsync/internal/safe"
)

type Expected struct {
	RelPath string
	Size    int64
	SHA256  string
	Verify  func(path string) error
}

func Ensure(ctx context.Context, publishRoot, stagingRoot string, clients []*httpx.Client, expected Expected) error {
	final, err := safe.Join(publishRoot, expected.RelPath)
	if err != nil {
		return err
	}
	if ok, err := publish.VerifyPublished(final, expected.Size, expected.SHA256); err != nil {
		return err
	} else if ok {
		if expected.Verify != nil {
			return expected.Verify(final)
		}
		return nil
	}
	staged, err := safe.Join(filepath.Join(stagingRoot, "payloads"), expected.RelPath)
	if err != nil {
		return err
	}
	if ok, err := publish.VerifyPublished(staged, expected.Size, expected.SHA256); err != nil {
		return err
	} else if ok {
		if expected.Verify == nil || expected.Verify(staged) == nil {
			return publishStaged(staged, final)
		}
		os.Remove(staged)
	}
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
		return publishStaged(staged, final)
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

func publishStaged(staged, final string) error {
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return err
	}
	if err := os.Rename(staged, final); err != nil {
		return err
	}
	return nil
}
