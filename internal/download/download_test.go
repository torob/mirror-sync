package download

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/httpx"
	"github.com/torob/mirror-sync/internal/limit"
	"github.com/torob/mirror-sync/internal/model"
)

func TestEnsureManyDownloadsConcurrentlyWithinGlobalLimit(t *testing.T) {
	data := map[string][]byte{
		"pool/a.deb": []byte("package-a"),
		"pool/b.deb": []byte("package-b"),
		"pool/c.deb": []byte("package-c"),
	}
	var mu sync.Mutex
	active := 0
	maxActive := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()
		body, ok := data[r.URL.Path[1:]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	client := testClient(t, server.URL, 2, 10)
	root := t.TempDir()
	staging := t.TempDir()
	if _, err := EnsureRepaired(context.Background(), root, staging, []*httpx.Client{client}, testExpected(data)); err != nil {
		t.Fatal(err)
	}
	for rel, body := range data {
		got, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(body) {
			t.Fatalf("%s = %q, want %q", rel, got, body)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if maxActive > 2 {
		t.Fatalf("global in-flight limit exceeded: max active %d", maxActive)
	}
	if maxActive < 2 {
		t.Fatalf("downloads did not overlap, max active %d", maxActive)
	}
}

func TestResolveExactContinuesPastMirrorFailures(t *testing.T) {
	good := []byte("signed-content")
	expected := testExpected(map[string][]byte{"dists/stable/index": good})
	for _, tt := range []struct {
		name   string
		mirror http.HandlerFunc
	}{
		{name: "404", mirror: func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }},
		{name: "server error", mirror: func(w http.ResponseWriter, r *http.Request) { http.Error(w, "bad gateway", http.StatusBadGateway) }},
		{name: "invalid content", mirror: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("invalid")) }},
		{name: "transport error", mirror: func(w http.ResponseWriter, r *http.Request) {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "cannot hijack", http.StatusInternalServerError)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				return
			}
			_ = conn.Close()
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mirror := httptest.NewServer(tt.mirror)
			defer mirror.Close()
			primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(good) }))
			defer primary.Close()
			staging := t.TempDir()
			resolved, err := ResolveExact(context.Background(), "", staging, nil, []*httpx.Client{
				testClient(t, mirror.URL, 2, 2), testClient(t, primary.URL, 2, 2),
			}, expected)
			if err != nil {
				t.Fatal(err)
			}
			if len(resolved) != 1 || resolved[0].RelPath != expected[0].RelPath {
				t.Fatalf("resolved = %#v, want exact file", resolved)
			}
			data, err := os.ReadFile(filepath.Join(staging, "payloads", filepath.FromSlash(expected[0].RelPath)))
			if err != nil || !bytes.Equal(data, good) {
				t.Fatalf("staged data = %q, err %v", data, err)
			}
		})
	}
}

func TestResolveExactPrimaryFailureClassification(t *testing.T) {
	good := []byte("signed-content")
	expected := testExpected(map[string][]byte{"dists/stable/index": good})
	for _, tt := range []struct {
		name          string
		primary       http.HandlerFunc
		wantMissing   bool
		wantErrorPart string
	}{
		{name: "404 is confirmed missing", primary: func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }, wantMissing: true},
		{name: "server error is fatal", primary: func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}, wantErrorPart: "503 Service Unavailable"},
		{name: "invalid content is fatal", primary: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("invalid")) }, wantErrorPart: "size mismatch"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
			defer mirror.Close()
			primary := httptest.NewServer(tt.primary)
			defer primary.Close()
			resolved, err := ResolveExact(context.Background(), "", t.TempDir(), nil, []*httpx.Client{
				testClient(t, mirror.URL, 2, 2), testClient(t, primary.URL, 2, 2),
			}, expected)
			if tt.wantErrorPart != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrorPart) {
					t.Fatalf("ResolveExact error = %v, want %q", err, tt.wantErrorPart)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantMissing && len(resolved) != 0 {
				t.Fatalf("resolved = %#v, want confirmed missing", resolved)
			}
		})
	}
}

func TestResolveExactReusesOnlyExplicitlyReusablePublishedFile(t *testing.T) {
	good := []byte("signed-content")
	rel := "dists/stable/index.xz"
	expected := testExpected(map[string][]byte{rel: good})
	published := t.TempDir()
	full := filepath.Join(published, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, good, 0o644); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "must not fetch", http.StatusInternalServerError)
	}))
	defer server.Close()

	resolved, err := ResolveExact(context.Background(), published, t.TempDir(), map[string]bool{rel: true}, []*httpx.Client{
		testClient(t, server.URL, 2, 2),
	}, expected)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || hits.Load() != 0 {
		t.Fatalf("resolved=%#v hits=%d", resolved, hits.Load())
	}
}

func TestResolveExactRepairsCorruptReusablePublishedFile(t *testing.T) {
	good := []byte("signed-content")
	rel := "dists/stable/index.xz"
	expected := testExpected(map[string][]byte{rel: good})
	published := t.TempDir()
	full := filepath.Join(published, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("corrupt-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write(good)
	}))
	defer server.Close()

	staging := t.TempDir()
	resolved, err := ResolveExact(context.Background(), published, staging, map[string]bool{rel: true}, []*httpx.Client{
		testClient(t, server.URL, 2, 2),
	}, expected)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || hits.Load() != 1 {
		t.Fatalf("resolved=%#v hits=%d", resolved, hits.Load())
	}
	staged, err := os.ReadFile(filepath.Join(staging, "payloads", filepath.FromSlash(rel)))
	if err != nil || !bytes.Equal(staged, good) {
		t.Fatalf("staged=%q err=%v", staged, err)
	}
}

func TestResolveExactDoesNotReuseUnrecordedStagedFile(t *testing.T) {
	good := []byte("signed-content")
	rel := "dists/stable/index"
	expected := testExpected(map[string][]byte{rel: good})
	staging := t.TempDir()
	staged := filepath.Join(staging, "payloads", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, good, 0o644); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()

	resolved, err := ResolveExact(context.Background(), "", staging, nil, []*httpx.Client{
		testClient(t, server.URL, 2, 2),
	}, expected)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 0 || hits.Load() != 1 {
		t.Fatalf("resolved=%#v hits=%d, want confirmed missing after one request", resolved, hits.Load())
	}
}

func TestEnsureManyHonorsPerSourceLimit(t *testing.T) {
	data := map[string][]byte{
		"pool/a.deb": []byte("package-a"),
		"pool/b.deb": []byte("package-b"),
		"pool/c.deb": []byte("package-c"),
	}
	var mu sync.Mutex
	active := 0
	maxActive := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()
		body, ok := data[r.URL.Path[1:]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	client := testClient(t, server.URL, 10, 1)
	if _, err := EnsureRepaired(context.Background(), t.TempDir(), t.TempDir(), []*httpx.Client{client}, testExpected(data)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if maxActive > 1 {
		t.Fatalf("per-source in-flight limit exceeded: max active %d", maxActive)
	}
}

func TestEnsureManyFallsBackSourcesInOrder(t *testing.T) {
	data := map[string][]byte{"pool/a.deb": []byte("package-a")}
	var firstHits, secondHits int
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits++
		http.NotFound(w, r)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits++
		_, _ = w.Write(data[r.URL.Path[1:]])
	}))
	defer second.Close()

	clients := []*httpx.Client{
		testClient(t, first.URL, 10, 10),
		testClient(t, second.URL, 10, 10),
	}
	root := t.TempDir()
	if _, err := EnsureRepaired(context.Background(), root, t.TempDir(), clients, testExpected(data)); err != nil {
		t.Fatal(err)
	}
	if firstHits != 1 || secondHits != 1 {
		t.Fatalf("fallback hits = first %d second %d, want 1/1", firstHits, secondHits)
	}
	got, err := os.ReadFile(filepath.Join(root, "pool/a.deb"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "package-a" {
		t.Fatalf("published payload = %q", got)
	}
}

func TestEnsureManyCanMaterializeExpectedFileFromGzipSource(t *testing.T) {
	raw := []byte("release-listed raw metadata")
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	hits := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		if r.URL.Path != "/dists/suite/main/dep11/icons-48x48.tar.gz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(compressed.Bytes())
	}))
	defer server.Close()

	sum := sha256.Sum256(raw)
	exp := Expected{
		RelPath:      "dists/suite/main/dep11/icons-48x48.tar",
		Size:         int64(len(raw)),
		SHA256:       hex.EncodeToString(sum[:]),
		VerifyOnSync: true,
		Sources: []Source{
			{RelPath: "dists/suite/main/dep11/icons-48x48.tar"},
			{RelPath: "dists/suite/main/dep11/icons-48x48.tar.gz", Decompress: "gzip"},
		},
	}
	root := t.TempDir()
	if _, err := EnsureSynced(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, []Expected{exp}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "dists", "suite", "main", "dep11", "icons-48x48.tar"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("materialized file = %q, want %q", got, raw)
	}
	if hits["/dists/suite/main/dep11/icons-48x48.tar"] != 1 || hits["/dists/suite/main/dep11/icons-48x48.tar.gz"] != 1 {
		t.Fatalf("hits = %#v, want one raw attempt and one gzip fallback", hits)
	}
}

func TestEnsureSyncedPublishesReadablePayloadAndDirectoriesWithRestrictiveUmask(t *testing.T) {
	oldUmask := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(oldUmask) })

	data := map[string][]byte{"pool/main/a.deb": []byte("package-a")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := data[r.URL.Path[1:]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	root := t.TempDir()
	if _, err := EnsureSynced(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, testExpected(data)); err != nil {
		t.Fatal(err)
	}

	assertMode(t, filepath.Join(root, "pool", "main", "a.deb"), 0o644)
	assertMode(t, root, 0o755)
	assertMode(t, filepath.Join(root, "pool"), 0o755)
	assertMode(t, filepath.Join(root, "pool", "main"), 0o755)
}

func TestEnsureSyncedReusesExistingPayloadWithoutRepairingMode(t *testing.T) {
	good := []byte("package-a")
	root := t.TempDir()
	pool := filepath.Join(root, "pool")
	if err := os.MkdirAll(pool, 0o700); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(pool, "a.deb")
	if err := os.WriteFile(final, good, 0o600); err != nil {
		t.Fatal(err)
	}

	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write(good)
	}))
	defer server.Close()

	if _, err := EnsureSynced(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, testExpected(map[string][]byte{"pool/a.deb": good})); err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("downloads = %d, want 0", hits)
	}
	assertMode(t, final, 0o600)
	assertMode(t, pool, 0o700)
}

func TestEnsureSizeOnlyReusesMatchingSizePayloadWithoutVerification(t *testing.T) {
	good := []byte("package-a")
	bad := []byte("PACKAGE-a")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pool/a.deb"), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write(good)
	}))
	defer server.Close()

	calledVerify := false
	exp := testExpected(map[string][]byte{"pool/a.deb": good})[0]
	exp.Verify = func(string) error {
		calledVerify = true
		return fmt.Errorf("unexpected verification")
	}
	if _, err := EnsureSynced(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, []Expected{exp}); err != nil {
		t.Fatal(err)
	}
	if calledVerify {
		t.Fatal("size-only reuse called payload verifier")
	}
	if hits != 0 {
		t.Fatalf("size-only reuse downloads = %d, want 0", hits)
	}
	got, err := os.ReadFile(filepath.Join(root, "pool/a.deb"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bad) {
		t.Fatalf("payload was changed: got %q want %q", got, bad)
	}
}

func TestEnsureSizeOnlyDownloadsWrongSizePayload(t *testing.T) {
	good := []byte("package-a")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pool/a.deb"), []byte("bad"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pool/a.deb" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(good)
	}))
	defer server.Close()

	if _, err := EnsureSynced(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, testExpected(map[string][]byte{"pool/a.deb": good})); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "pool/a.deb"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(good) {
		t.Fatalf("payload = %q, want %q", got, good)
	}
}

func TestEnsureSizeOnlyIgnoresStagedPayload(t *testing.T) {
	good := []byte("package-a")
	root := t.TempDir()
	staging := t.TempDir()
	staged := filepath.Join(staging, "payloads", "pool/a.deb")
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, good, 0o644); err != nil {
		t.Fatal(err)
	}
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/pool/a.deb" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(good)
	}))
	defer server.Close()

	if _, err := EnsureSynced(context.Background(), root, staging, []*httpx.Client{testClient(t, server.URL, 1, 1)}, testExpected(map[string][]byte{"pool/a.deb": good})); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("downloads = %d, want 1", hits)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("staged payload still exists, err=%v", err)
	}
}

func TestEnsureRepairReplacesSameSizeCorruptedPayload(t *testing.T) {
	good := []byte("package-a")
	bad := []byte("PACKAGE-a")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pool/a.deb"), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/pool/a.deb" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(good)
	}))
	defer server.Close()

	if _, err := EnsureRepaired(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, testExpected(map[string][]byte{"pool/a.deb": good})); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("repair downloads = %d, want 1", hits)
	}
	got, err := os.ReadFile(filepath.Join(root, "pool/a.deb"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(good) {
		t.Fatalf("payload = %q, want %q", got, good)
	}
}

func TestEnsureRepairReplacesPayloadRejectedByVerifier(t *testing.T) {
	good := []byte("package-a")
	bad := []byte("PACKAGE-a")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pool/a.apk"), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pool/a.apk" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(good)
	}))
	defer server.Close()

	exp := Expected{
		RelPath: "pool/a.apk",
		Size:    int64(len(good)),
		Verify: func(path string) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if string(data) != string(good) {
				return fmt.Errorf("bad payload")
			}
			return nil
		},
	}
	if _, err := EnsureRepaired(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, []Expected{exp}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "pool/a.apk"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(good) {
		t.Fatalf("payload = %q, want %q", got, good)
	}
}

func TestWorkerCountIsBoundedBySourceCapacityAndExpected(t *testing.T) {
	clients := []*httpx.Client{
		testClient(t, "https://example.com/one", 10, 2),
		testClient(t, "https://example.com/two", 10, 3),
	}
	if got := workerCount(clients, 10000); got != 5 {
		t.Fatalf("workerCount = %d, want 5", got)
	}
	if got := workerCount(clients, 3); got != 3 {
		t.Fatalf("workerCount capped by expected = %d, want 3", got)
	}
	if got := workerCount(nil, 10000); got != 1 {
		t.Fatalf("workerCount without clients = %d, want 1", got)
	}
	if got := workerCount(clients, 0); got != 0 {
		t.Fatalf("workerCount without expected packages = %d, want 0", got)
	}
}

func TestEnsureSyncedReportsDownloadedAndReusedPayloads(t *testing.T) {
	data := map[string][]byte{
		"pool/reused.deb":     []byte("already-present"),
		"pool/downloaded.deb": []byte("downloaded"),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := data[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pool/reused.deb"), data["pool/reused.deb"], 0o644); err != nil {
		t.Fatal(err)
	}
	stats, err := EnsureSynced(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 2, 2)}, testExpected(data))
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesChecked != 2 || stats.FilesReused != 1 || stats.FilesDownloaded != 1 {
		t.Fatalf("stats = %+v, want checked=2 reused=1 downloaded=1", stats)
	}
	if stats.BytesDownloaded != int64(len(data["pool/downloaded.deb"])) {
		t.Fatalf("downloaded bytes = %d, want %d", stats.BytesDownloaded, len(data["pool/downloaded.deb"]))
	}
}

func TestEnsureRepairedReportsStagedRepairWithoutDownload(t *testing.T) {
	good := []byte("package-a")
	root := t.TempDir()
	staging := t.TempDir()
	staged := filepath.Join(staging, "payloads", "pool/a.deb")
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, good, 0o644); err != nil {
		t.Fatal(err)
	}
	stats, err := EnsureRepaired(context.Background(), root, staging, nil, testExpected(map[string][]byte{"pool/a.deb": good}))
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesChecked != 1 || stats.FilesRepaired != 1 || stats.FilesDownloaded != 0 || stats.BytesDownloaded != 0 {
		t.Fatalf("stats = %+v, want one staged repair without download", stats)
	}
}

func TestEnsureSyncedPayloadsUsesCompactPayloadMap(t *testing.T) {
	body := []byte("package")
	sum := sha256.Sum256(body)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	payloads := map[string]model.Payload{
		"pool/package.deb": {Size: int64(len(body)), Checksums: model.Checksums{SHA256: hex.EncodeToString(sum[:])}},
	}
	root, staging := t.TempDir(), t.TempDir()
	stats, err := EnsureSyncedPayloads(context.Background(), root, staging, []*httpx.Client{testClient(t, server.URL, 1, 1)}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesDownloaded != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if got, err := os.ReadFile(filepath.Join(root, "pool", "package.deb")); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("published payload = %q, error = %v", got, err)
	}
}

func BenchmarkPayloadExpectedIteration(b *testing.B) {
	payloads := make(map[string]model.Payload, 100_000)
	for i := 0; i < 100_000; i++ {
		payloads[fmt.Sprintf("pool/package-%d.deb", i)] = model.Payload{Size: int64(i), Checksums: model.Checksums{SHA256: strings.Repeat("a", 64)}}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		count := 0
		payloadExpected(payloads)(func(Expected) bool {
			count++
			return true
		})
		if count != len(payloads) {
			b.Fatalf("iterated %d payloads, want %d", count, len(payloads))
		}
	}
}

func testClient(t *testing.T, url string, globalMax, sourceMax int) *httpx.Client {
	t.Helper()
	cfg := &config.Config{Sync: config.Sync{Download: config.Download{
		MaxInFlightRequests: globalMax,
	}}}
	src, err := cfg.Source("repo", config.RepoAPT, config.SourceMirror, 0, config.Source{
		URL:                 url,
		MaxConnections:      10,
		MaxInFlightRequests: sourceMax,
	})
	if err != nil {
		t.Fatal(err)
	}
	factory := httpx.NewFactory(0, limit.New(cfg.MaxInFlightRequests()))
	client, err := factory.Client(src)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testExpected(data map[string][]byte) []Expected {
	out := make([]Expected, 0, len(data))
	for rel, body := range data {
		sum := sha256.Sum256(body)
		out = append(out, Expected{RelPath: rel, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])})
	}
	return out
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}
