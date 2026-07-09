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
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/httpx"
	"github.com/torob/mirror-sync/internal/limit"
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
	if err := EnsureRepaired(context.Background(), root, staging, []*httpx.Client{client}, testExpected(data)); err != nil {
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
	if err := EnsureRepaired(context.Background(), t.TempDir(), t.TempDir(), []*httpx.Client{client}, testExpected(data)); err != nil {
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
	if err := EnsureRepaired(context.Background(), root, t.TempDir(), clients, testExpected(data)); err != nil {
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
	if err := EnsureSynced(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, []Expected{exp}); err != nil {
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
	if err := EnsureSynced(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, testExpected(data)); err != nil {
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

	if err := EnsureSynced(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, testExpected(map[string][]byte{"pool/a.deb": good})); err != nil {
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
	if err := EnsureSynced(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, []Expected{exp}); err != nil {
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

	if err := EnsureSynced(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, testExpected(map[string][]byte{"pool/a.deb": good})); err != nil {
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

	if err := EnsureSynced(context.Background(), root, staging, []*httpx.Client{testClient(t, server.URL, 1, 1)}, testExpected(map[string][]byte{"pool/a.deb": good})); err != nil {
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

	if err := EnsureRepaired(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, testExpected(map[string][]byte{"pool/a.deb": good})); err != nil {
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
	if err := EnsureRepaired(context.Background(), root, t.TempDir(), []*httpx.Client{testClient(t, server.URL, 1, 1)}, []Expected{exp}); err != nil {
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
