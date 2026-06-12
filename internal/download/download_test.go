package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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
	if err := EnsureMany(context.Background(), root, staging, []*httpx.Client{client}, testExpected(data)); err != nil {
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
	if err := EnsureMany(context.Background(), t.TempDir(), t.TempDir(), []*httpx.Client{client}, testExpected(data)); err != nil {
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
	if err := EnsureMany(context.Background(), root, t.TempDir(), clients, testExpected(data)); err != nil {
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
