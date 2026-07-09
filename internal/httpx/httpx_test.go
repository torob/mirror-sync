package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/limit"
)

func TestClientRetriesHTTPFailuresBeforeSuccess(t *testing.T) {
	oldBackoff := retryBackoff
	retryBackoff = func(int) time.Duration { return 0 }
	defer func() { retryBackoff = oldBackoff }()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			http.Error(w, "temporary", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := testClient(t, server.URL, 1)
	data, err := client.GetBytes(context.Background(), "payload", 0)
	if err != nil {
		t.Fatalf("GetBytes failed: %v", err)
	}
	if string(data) != "ok" {
		t.Fatalf("payload = %q, want ok", data)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server hits = %d, want 2", got)
	}
}

func TestClientExhaustsHTTPRetries(t *testing.T) {
	oldBackoff := retryBackoff
	retryBackoff = func(int) time.Duration { return 0 }
	defer func() { retryBackoff = oldBackoff }()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "temporary", http.StatusBadGateway)
	}))
	defer server.Close()

	client := testClient(t, server.URL, 2)
	_, err := client.GetBytes(context.Background(), "payload", 0)
	if err == nil {
		t.Fatal("GetBytes succeeded, want retry exhaustion error")
	}
	if !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Fatalf("GetBytes error = %v, want final HTTP status", err)
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("server hits = %d, want 3", got)
	}
}

func testClient(t *testing.T, baseURL string, retries int) *Client {
	t.Helper()
	factory := NewFactory(retries, limit.New(10))
	client, err := factory.Client(config.EffectiveSource{
		RepoName:            "repo",
		URL:                 baseURL,
		MaxConnections:      10,
		MaxInFlightRequests: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
