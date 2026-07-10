package httpx

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/limit"
)

func TestRequestErrorsAndRetryLogsRedactURLCredentialsAndQuery(t *testing.T) {
	oldBackoff := retryBackoff
	retryBackoff = func(int) time.Duration { return 0 }
	defer func() { retryBackoff = oldBackoff }()

	var logs bytes.Buffer
	factory := NewFactory(1, limit.New(1), slog.New(slog.NewTextHandler(&logs, nil)))
	client, err := factory.Client(config.EffectiveSource{
		RepoName:            "repo",
		URL:                 "http://user:source-secret@127.0.0.1:1/base?token=query-secret",
		ProxyURL:            "http://proxy-user:proxy-secret@127.0.0.1:2",
		MaxConnections:      1,
		MaxInFlightRequests: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetBytes(context.Background(), "pool/a.deb", 1024)
	if err == nil {
		t.Fatal("GetBytes succeeded, want connection failure")
	}
	combined := err.Error() + logs.String()
	for _, secret := range []string{"source-secret", "proxy-secret", "query-secret", "user:", "proxy-user:"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("output exposed %q: %s", secret, combined)
		}
	}
	for _, want := range []string{"source_host=127.0.0.1:1", "proxy_host=127.0.0.1:2", "path=pool/a.deb", "retrying"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("retry log does not contain %q: %s", want, logs.String())
		}
	}
}

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

func TestIsStatusRecognizesWrappedHTTPStatusOnly(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	client := testClient(t, server.URL, 0)
	_, err := client.GetBytes(context.Background(), "missing", 0)
	if err == nil {
		t.Fatal("GetBytes succeeded, want 404 error")
	}
	if !IsStatus(fmt.Errorf("fetch metadata: %w", err), http.StatusNotFound) {
		t.Fatalf("IsStatus(%v, 404) = false, want true", err)
	}
	if IsStatus(err, http.StatusBadGateway) {
		t.Fatalf("IsStatus(%v, 502) = true, want false", err)
	}
	if IsStatus(context.DeadlineExceeded, http.StatusNotFound) {
		t.Fatal("IsStatus(deadline exceeded, 404) = true, want false")
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
