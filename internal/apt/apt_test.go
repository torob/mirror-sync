package apt

import (
	"testing"

	"github.com/torob/mirror-sync/internal/config"
)

func TestSourceDescriptionsUsePayloadSourceOrder(t *testing.T) {
	cfg := &config.Config{Sync: config.Sync{Download: config.Download{
		Proxy:                        config.Proxy{URL: "http://global-proxy.example:8080"},
		MaxConnectionsPerSource:      4,
		MaxInFlightRequests:          12,
		MaxInFlightRequestsPerSource: 5,
	}}}
	r := &Runner{
		Config: cfg,
		Repo: config.APTRepository{
			Name: "repo",
			PrimarySource: config.Source{
				URL:                 "https://primary.example/repo/",
				Proxy:               config.Proxy{URL: "http://primary-proxy.example:8080"},
				MaxConnections:      2,
				MaxInFlightRequests: 3,
			},
			MirrorSources: []config.Source{
				{
					URL:                 "https://mirror.example/repo",
					Proxy:               config.Proxy{Mode: "direct"},
					MaxConnections:      8,
					MaxInFlightRequests: 9,
				},
			},
		},
	}

	got := r.sourceDescriptions()
	want := []string{
		"https://mirror.example/repo proxy=direct max_connections=8 max_in_flight_requests=9",
		"https://primary.example/repo proxy=http://primary-proxy.example:8080 max_connections=2 max_in_flight_requests=3",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d descriptions, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("description[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
