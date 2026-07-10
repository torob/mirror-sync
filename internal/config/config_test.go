package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoggingLevelValidation(t *testing.T) {
	for _, level := range []string{"", "debug", "info", "warn", "error", "off"} {
		t.Run("accepted_"+level, func(t *testing.T) {
			cfg := &Config{
				Version:   1,
				Logging:   Logging{Level: level},
				ConfigDir: t.TempDir(),
				Storage:   Storage{Published: "repos", Staging: "staged"},
			}
			if err := cfg.validate(); err != nil {
				t.Fatalf("validate logging level %q: %v", level, err)
			}
		})
	}

	cfg := &Config{Version: 1, Logging: Logging{Level: "trace"}}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "logging.level") {
		t.Fatalf("validate invalid logging level = %v, want logging.level error", err)
	}
}

func TestLoadRejectsDuplicateResolvedPublishPaths(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.gpg")
	if err := os.WriteFile(key, []byte("not parsed during config validation"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := []byte(`
version: 1
storage:
  published: repos
  staging: staged
apt:
  repositories:
    - name: a
      publish_path: same
      keyring: key.gpg
      primary_source:
        url: https://example.com/a
      architectures: [amd64]
      suites:
        - name: stable
          components: [main]
apk:
  repositories:
    - name: b
      publish_path: ./same
      keys_dir: keys
      primary_source:
        url: https://example.com/b
      architectures: [x86_64]
      versions:
        - name: v1
          repositories: [main]
`)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("Load succeeded, want duplicate publish_path error")
	}
}

func TestLoadRejectsStorageRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := []byte(`
version: 1
storage:
  root: repos
  staging: staged
`)
	if err := os.WriteFile(path, cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatalf("Load succeeded, want unknown storage.root error")
	}
	if !strings.Contains(err.Error(), "field root not found") {
		t.Fatalf("Load error = %v, want unknown root field", err)
	}
}

func TestSourceProxyPrecedence(t *testing.T) {
	t.Setenv("MIRRORSYNC_PROXY", "http://env.example:8080")
	cfg := &Config{
		Sync: Sync{Download: Download{Proxy: GlobalProxy{URL: "http://global.example:8080"}, MaxConnectionsPerSource: 2}},
	}
	src, err := cfg.Source("repo", RepoAPT, SourcePrimary, 0, Source{URL: "https://example.com", Proxy: SourceProxy{Enabled: boolPtr(false)}})
	if err != nil {
		t.Fatal(err)
	}
	if !src.DirectProxy || src.ProxyURL != "" {
		t.Fatalf("source direct proxy did not override inherited proxy: %+v", src)
	}
	src, err = cfg.Source("repo", RepoAPT, SourcePrimary, 0, Source{URL: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if src.ProxyURL != "http://global.example:8080" {
		t.Fatalf("got proxy %q", src.ProxyURL)
	}
}

func TestLoadRepositoryRetries(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.gpg"), []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(validLimitsConfig(), "sync:\n  download:", "sync:\n  repository_retries: 2\n  download:", 1)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sync.RepositoryRetries != 2 {
		t.Fatalf("repository retries = %d, want 2", cfg.Sync.RepositoryRetries)
	}
}

func TestLoadRejectsNegativeRepositoryRetries(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.gpg"), []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(validLimitsConfig(), "sync:\n  download:", "sync:\n  repository_retries: -1\n  download:", 1)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load succeeded, want negative repository retries error")
	}
	if !strings.Contains(err.Error(), "sync.repository_retries must be non-negative") {
		t.Fatalf("Load error = %v, want repository retries validation", err)
	}
}

func TestLoadDefaultsRepositoryRetriesToZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.gpg"), []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(validLimitsConfig()), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sync.RepositoryRetries != 0 {
		t.Fatalf("repository retries default = %d, want 0", cfg.Sync.RepositoryRetries)
	}
}

func TestProxyEnabledByDefault(t *testing.T) {
	t.Setenv("MIRRORSYNC_PROXY", "http://env.example:8080")
	cfg := &Config{Sync: Sync{Download: Download{
		Proxy: GlobalProxy{URL: "http://global.example:8080", EnabledByDefault: boolPtr(false)},
	}}}
	src, err := cfg.Source("repo", RepoAPT, SourceMirror, 0, Source{URL: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !src.DirectProxy || src.ProxyURL != "" {
		t.Fatalf("unannotated source should be direct when proxy disabled by default: %+v", src)
	}
	src, err = cfg.Source("repo", RepoAPT, SourceMirror, 0, Source{URL: "https://example.com", Proxy: SourceProxy{Enabled: boolPtr(true)}})
	if err != nil {
		t.Fatal(err)
	}
	if src.DirectProxy || src.ProxyURL != "http://global.example:8080" {
		t.Fatalf("enabled source should inherit global proxy: %+v", src)
	}
}

func TestProxyEnabledUsesEnvironmentFallback(t *testing.T) {
	t.Setenv("MIRRORSYNC_PROXY", "http://env.example:8080")
	cfg := &Config{Sync: Sync{Download: Download{
		Proxy: GlobalProxy{EnabledByDefault: boolPtr(false)},
	}}}
	src, err := cfg.Source("repo", RepoAPT, SourceMirror, 0, Source{URL: "https://example.com", Proxy: SourceProxy{Enabled: boolPtr(true)}})
	if err != nil {
		t.Fatal(err)
	}
	if src.DirectProxy || src.ProxyURL != "http://env.example:8080" {
		t.Fatalf("enabled source should inherit environment proxy: %+v", src)
	}
}

func TestSourceProxyURLOverridesEnablement(t *testing.T) {
	cfg := &Config{Sync: Sync{Download: Download{
		Proxy: GlobalProxy{URL: "http://global.example:8080", EnabledByDefault: boolPtr(false)},
	}}}
	src, err := cfg.Source("repo", RepoAPT, SourceMirror, 0, Source{URL: "https://example.com", Proxy: SourceProxy{URL: "http://source.example:8080"}})
	if err != nil {
		t.Fatal(err)
	}
	if src.DirectProxy || src.ProxyURL != "http://source.example:8080" {
		t.Fatalf("source proxy URL should win: %+v", src)
	}
}

func TestLoadRejectsInvalidProxyFields(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"source url plus enabled": func(body string) string {
			return strings.Replace(body, "        url: https://example.com/a\n", "        url: https://example.com/a\n        proxy:\n          url: http://source.example:8080\n          enabled: true\n", 1)
		},
		"global mode removed": func(body string) string {
			return strings.Replace(body, "download:\n    retries: 1\n", "download:\n    retries: 1\n    proxy:\n      mode: direct\n", 1)
		},
		"source mode removed": func(body string) string {
			return strings.Replace(body, "        url: https://example.com/a\n", "        url: https://example.com/a\n        proxy:\n          mode: direct\n", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "key.gpg"), []byte("key"), 0o644); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(mutate(validLimitsConfig())), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("Load succeeded, want proxy validation error")
			}
		})
	}
}

func TestLoadRejectsRemovedFields(t *testing.T) {
	for name, extra := range map[string]string{
		"sync concurrency":  "  concurrency: 4\n",
		"global rate_limit": "  download:\n    rate_limit:\n      requests_per_second: 1\n",
		"source rate_limit": "apt:\n  repositories:\n    - name: a\n      publish_path: a\n      keyring: key.gpg\n      primary_source:\n        url: https://example.com/a\n        rate_limit:\n          requests_per_second: 1\n      architectures: [amd64]\n      suites:\n        - name: stable\n          components: [main]\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "key.gpg"), []byte("key"), 0o644); err != nil {
				t.Fatal(err)
			}
			body := `
version: 1
storage:
  published: repos
  staging: staged
sync:
` + extra
			if !strings.HasPrefix(extra, "apt:") {
				body += `
apt:
  repositories:
    - name: a
      publish_path: a
      keyring: key.gpg
      primary_source:
        url: https://example.com/a
      architectures: [amd64]
      suites:
        - name: stable
          components: [main]
`
			}
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("Load succeeded, want removed field error")
			}
		})
	}
}

func TestMaxInFlightDefaultsAndOverrides(t *testing.T) {
	cfg := &Config{}
	if got := cfg.MaxInFlightRequests(); got != DefaultMaxInFlightRequests {
		t.Fatalf("default global max in-flight = %d, want %d", got, DefaultMaxInFlightRequests)
	}
	src, err := cfg.Source("repo", RepoAPT, SourcePrimary, 0, Source{URL: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if src.MaxInFlightRequests != DefaultMaxInFlightRequests {
		t.Fatalf("default source max in-flight = %d", src.MaxInFlightRequests)
	}

	cfg.Sync.Download.MaxInFlightRequests = 7
	src, err = cfg.Source("repo", RepoAPT, SourcePrimary, 0, Source{URL: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if src.MaxInFlightRequests != 7 {
		t.Fatalf("source inherited global = %d, want 7", src.MaxInFlightRequests)
	}

	cfg.Sync.Download.MaxInFlightRequestsPerSource = 3
	src, err = cfg.Source("repo", RepoAPT, SourcePrimary, 0, Source{URL: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if src.MaxInFlightRequests != 3 {
		t.Fatalf("source inherited per-source default = %d, want 3", src.MaxInFlightRequests)
	}

	src, err = cfg.Source("repo", RepoAPT, SourcePrimary, 0, Source{URL: "https://example.com", MaxInFlightRequests: 2})
	if err != nil {
		t.Fatal(err)
	}
	if src.MaxInFlightRequests != 2 {
		t.Fatalf("source override = %d, want 2", src.MaxInFlightRequests)
	}
}

func TestPayloadSourcesOrdersMirrorsBeforePrimary(t *testing.T) {
	cfg := &Config{}
	sources, err := cfg.PayloadSources("repo", RepoAPT,
		Source{URL: "https://primary.example/repo"},
		[]Source{
			{URL: "https://mirror-a.example/repo"},
			{URL: "https://mirror-b.example/repo"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 3 {
		t.Fatalf("got %d sources, want 3", len(sources))
	}
	wantURLs := []string{
		"https://mirror-a.example/repo",
		"https://mirror-b.example/repo",
		"https://primary.example/repo",
	}
	wantRoles := []SourceRole{SourceMirror, SourceMirror, SourcePrimary}
	wantIndexes := []int{0, 1, 0}
	for i := range sources {
		if sources[i].URL != wantURLs[i] || sources[i].Role != wantRoles[i] || sources[i].Index != wantIndexes[i] {
			t.Fatalf("source[%d] = url %q role %q index %d, want url %q role %q index %d", i, sources[i].URL, sources[i].Role, sources[i].Index, wantURLs[i], wantRoles[i], wantIndexes[i])
		}
	}
}

func TestPayloadSourcesUsesPrimaryWhenMirrorsEmpty(t *testing.T) {
	cfg := &Config{}
	sources, err := cfg.PayloadSources("repo", RepoAPK, Source{URL: "https://primary.example/repo"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].URL != "https://primary.example/repo" || sources[0].Role != SourcePrimary {
		t.Fatalf("sources = %+v, want primary only", sources)
	}
}

func TestPayloadSourcesSkipsPrimaryWithSameNormalizedMirrorURL(t *testing.T) {
	cfg := &Config{}
	sources, err := cfg.PayloadSources("repo", RepoAPT,
		Source{URL: "https://primary.example/repo/"},
		[]Source{
			{URL: "https://mirror.example/repo"},
			{URL: "https://primary.example/repo"},
			{URL: "https://primary.example/repo"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 3 {
		t.Fatalf("got %d sources, want duplicate mirrors retained and primary skipped", len(sources))
	}
	if sources[0].URL != "https://mirror.example/repo" || sources[1].URL != "https://primary.example/repo" || sources[2].URL != "https://primary.example/repo" {
		t.Fatalf("source URLs = %+v", sources)
	}
	for i, src := range sources {
		if src.Role != SourceMirror || src.Index != i {
			t.Fatalf("source[%d] role/index = %q/%d, want mirror/%d", i, src.Role, src.Index, i)
		}
	}
}

func TestPayloadSourcesPreservesPrimaryFallbackSettings(t *testing.T) {
	cfg := &Config{Sync: Sync{Download: Download{
		Proxy:                        GlobalProxy{URL: "http://global-proxy.example:8080"},
		MaxConnectionsPerSource:      4,
		MaxInFlightRequests:          12,
		MaxInFlightRequestsPerSource: 5,
	}}}
	sources, err := cfg.PayloadSources("repo", RepoAPT,
		Source{
			URL:                 "https://primary.example/repo",
			Proxy:               SourceProxy{URL: "http://primary-proxy.example:8080"},
			MaxConnections:      2,
			MaxInFlightRequests: 3,
		},
		[]Source{{
			URL:                 "https://mirror.example/repo",
			Proxy:               SourceProxy{Enabled: boolPtr(false)},
			MaxConnections:      8,
			MaxInFlightRequests: 9,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 {
		t.Fatalf("got %d sources, want mirror plus primary", len(sources))
	}
	primary := sources[1]
	if primary.Role != SourcePrimary || primary.ProxyURL != "http://primary-proxy.example:8080" || primary.DirectProxy || primary.MaxConnections != 2 || primary.MaxInFlightRequests != 3 {
		t.Fatalf("primary fallback settings = %+v", primary)
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func TestValidateRejectsNegativeMaxInFlight(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"global":             func(c *Config) { c.Sync.Download.MaxInFlightRequests = -1 },
		"per-source default": func(c *Config) { c.Sync.Download.MaxInFlightRequestsPerSource = -1 },
		"source":             func(c *Config) { c.APT.Repositories[0].PrimarySource.MaxInFlightRequests = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			key := filepath.Join(dir, "key.gpg")
			if err := os.WriteFile(key, []byte("key"), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg := &Config{
				Version:   1,
				ConfigDir: dir,
				Storage:   Storage{Published: "repos", Staging: "staged"},
				APT: APTSection{Repositories: []APTRepository{{
					Name: "a", PublishPath: "a", Keyring: "key.gpg",
					PrimarySource: Source{URL: "https://example.com/a"},
					Architectures: []string{"amd64"},
					Suites:        []APTSuite{{Name: "stable", Components: []string{"main"}}},
				}}},
			}
			mutate(cfg)
			if err := cfg.validate(); err == nil {
				t.Fatalf("validate succeeded, want negative max in-flight error")
			}
		})
	}
}

func TestLoadRejectsExplicitZeroLimits(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"max connections per source": func(body string) string {
			return strings.Replace(body, "download:\n    retries: 1\n", "download:\n    retries: 1\n    max_connections_per_source: 0\n", 1)
		},
		"global max in-flight": func(body string) string {
			return strings.Replace(body, "download:\n    retries: 1\n", "download:\n    retries: 1\n    max_in_flight_requests: 0\n", 1)
		},
		"per-source max in-flight": func(body string) string {
			return strings.Replace(body, "download:\n    retries: 1\n", "download:\n    retries: 1\n    max_in_flight_requests_per_source: 0\n", 1)
		},
		"primary max connections": func(body string) string {
			return strings.Replace(body, "        url: https://example.com/a\n", "        url: https://example.com/a\n        max_connections: 0\n", 1)
		},
		"primary max in-flight": func(body string) string {
			return strings.Replace(body, "        url: https://example.com/a\n", "        url: https://example.com/a\n        max_in_flight_requests: 0\n", 1)
		},
		"mirror max connections": func(body string) string {
			return strings.Replace(body, "        - url: https://mirror.example.com/a\n", "        - url: https://mirror.example.com/a\n          max_connections: 0\n", 1)
		},
		"mirror max in-flight": func(body string) string {
			return strings.Replace(body, "        - url: https://mirror.example.com/a\n", "        - url: https://mirror.example.com/a\n          max_in_flight_requests: 0\n", 1)
		},
		"apk primary max connections": func(body string) string {
			return strings.Replace(body, "        url: https://example.com/apk\n", "        url: https://example.com/apk\n        max_connections: 0\n", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "key.gpg"), []byte("key"), 0o644); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(mutate(validLimitsConfig())), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load succeeded, want explicit zero limit error")
			}
			if !strings.Contains(err.Error(), "must be positive when set") {
				t.Fatalf("Load error = %v, want positive when set", err)
			}
		})
	}
}

func TestLoadAllowsOmittedLimitDefaults(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.gpg"), []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(validLimitsConfig()), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxInFlightRequests() != DefaultMaxInFlightRequests {
		t.Fatalf("global default = %d, want %d", cfg.MaxInFlightRequests(), DefaultMaxInFlightRequests)
	}
	src, err := cfg.Source("repo", RepoAPT, SourcePrimary, 0, cfg.APT.Repositories[0].PrimarySource)
	if err != nil {
		t.Fatal(err)
	}
	if src.MaxConnections != DefaultMaxConnectionsPerSource || src.MaxInFlightRequests != DefaultMaxInFlightRequests {
		t.Fatalf("source defaults = %+v", src)
	}
}

func validLimitsConfig() string {
	return `
version: 1
storage:
  published: repos
  staging: staged
sync:
  download:
    retries: 1
apt:
  repositories:
    - name: a
      publish_path: a
      keyring: key.gpg
      primary_source:
        url: https://example.com/a
      mirror_sources:
        - url: https://mirror.example.com/a
      architectures: [amd64]
      suites:
        - name: stable
          components: [main]
apk:
  repositories:
    - name: b
      publish_path: b
      keys_dir: keys
      primary_source:
        url: https://example.com/apk
      architectures: [x86_64]
      versions:
        - name: v1
          repositories: [main]
`
}
