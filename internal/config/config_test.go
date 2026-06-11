package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsDuplicateResolvedPublishPaths(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.gpg")
	if err := os.WriteFile(key, []byte("not parsed during config validation"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := []byte(`
version: 1
storage:
  root: repos
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

func TestSourceProxyPrecedence(t *testing.T) {
	t.Setenv("MIRRORSYNC_PROXY", "http://env.example:8080")
	cfg := &Config{
		Sync: Sync{Download: Download{Proxy: Proxy{URL: "http://global.example:8080"}, MaxConnectionsPerSource: 2}},
	}
	src, err := cfg.Source("repo", RepoAPT, SourcePrimary, 0, Source{URL: "https://example.com", Proxy: Proxy{Mode: "direct"}}, RateLimit{})
	if err != nil {
		t.Fatal(err)
	}
	if !src.DirectProxy || src.ProxyURL != "" {
		t.Fatalf("source direct proxy did not override inherited proxy: %+v", src)
	}
	src, err = cfg.Source("repo", RepoAPT, SourcePrimary, 0, Source{URL: "https://example.com"}, RateLimit{})
	if err != nil {
		t.Fatal(err)
	}
	if src.ProxyURL != "http://global.example:8080" {
		t.Fatalf("got proxy %q", src.ProxyURL)
	}
}
