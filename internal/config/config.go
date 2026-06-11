package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const DefaultConcurrency = 4
const DefaultMaxConnectionsPerSource = 4

type Config struct {
	Version   int        `yaml:"version"`
	Storage   Storage    `yaml:"storage"`
	Sync      Sync       `yaml:"sync"`
	APT       APTSection `yaml:"apt"`
	APK       APKSection `yaml:"apk"`
	ConfigDir string     `yaml:"-"`
}

type Storage struct {
	Root    string `yaml:"root"`
	Staging string `yaml:"staging"`
}

type Sync struct {
	Concurrency int      `yaml:"concurrency"`
	Prune       bool     `yaml:"prune"`
	Schedule    Schedule `yaml:"schedule"`
	Download    Download `yaml:"download"`
}

type Schedule struct {
	Interval string `yaml:"interval"`
	Cron     string `yaml:"cron"`
	Timezone string `yaml:"timezone"`
}

type Download struct {
	Retries                 int       `yaml:"retries"`
	MaxConnectionsPerSource int       `yaml:"max_connections_per_source"`
	Proxy                   Proxy     `yaml:"proxy"`
	RateLimit               RateLimit `yaml:"rate_limit"`
}

type RateLimit struct {
	RequestsPerSecond        float64 `yaml:"requests_per_second"`
	RequestsPerSecondPerHost float64 `yaml:"requests_per_second_per_host"`
	Burst                    int     `yaml:"burst"`
}

type Proxy struct {
	URL  string `yaml:"url"`
	Mode string `yaml:"mode"`
}

type Source struct {
	URL            string    `yaml:"url"`
	MaxConnections int       `yaml:"max_connections"`
	Proxy          Proxy     `yaml:"proxy"`
	RateLimit      RateLimit `yaml:"rate_limit"`
}

type APTSection struct {
	Repositories []APTRepository `yaml:"repositories"`
}

type APTRepository struct {
	Name           string     `yaml:"name"`
	PublishPath    string     `yaml:"publish_path"`
	Keyring        string     `yaml:"keyring"`
	PrimarySource  Source     `yaml:"primary_source"`
	MirrorSources  []Source   `yaml:"mirror_sources"`
	Architectures  []string   `yaml:"architectures"`
	Suites         []APTSuite `yaml:"suites"`
	AbsPublishPath string     `yaml:"-"`
	AbsKeyring     string     `yaml:"-"`
}

type APTSuite struct {
	Name       string   `yaml:"name"`
	Components []string `yaml:"components"`
}

type APKSection struct {
	Repositories []APKRepository `yaml:"repositories"`
}

type APKRepository struct {
	Name           string       `yaml:"name"`
	PublishPath    string       `yaml:"publish_path"`
	KeysDir        string       `yaml:"keys_dir"`
	PrimarySource  Source       `yaml:"primary_source"`
	MirrorSources  []Source     `yaml:"mirror_sources"`
	Architectures  []string     `yaml:"architectures"`
	Versions       []APKVersion `yaml:"versions"`
	AbsPublishPath string       `yaml:"-"`
	AbsKeysDir     string       `yaml:"-"`
}

type APKVersion struct {
	Name         string   `yaml:"name"`
	Repositories []string `yaml:"repositories"`
}

type RepoKind string

const (
	RepoAPT RepoKind = "apt"
	RepoAPK RepoKind = "apk"
)

type SourceRole string

const (
	SourcePrimary SourceRole = "primary"
	SourceMirror  SourceRole = "mirror"
)

type EffectiveSource struct {
	RepoName       string
	RepoKind       RepoKind
	Role           SourceRole
	Index          int
	URL            string
	ProxyURL       string
	DirectProxy    bool
	MaxConnections int
	RateLimit      RateLimit
}

func Load(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("-config is required")
	}
	absConfig, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(absConfig)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.ConfigDir = filepath.Dir(absConfig)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("version must be 1")
	}
	var err error
	c.Storage.Root, err = resolvePath(c.ConfigDir, c.Storage.Root)
	if err != nil {
		return fmt.Errorf("storage.root: %w", err)
	}
	c.Storage.Staging, err = resolvePath(c.ConfigDir, c.Storage.Staging)
	if err != nil {
		return fmt.Errorf("storage.staging: %w", err)
	}
	if c.Sync.Concurrency < 0 {
		return fmt.Errorf("sync.concurrency must be positive")
	}
	if c.Sync.Download.Retries < 0 {
		return fmt.Errorf("sync.download.retries must be non-negative")
	}
	if c.Sync.Download.MaxConnectionsPerSource < 0 {
		return fmt.Errorf("sync.download.max_connections_per_source must be positive")
	}
	if err := validateProxy(c.Sync.Download.Proxy); err != nil {
		return fmt.Errorf("sync.download.proxy: %w", err)
	}
	if c.Sync.Schedule.Interval != "" {
		if _, err := time.ParseDuration(c.Sync.Schedule.Interval); err != nil {
			return fmt.Errorf("sync.schedule.interval: %w", err)
		}
	}
	if c.Sync.Schedule.Cron != "" && c.Sync.Schedule.Timezone == "" {
		return fmt.Errorf("sync.schedule.timezone is required when cron is set")
	}
	if c.Sync.Schedule.Cron != "" {
		if _, err := time.LoadLocation(c.Sync.Schedule.Timezone); err != nil {
			return fmt.Errorf("sync.schedule.timezone: %w", err)
		}
	}
	if c.Sync.Schedule.Cron != "" && c.Sync.Schedule.Interval != "" {
		return fmt.Errorf("sync.schedule must specify only one of interval or cron")
	}

	publishPaths := map[string]string{}
	aptNames := map[string]bool{}
	for i := range c.APT.Repositories {
		repo := &c.APT.Repositories[i]
		if repo.Name == "" {
			return fmt.Errorf("apt.repositories[%d].name is required", i)
		}
		if aptNames[repo.Name] {
			return fmt.Errorf("duplicate apt repository name %q", repo.Name)
		}
		aptNames[repo.Name] = true
		if err := validateHTTPSource(repo.PrimarySource); err != nil {
			return fmt.Errorf("apt repository %s primary_source: %w", repo.Name, err)
		}
		for j, src := range repo.MirrorSources {
			if err := validateHTTPSource(src); err != nil {
				return fmt.Errorf("apt repository %s mirror_sources[%d]: %w", repo.Name, j, err)
			}
		}
		repo.AbsPublishPath, err = resolvePublish(c.Storage.Root, repo.PublishPath)
		if err != nil {
			return fmt.Errorf("apt repository %s publish_path: %w", repo.Name, err)
		}
		if owner, ok := publishPaths[repo.AbsPublishPath]; ok {
			return fmt.Errorf("publish_path %s is used by both %s and apt/%s", repo.AbsPublishPath, owner, repo.Name)
		}
		publishPaths[repo.AbsPublishPath] = "apt/" + repo.Name
		if repo.Keyring == "" {
			return fmt.Errorf("apt repository %s keyring is required", repo.Name)
		}
		if strings.Contains(repo.Keyring, "://") {
			return fmt.Errorf("apt repository %s keyring must be a local path", repo.Name)
		}
		repo.AbsKeyring, err = resolvePath(c.ConfigDir, repo.Keyring)
		if err != nil {
			return fmt.Errorf("apt repository %s keyring: %w", repo.Name, err)
		}
		if err := readableFile(repo.AbsKeyring); err != nil {
			return fmt.Errorf("apt repository %s keyring: %w", repo.Name, err)
		}
		if len(repo.Architectures) == 0 || len(repo.Suites) == 0 {
			return fmt.Errorf("apt repository %s requires architectures and suites", repo.Name)
		}
	}

	apkNames := map[string]bool{}
	for i := range c.APK.Repositories {
		repo := &c.APK.Repositories[i]
		if repo.Name == "" {
			return fmt.Errorf("apk.repositories[%d].name is required", i)
		}
		if apkNames[repo.Name] {
			return fmt.Errorf("duplicate apk repository name %q", repo.Name)
		}
		apkNames[repo.Name] = true
		if err := validateHTTPSource(repo.PrimarySource); err != nil {
			return fmt.Errorf("apk repository %s primary_source: %w", repo.Name, err)
		}
		for j, src := range repo.MirrorSources {
			if err := validateHTTPSource(src); err != nil {
				return fmt.Errorf("apk repository %s mirror_sources[%d]: %w", repo.Name, j, err)
			}
		}
		repo.AbsPublishPath, err = resolvePublish(c.Storage.Root, repo.PublishPath)
		if err != nil {
			return fmt.Errorf("apk repository %s publish_path: %w", repo.Name, err)
		}
		if owner, ok := publishPaths[repo.AbsPublishPath]; ok {
			return fmt.Errorf("publish_path %s is used by both %s and apk/%s", repo.AbsPublishPath, owner, repo.Name)
		}
		publishPaths[repo.AbsPublishPath] = "apk/" + repo.Name
		if repo.KeysDir == "" {
			return fmt.Errorf("apk repository %s keys_dir is required", repo.Name)
		}
		repo.AbsKeysDir, err = resolvePath(c.ConfigDir, repo.KeysDir)
		if err != nil {
			return fmt.Errorf("apk repository %s keys_dir: %w", repo.Name, err)
		}
		if len(repo.Architectures) == 0 || len(repo.Versions) == 0 {
			return fmt.Errorf("apk repository %s requires architectures and versions", repo.Name)
		}
	}
	return nil
}

func resolvePath(base, p string) (string, error) {
	if p == "" {
		return "", errors.New("path is required")
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	return filepath.Abs(filepath.Clean(p))
}

func resolvePublish(root, p string) (string, error) {
	if p == "" {
		return "", errors.New("publish_path is required")
	}
	if filepath.IsAbs(p) {
		return "", errors.New("publish_path must be relative")
	}
	clean := filepath.Clean(p)
	if clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", errors.New("publish_path must not escape storage.root")
	}
	abs, err := filepath.Abs(filepath.Join(root, clean))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("publish_path must not escape storage.root")
	}
	return abs, nil
}

func readableFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return f.Close()
}

func validateHTTPSource(src Source) error {
	if src.URL == "" {
		return errors.New("url is required")
	}
	u, err := url.Parse(src.URL)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("url must use http or https")
	}
	if src.MaxConnections < 0 {
		return errors.New("max_connections must be positive")
	}
	return validateProxy(src.Proxy)
}

func validateProxy(p Proxy) error {
	hasURL := p.URL != ""
	hasDirect := p.Mode == "direct"
	if p.Mode != "" && p.Mode != "direct" {
		return errors.New("mode must be direct when set")
	}
	if hasURL && hasDirect {
		return errors.New("specify exactly one of url or mode: direct")
	}
	if hasURL {
		u, err := url.Parse(p.URL)
		if err != nil {
			return err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return errors.New("proxy url must use http or https")
		}
	}
	return nil
}

func (c *Config) Concurrency() int {
	if c.Sync.Concurrency > 0 {
		return c.Sync.Concurrency
	}
	return DefaultConcurrency
}

func (c *Config) Retries() int {
	return c.Sync.Download.Retries
}

func (c *Config) Source(repoName string, kind RepoKind, role SourceRole, index int, src Source, repoLimit RateLimit) (EffectiveSource, error) {
	proxyURL, direct, err := c.resolveProxy(src.Proxy)
	if err != nil {
		return EffectiveSource{}, err
	}
	maxConns := src.MaxConnections
	if maxConns == 0 {
		maxConns = c.Sync.Download.MaxConnectionsPerSource
	}
	if maxConns == 0 {
		maxConns = DefaultMaxConnectionsPerSource
	}
	limit := inheritRateLimit(src.RateLimit, repoLimit, c.Sync.Download.RateLimit)
	return EffectiveSource{
		RepoName: repoName, RepoKind: kind, Role: role, Index: index, URL: strings.TrimRight(src.URL, "/"),
		ProxyURL: proxyURL, DirectProxy: direct, MaxConnections: maxConns, RateLimit: limit,
	}, nil
}

func (c *Config) resolveProxy(src Proxy) (string, bool, error) {
	if src.Mode == "direct" {
		return "", true, nil
	}
	if src.URL != "" {
		return src.URL, false, nil
	}
	if c.Sync.Download.Proxy.Mode == "direct" {
		return "", true, nil
	}
	if c.Sync.Download.Proxy.URL != "" {
		return c.Sync.Download.Proxy.URL, false, nil
	}
	env := os.Getenv("MIRRORSYNC_PROXY")
	if env == "" {
		return "", true, nil
	}
	if err := validateProxy(Proxy{URL: env}); err != nil {
		return "", false, fmt.Errorf("MIRRORSYNC_PROXY: %w", err)
	}
	return env, false, nil
}

func inheritRateLimit(scopes ...RateLimit) RateLimit {
	var out RateLimit
	for _, r := range scopes {
		if out.RequestsPerSecond == 0 {
			out.RequestsPerSecond = r.RequestsPerSecond
		}
		if out.RequestsPerSecondPerHost == 0 {
			out.RequestsPerSecondPerHost = r.RequestsPerSecondPerHost
		}
		if out.Burst == 0 {
			out.Burst = r.Burst
		}
	}
	return out
}
