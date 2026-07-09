package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const DefaultMaxInFlightRequests = 4
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
	Published string `yaml:"published"`
	Staging   string `yaml:"staging"`
}

type Sync struct {
	Prune             bool     `yaml:"prune"`
	RepositoryRetries int      `yaml:"repository_retries"`
	Schedule          Schedule `yaml:"schedule"`
	Download          Download `yaml:"download"`
}

type Schedule struct {
	Interval string `yaml:"interval"`
	Cron     string `yaml:"cron"`
	Timezone string `yaml:"timezone"`
}

type Download struct {
	Retries                      int         `yaml:"retries"`
	MaxConnectionsPerSource      int         `yaml:"max_connections_per_source"`
	MaxInFlightRequests          int         `yaml:"max_in_flight_requests"`
	MaxInFlightRequestsPerSource int         `yaml:"max_in_flight_requests_per_source"`
	Proxy                        GlobalProxy `yaml:"proxy"`
}

type GlobalProxy struct {
	URL              string `yaml:"url"`
	EnabledByDefault *bool  `yaml:"enabled_by_default"`
}

type SourceProxy struct {
	URL     string `yaml:"url"`
	Enabled *bool  `yaml:"enabled"`
}

type Source struct {
	URL                 string      `yaml:"url"`
	MaxConnections      int         `yaml:"max_connections"`
	MaxInFlightRequests int         `yaml:"max_in_flight_requests"`
	Proxy               SourceProxy `yaml:"proxy"`
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
	RepoName            string
	RepoKind            RepoKind
	Role                SourceRole
	Index               int
	URL                 string
	ProxyURL            string
	DirectProxy         bool
	MaxConnections      int
	MaxInFlightRequests int
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
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := rejectExplicitZeroLimits(data); err != nil {
		return nil, err
	}
	cfg.ConfigDir = filepath.Dir(absConfig)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func rejectExplicitZeroLimits(data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	root := documentRoot(&doc)
	for _, path := range []struct {
		keys  []string
		label string
	}{
		{[]string{"sync", "download", "max_connections_per_source"}, "sync.download.max_connections_per_source"},
		{[]string{"sync", "download", "max_in_flight_requests"}, "sync.download.max_in_flight_requests"},
		{[]string{"sync", "download", "max_in_flight_requests_per_source"}, "sync.download.max_in_flight_requests_per_source"},
	} {
		if err := rejectZeroNode(mappingPath(root, path.keys...), path.label); err != nil {
			return err
		}
	}
	for _, section := range []string{"apt", "apk"} {
		repos := mappingValue(mappingValue(root, section), "repositories")
		if repos == nil || repos.Kind != yaml.SequenceNode {
			continue
		}
		for i, repo := range repos.Content {
			prefix := fmt.Sprintf("%s.repositories[%d]", section, i)
			if err := rejectZeroSourceLimits(mappingValue(repo, "primary_source"), prefix+".primary_source"); err != nil {
				return err
			}
			mirrors := mappingValue(repo, "mirror_sources")
			if mirrors == nil || mirrors.Kind != yaml.SequenceNode {
				continue
			}
			for j, mirror := range mirrors.Content {
				if err := rejectZeroSourceLimits(mirror, fmt.Sprintf("%s.mirror_sources[%d]", prefix, j)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func rejectZeroSourceLimits(src *yaml.Node, label string) error {
	if src == nil {
		return nil
	}
	for _, field := range []string{"max_connections", "max_in_flight_requests"} {
		if err := rejectZeroNode(mappingValue(src, field), label+"."+field); err != nil {
			return err
		}
	}
	return nil
}

func rejectZeroNode(node *yaml.Node, label string) error {
	if node == nil || node.Kind != yaml.ScalarNode {
		return nil
	}
	value, err := strconv.ParseInt(node.Value, 0, 64)
	if err != nil {
		return nil
	}
	if value == 0 {
		return fmt.Errorf("%s must be positive when set", label)
	}
	return nil
}

func documentRoot(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return node.Content[0]
	}
	return node
}

func mappingPath(node *yaml.Node, keys ...string) *yaml.Node {
	cur := node
	for _, key := range keys {
		cur = mappingValue(cur, key)
		if cur == nil {
			return nil
		}
	}
	return cur
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func (c *Config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("version must be 1")
	}
	var err error
	c.Storage.Published, err = resolvePath(c.ConfigDir, c.Storage.Published)
	if err != nil {
		return fmt.Errorf("storage.published: %w", err)
	}
	c.Storage.Staging, err = resolvePath(c.ConfigDir, c.Storage.Staging)
	if err != nil {
		return fmt.Errorf("storage.staging: %w", err)
	}
	if c.Sync.Download.Retries < 0 {
		return fmt.Errorf("sync.download.retries must be non-negative")
	}
	if c.Sync.RepositoryRetries < 0 {
		return fmt.Errorf("sync.repository_retries must be non-negative")
	}
	if c.Sync.Download.MaxConnectionsPerSource < 0 {
		return fmt.Errorf("sync.download.max_connections_per_source must be non-negative")
	}
	if c.Sync.Download.MaxInFlightRequests < 0 {
		return fmt.Errorf("sync.download.max_in_flight_requests must be non-negative")
	}
	if c.Sync.Download.MaxInFlightRequestsPerSource < 0 {
		return fmt.Errorf("sync.download.max_in_flight_requests_per_source must be non-negative")
	}
	if err := validateGlobalProxy(c.Sync.Download.Proxy); err != nil {
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
		repo.AbsPublishPath, err = resolvePublish(c.Storage.Published, repo.PublishPath)
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
		repo.AbsPublishPath, err = resolvePublish(c.Storage.Published, repo.PublishPath)
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
		return "", errors.New("publish_path must not escape storage.published")
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
		return "", errors.New("publish_path must not escape storage.published")
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
		return errors.New("max_connections must be non-negative")
	}
	if src.MaxInFlightRequests < 0 {
		return errors.New("max_in_flight_requests must be non-negative")
	}
	return validateSourceProxy(src.Proxy)
}

func validateGlobalProxy(p GlobalProxy) error {
	return validateProxyURL(p.URL)
}

func validateSourceProxy(p SourceProxy) error {
	if p.URL != "" && p.Enabled != nil {
		return errors.New("specify only one of url or enabled")
	}
	return validateProxyURL(p.URL)
}

func validateProxyURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("proxy url must use http or https")
	}
	return nil
}

func (c *Config) Retries() int {
	return c.Sync.Download.Retries
}

func (c *Config) MaxInFlightRequests() int {
	if c.Sync.Download.MaxInFlightRequests > 0 {
		return c.Sync.Download.MaxInFlightRequests
	}
	return DefaultMaxInFlightRequests
}

func (c *Config) Source(repoName string, kind RepoKind, role SourceRole, index int, src Source) (EffectiveSource, error) {
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
	maxInFlight := src.MaxInFlightRequests
	if maxInFlight == 0 {
		maxInFlight = c.Sync.Download.MaxInFlightRequestsPerSource
	}
	if maxInFlight == 0 {
		maxInFlight = c.MaxInFlightRequests()
	}
	return EffectiveSource{
		RepoName: repoName, RepoKind: kind, Role: role, Index: index, URL: strings.TrimRight(src.URL, "/"),
		ProxyURL: proxyURL, DirectProxy: direct, MaxConnections: maxConns, MaxInFlightRequests: maxInFlight,
	}, nil
}

func (c *Config) PayloadSources(repoName string, kind RepoKind, primary Source, mirrors []Source) ([]EffectiveSource, error) {
	primaryEff, err := c.Source(repoName, kind, SourcePrimary, 0, primary)
	if err != nil {
		return nil, err
	}
	out := make([]EffectiveSource, 0, len(mirrors)+1)
	hasPrimaryURL := false
	for i, mirror := range mirrors {
		eff, err := c.Source(repoName, kind, SourceMirror, i, mirror)
		if err != nil {
			return nil, err
		}
		if eff.URL == primaryEff.URL {
			hasPrimaryURL = true
		}
		out = append(out, eff)
	}
	if !hasPrimaryURL {
		out = append(out, primaryEff)
	}
	return out, nil
}

func (c *Config) resolveProxy(src SourceProxy) (string, bool, error) {
	if src.URL != "" {
		return src.URL, false, nil
	}
	if src.Enabled != nil {
		if !*src.Enabled {
			return "", true, nil
		}
		return c.inheritedProxy()
	}
	if c.Sync.Download.Proxy.EnabledByDefault != nil && !*c.Sync.Download.Proxy.EnabledByDefault {
		return "", true, nil
	}
	return c.inheritedProxy()
}

func (c *Config) inheritedProxy() (string, bool, error) {
	if c.Sync.Download.Proxy.URL != "" {
		return c.Sync.Download.Proxy.URL, false, nil
	}
	env := os.Getenv("MIRRORSYNC_PROXY")
	if env == "" {
		return "", true, nil
	}
	if err := validateProxyURL(env); err != nil {
		return "", false, fmt.Errorf("MIRRORSYNC_PROXY: %w", err)
	}
	return env, false, nil
}
