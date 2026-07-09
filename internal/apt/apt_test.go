package apt

import (
	"reflect"
	"testing"

	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/download"
	"github.com/torob/mirror-sync/internal/model"
)

func TestSourceDescriptionsUsePayloadSourceOrder(t *testing.T) {
	cfg := &config.Config{Sync: config.Sync{Download: config.Download{
		Proxy:                        config.GlobalProxy{URL: "http://global-proxy.example:8080"},
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
				Proxy:               config.SourceProxy{URL: "http://primary-proxy.example:8080"},
				MaxConnections:      2,
				MaxInFlightRequests: 3,
			},
			MirrorSources: []config.Source{
				{
					URL:                 "https://mirror.example/repo",
					Proxy:               config.SourceProxy{Enabled: boolPtr(false)},
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

func TestSelectReleaseFilesIncludesAllExceptUnselectedRealArchitectures(t *testing.T) {
	hashes := releaseHashesFromPaths(
		"Contents-amd64.gz",
		"Contents-arm64.gz",
		"main/binary-amd64/Packages.xz",
		"main/binary-all/Packages.xz",
		"main/binary-all/Release",
		"main/binary-arm64/Packages.xz",
		"main/binary-arm64/Release",
		"main/cnf/Commands-amd64.xz",
		"main/cnf/Commands-all.xz",
		"main/cnf/Commands-arm64.xz",
		"main/debian-installer/binary-amd64/Packages.xz",
		"main/debian-installer/binary-all/Packages.xz",
		"main/debian-installer/binary-arm64/Packages.xz",
		"main/dep11/CID-Index-amd64.json.gz",
		"main/dep11/CID-Index-arm64.json.gz",
		"main/dep11/Components-amd64.yml.xz",
		"main/dep11/Components-all.yml.xz",
		"main/dep11/Components-arm64.yml.xz",
		"main/dep11/icons-48x48.tar",
		"main/dep11/icons-48x48.tar.gz",
		"main/i18n/Translation-en.xz",
		"main/source/Sources.xz",
		"universe/binary-amd64/Packages.xz",
	)
	files, err := selectReleaseFiles(config.APTSuite{Name: "resolute", Components: []string{"main"}}, []string{"amd64"}, hashes)
	if err != nil {
		t.Fatal(err)
	}
	got := filePaths(files)
	want := []string{
		"dists/resolute/Contents-amd64.gz",
		"dists/resolute/main/binary-all/Packages.xz",
		"dists/resolute/main/binary-all/Release",
		"dists/resolute/main/binary-amd64/Packages.xz",
		"dists/resolute/main/cnf/Commands-amd64.xz",
		"dists/resolute/main/debian-installer/binary-amd64/Packages.xz",
		"dists/resolute/main/dep11/CID-Index-amd64.json.gz",
		"dists/resolute/main/dep11/Components-amd64.yml.xz",
		"dists/resolute/main/dep11/icons-48x48.tar",
		"dists/resolute/main/dep11/icons-48x48.tar.gz",
		"dists/resolute/main/i18n/Translation-en.xz",
		"dists/resolute/main/source/Sources.xz",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("files = %#v, want %#v", got, want)
	}
}

func TestPackageIndexArchitecturesAddsImplicitAll(t *testing.T) {
	got := packageIndexArchitectures([]string{"amd64", "arm64", "amd64"})
	want := []string{"amd64", "arm64", "all"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packageIndexArchitectures = %#v, want %#v", got, want)
	}
}

func TestAptFileExpectedVerifiesAndCanMaterializeRawFromCompressedSiblings(t *testing.T) {
	expected := aptFileExpected([]model.RepositoryFile{
		{Path: "dists/resolute/main/dep11/icons-48x48.tar", Size: 100, SHA256: "raw"},
		{Path: "dists/resolute/main/dep11/icons-48x48.tar.gz", Size: 50, SHA256: "gz"},
		{Path: "dists/resolute/main/dep11/Components-amd64.yml", Size: 200, SHA256: "raw-yml"},
		{Path: "dists/resolute/main/dep11/Components-amd64.yml.xz", Size: 80, SHA256: "xz-yml"},
	})
	if len(expected) != 4 {
		t.Fatalf("expected files = %d, want 4", len(expected))
	}
	rawIcons := expected[2]
	if rawIcons.RelPath != "dists/resolute/main/dep11/icons-48x48.tar" || !rawIcons.VerifyOnSync {
		t.Fatalf("raw icon expectation = %#v", rawIcons)
	}
	wantIconSources := []string{
		"dists/resolute/main/dep11/icons-48x48.tar:",
		"dists/resolute/main/dep11/icons-48x48.tar.gz:gzip",
	}
	if got := sourceDescriptions(rawIcons.Sources); !reflect.DeepEqual(got, wantIconSources) {
		t.Fatalf("raw icon sources = %#v, want %#v", got, wantIconSources)
	}
	rawYML := expected[0]
	wantYMLSources := []string{
		"dists/resolute/main/dep11/Components-amd64.yml:",
		"dists/resolute/main/dep11/Components-amd64.yml.xz:xz",
	}
	if got := sourceDescriptions(rawYML.Sources); !reflect.DeepEqual(got, wantYMLSources) {
		t.Fatalf("raw yml sources = %#v, want %#v", got, wantYMLSources)
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func releaseHashesFromPaths(paths ...string) map[string]releaseFile {
	out := map[string]releaseFile{}
	for i, p := range paths {
		out[p] = releaseFile{Size: int64(i + 1), SHA256: "sha"}
	}
	return out
}

func filePaths(files []model.RepositoryFile) []string {
	out := make([]string, 0, len(files))
	for _, file := range files {
		out = append(out, file.Path)
	}
	return out
}

func sourceDescriptions(sources []download.Source) []string {
	out := make([]string, 0, len(sources))
	for _, source := range sources {
		out = append(out, source.RelPath+":"+source.Decompress)
	}
	return out
}
