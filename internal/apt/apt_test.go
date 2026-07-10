package apt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ulikunitz/xz"

	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/download"
	"github.com/torob/mirror-sync/internal/httpx"
	"github.com/torob/mirror-sync/internal/limit"
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
		"Contents-all.gz",
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
		"dists/resolute/Contents-all.gz",
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

func TestFetchStateSkipsReleaseAbsentConfiguredArchitecture(t *testing.T) {
	release := []byte("Origin: example\nSHA256:\n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages\n")
	inRelease, keyring, _ := signedInRelease(t, release)
	keyringPath := writeTestKeyring(t, keyring)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dists/stable/InRelease":
			_, _ = w.Write(inRelease)
		case "/dists/stable/main/binary-amd64/Packages":
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	runner := testFetchStateRunner(t, server.URL, keyringPath, t.TempDir(), []string{"amd64", "arm64"})
	state, err := runner.fetchState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Packages) != 0 {
		t.Fatalf("packages = %d, want none", len(state.Packages))
	}
}

func TestFetchStateAllowsReleaseAbsentPublishedBranchToBePruned(t *testing.T) {
	release := []byte("Origin: example\nSHA256:\n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages\n")
	inRelease, keyring, _ := signedInRelease(t, release)
	keyringPath := writeTestKeyring(t, keyring)
	publishRoot := t.TempDir()
	writeTestFile(t, publishRoot, "dists/stable/main/binary-arm64/Packages.xz", []byte("stale"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dists/stable/InRelease":
			_, _ = w.Write(inRelease)
		case "/dists/stable/main/binary-amd64/Packages":
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	runner := testFetchStateRunner(t, server.URL, keyringPath, publishRoot, []string{"amd64", "arm64"})
	state, err := runner.fetchState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range state.Files {
		if file.Path == "dists/stable/main/binary-arm64/Packages.xz" {
			t.Fatalf("state keeps stale absent branch file: %#v", state.Files)
		}
	}
	removed, err := runner.pruneState(state)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{"dists/stable/main/binary-arm64/Packages.xz"}) {
		t.Fatalf("removed = %#v, want stale branch pruned", removed)
	}
}

func TestSyncResolvesExactDistsFromMirrorsAndPersistsMissingPaths(t *testing.T) {
	compressed := xzTestData(t, nil)
	compressedDigest := sha256.Sum256(compressed)
	emptyDigest := sha256.Sum256(nil)
	release := []byte(fmt.Sprintf("Origin: example\nAcquire-By-Hash: yes\nSHA256:\n %x %d main/binary-amd64/Packages.xz\n %x 0 main/binary-amd64/Packages\n", compressedDigest, len(compressed), emptyDigest))
	inRelease, keyring, _ := signedInRelease(t, release)

	var mirrorSignedHits int
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/dists/stable/main/binary-amd64/Packages.xz":
			_, _ = w.Write(compressed)
		case "/dists/stable/InRelease", "/dists/stable/Release", "/dists/stable/Release.gpg":
			mirrorSignedHits++
			http.Error(w, "must not request signed metadata from mirror", http.StatusInternalServerError)
		default:
			http.NotFound(w, req)
		}
	}))
	defer mirror.Close()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/dists/stable/InRelease":
			_, _ = w.Write(inRelease)
		case "/dists/stable/main/binary-amd64/Packages.xz":
			http.Error(w, "mirror copy should be sufficient", http.StatusBadGateway)
		default:
			http.NotFound(w, req)
		}
	}))
	defer primary.Close()

	publishRoot := t.TempDir()
	stagingRoot := t.TempDir()
	staleRaw := "dists/stable/main/binary-amd64/Packages"
	writeTestFile(t, publishRoot, staleRaw, nil)
	cfg := &config.Config{
		Storage: config.Storage{Staging: stagingRoot},
		Sync:    config.Sync{Download: config.Download{MaxInFlightRequests: 4}},
	}
	runner := &Runner{
		Config: cfg,
		Repo: config.APTRepository{
			Name:           "repo",
			AbsPublishPath: publishRoot,
			AbsKeyring:     writeTestKeyring(t, keyring),
			PrimarySource:  config.Source{URL: primary.URL},
			MirrorSources:  []config.Source{{URL: mirror.URL}},
			Architectures:  []string{"amd64"},
			Suites:         []config.APTSuite{{Name: "stable", Components: []string{"main"}}},
		},
		HTTP: httpx.NewFactory(0, limit.New(cfg.MaxInFlightRequests())),
	}

	if _, err := runner.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mirrorSignedHits != 0 {
		t.Fatalf("signed metadata requests to mirror = %d, want none", mirrorSignedHits)
	}
	compressedRel := "dists/stable/main/binary-amd64/Packages.xz"
	if data, err := os.ReadFile(filepath.Join(publishRoot, filepath.FromSlash(compressedRel))); err != nil || !bytes.Equal(data, compressed) {
		t.Fatalf("published exact compressed index = %q, err %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(publishRoot, filepath.FromSlash(staleRaw))); err != nil {
		t.Fatalf("unresolved pre-existing raw file should remain before prune: %v", err)
	}
	resolved, status, err := runner.loadResolvedReleaseState()
	if err != nil || status != resolvedReleaseStateValid {
		t.Fatalf("resolved state status = %v, err %v", status, err)
	}
	paths, ok := resolved.paths("stable", releaseFingerprint(string(mustVerifyInRelease(t, inRelease, keyring))))
	if !ok || !paths[compressedRel] || paths[staleRaw] {
		t.Fatalf("resolved paths = %#v, found %t", paths, ok)
	}
	if _, err := runner.Verify(context.Background()); err != nil {
		t.Fatalf("verify with confirmed missing raw variant: %v", err)
	}
	removed, err := runner.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{staleRaw}) {
		t.Fatalf("pruned paths = %#v, want unresolved raw path", removed)
	}
	for _, byHash := range mustReadPublishedState(t, runner).ByHashFiles {
		if byHash.CanonicalPath != compressedRel {
			t.Fatalf("by-hash derived for unresolved path: %#v", byHash)
		}
	}
}

func TestSyncFailsOnNon404PrimaryDistsFailureBeforePublishingMetadata(t *testing.T) {
	wantData := []byte("index")
	digest := sha256.Sum256(wantData)
	release := []byte(fmt.Sprintf("Origin: example\nSHA256:\n %x %d main/binary-amd64/Packages\n", digest, len(wantData)))
	inRelease, keyring, _ := signedInRelease(t, release)
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/dists/stable/InRelease" {
			_, _ = w.Write(inRelease)
			return
		}
		if req.URL.Path == "/dists/stable/main/binary-amd64/Packages" {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		http.NotFound(w, req)
	}))
	defer primary.Close()

	publishRoot := t.TempDir()
	runner := testFetchStateRunner(t, primary.URL, writeTestKeyring(t, keyring), publishRoot, []string{"amd64"})
	_, err := runner.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "503 Service Unavailable") {
		t.Fatalf("Sync error = %v, want primary 503", err)
	}
	if _, err := os.Stat(filepath.Join(publishRoot, "dists", "stable", "InRelease")); !os.IsNotExist(err) {
		t.Fatalf("new signed metadata was published after failed exact file: %v", err)
	}
}

func TestReadPublishedStateSkipsUnadvertisedConfiguredCombination(t *testing.T) {
	root := t.TempDir()
	release := []byte("Origin: example\nSHA256:\n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages\n")
	inRelease, keyring, _ := signedInRelease(t, release)
	writePublishedInRelease(t, root, "stable", inRelease)
	writeTestFile(t, root, "dists/stable/Release", release)
	writeTestFile(t, root, "dists/stable/Release.gpg", armoredDetachedSignature(t, keyring[0], release))
	writeTestFile(t, root, "dists/stable/main/binary-amd64/Packages", nil)
	writeTestFile(t, root, "dists/stable/stale", []byte("stale"))
	runner := &Runner{Repo: config.APTRepository{
		Name:           "repo",
		AbsPublishPath: root,
		AbsKeyring:     writeTestKeyring(t, keyring),
		Architectures:  []string{"amd64", "arm64"},
		Suites:         []config.APTSuite{{Name: "stable", Components: []string{"main"}}},
	}}

	state, err := runner.readPublishedState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Packages) != 0 {
		t.Fatalf("packages = %d, want none", len(state.Packages))
	}
	wantMetadata := []string{"dists/stable/InRelease", "dists/stable/Release", "dists/stable/Release.gpg"}
	if got := metadataPaths(state.Metadata); !reflect.DeepEqual(got, wantMetadata) {
		t.Fatalf("published metadata = %#v, want %#v", got, wantMetadata)
	}
	if data, ok := metadataData(state.Metadata, "dists/stable/Release"); !ok || !bytes.Equal(data, release) {
		t.Fatalf("published Release metadata = %q, ok %t, want original Release bytes", data, ok)
	}
	removed, err := runner.pruneStateWithHistory(state, byHashHistory{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{"dists/stable/stale"}) {
		t.Fatalf("pruned files = %#v, want stale file only", removed)
	}
	for _, rel := range wantMetadata {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("valid metadata %s was not retained: %v", rel, err)
		}
	}
}

func TestReadPublishedStateRejectsAdvertisedMissingIndex(t *testing.T) {
	root := t.TempDir()
	release := []byte("Origin: example\nSHA256:\n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages\n")
	inRelease, keyring, _ := signedInRelease(t, release)
	writePublishedInRelease(t, root, "stable", inRelease)
	runner := &Runner{Repo: config.APTRepository{
		Name:           "repo",
		AbsPublishPath: root,
		AbsKeyring:     writeTestKeyring(t, keyring),
		Architectures:  []string{"amd64"},
		Suites:         []config.APTSuite{{Name: "stable", Components: []string{"main"}}},
	}}
	hashes, err := runner.readPublishedReleaseHashes("stable")
	if err != nil {
		t.Fatal(err)
	}
	if !releaseAdvertisesIndex("main/binary-amd64", "Packages", hashes) {
		t.Fatalf("Release hashes = %#v, want advertised Packages index", hashes)
	}

	_, err = runner.readPublishedState()
	if err == nil || !strings.Contains(err.Error(), "no valid published Packages index") {
		t.Fatalf("readPublishedState error = %v, want missing advertised index error", err)
	}
}

func TestParseReleaseHashesKeepsAllSupportedChecksums(t *testing.T) {
	hashes, err := parseReleaseHashes(`Origin: example
MD5Sum:
 11111111111111111111111111111111 12 main/binary-amd64/Packages.gz
SHA256:
 2222222222222222222222222222222222222222222222222222222222222222 12 main/binary-amd64/Packages.gz
SHA512:
 33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333 12 main/binary-amd64/Packages.gz
`)
	if err != nil {
		t.Fatal(err)
	}
	got := hashes["main/binary-amd64/Packages.gz"]
	if got.Size != 12 {
		t.Fatalf("size = %d, want 12", got.Size)
	}
	if got.Checksums["MD5Sum"] == "" || got.Checksums["SHA256"] == "" || got.Checksums["SHA512"] == "" {
		t.Fatalf("checksums = %#v, want md5/sha256/sha512", got.Checksums)
	}
}

func TestParseReleaseHashesRejectsConflictingEntries(t *testing.T) {
	_, err := parseReleaseHashes(`SHA256:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 12 main/binary-amd64/Packages.gz
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 12 main/binary-amd64/Packages.gz
`)
	if err == nil {
		t.Fatal("parseReleaseHashes succeeded, want conflict error")
	}
}

func TestParseReleaseHashesRejectsMalformedEntries(t *testing.T) {
	_, err := parseReleaseHashes(`SHA256:
 invalid-entry
`)
	if err == nil {
		t.Fatal("parseReleaseHashes succeeded, want malformed entry error")
	}
}

func TestParseReleaseHashesRejectsZeroSizeConflict(t *testing.T) {
	_, err := parseReleaseHashes(`SHA256:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 main/binary-amd64/Packages
SHA512:
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1 main/binary-amd64/Packages
`)
	if err == nil {
		t.Fatal("parseReleaseHashes succeeded, want zero-size conflict error")
	}
}

func TestFetchReleaseKeepsMatchingPlainReleaseWithInRelease(t *testing.T) {
	release := []byte("Origin: example\nSHA256:\n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 main/binary-amd64/Packages\n")
	inRelease, keyring, plain := signedInRelease(t, release)
	sig := detachedSignature(t, keyring[0], release)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dists/stable/InRelease":
			_, _ = w.Write(inRelease)
		case "/dists/stable/Release":
			_, _ = w.Write(release)
		case "/dists/stable/Release.gpg":
			_, _ = w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	runner, client := testAPTRunnerAndClient(t, server.URL)
	releaseText, hashes, metadata, err := runner.fetchRelease(context.Background(), client, keyring, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if releaseText != string(plain) {
		t.Fatalf("release text = %q, want verified cleartext %q", releaseText, plain)
	}
	if hashes["main/binary-amd64/Packages"].Size != 0 {
		t.Fatalf("parsed size = %d, want 0", hashes["main/binary-amd64/Packages"].Size)
	}
	got := metadataPaths(metadata)
	want := []string{"dists/stable/InRelease", "dists/stable/Release", "dists/stable/Release.gpg"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata paths = %#v, want %#v", got, want)
	}
	if data, ok := metadataData(metadata, "dists/stable/Release"); !ok || !bytes.Equal(data, release) {
		t.Fatalf("Release metadata = %q, ok %t, want original Release bytes", data, ok)
	}
}

func TestFetchReleaseKeepsMatchingArmoredReleaseWithInRelease(t *testing.T) {
	release := []byte("Origin: armored\n")
	inRelease, keyring, _ := signedInRelease(t, release)
	sig := append([]byte(" \t\r\n"), armoredDetachedSignature(t, keyring[0], release)...)
	runner := &Runner{Repo: config.APTRepository{Name: "repo"}}

	_, _, metadata, err := runner.selectReleaseForms(keyring, "stable", inRelease, true, release, true, sig, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"dists/stable/InRelease", "dists/stable/Release", "dists/stable/Release.gpg"}
	if got := metadataPaths(metadata); !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata paths = %#v, want %#v", got, want)
	}
}

func TestVerifyDetachedSignatureFormatsAndFailures(t *testing.T) {
	release := []byte("Origin: example\n")
	_, keyring, _ := signedInRelease(t, release)
	binarySig := detachedSignature(t, keyring[0], release)
	armoredSig := armoredDetachedSignature(t, keyring[0], release)
	truncatedArmoredSig := armoredSig[:bytes.LastIndex(armoredSig, []byte("-----END PGP SIGNATURE-----"))]
	armoredSigWithTrailingBody := bytes.Replace(armoredSig, []byte("\n-----END PGP SIGNATURE-----"), []byte("\nignored\n-----END PGP SIGNATURE-----"), 1)

	tests := []struct {
		name      string
		signature []byte
		message   []byte
		wantErr   bool
	}{
		{name: "binary", signature: binarySig, message: release},
		{name: "armored", signature: armoredSig, message: release},
		{name: "malformed armor", signature: truncatedArmoredSig, message: release, wantErr: true},
		{name: "trailing armored body", signature: armoredSigWithTrailingBody, message: release, wantErr: true},
		{name: "wrong armor type", signature: bytes.Replace(armoredSig, []byte("PGP SIGNATURE"), []byte("PGP MESSAGE"), 2), message: release, wantErr: true},
		{name: "invalid armored signature", signature: armoredSig, message: []byte("Origin: changed\n"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyDetachedSignature(tt.message, tt.signature, keyring)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyDetachedSignature() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestReleaseMatchesVerifiedCleartextCanonicalLineEndings(t *testing.T) {
	release := []byte("Origin: example\nSHA256:\n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 main/binary-amd64/Packages\n")
	_, _, plain := signedInRelease(t, release)

	for _, tt := range []struct {
		name string
		data []byte
	}{
		{name: "lf-final-newline", data: release},
		{name: "lf-extra-final-newline", data: append(append([]byte(nil), release...), '\n')},
		{name: "crlf-final-newline", data: []byte("Origin: example\r\nSHA256:\r\n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 main/binary-amd64/Packages\r\n")},
		{name: "canonical-cleartext", data: plain},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !releaseMatchesVerifiedCleartext(tt.data, plain) {
				t.Fatalf("releaseMatchesVerifiedCleartext() = false, want true")
			}
		})
	}
}

func TestFetchReleasePrefersInReleaseWhenDetachedFormDiffers(t *testing.T) {
	inRelease, keyring, _ := signedInRelease(t, []byte("Origin: example\nSHA256:\n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0 main/binary-amd64/Packages\n"))
	detachedRelease := []byte("Origin: different\n")
	detachedSig := detachedSignature(t, keyring[0], detachedRelease)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dists/stable/InRelease":
			_, _ = w.Write(inRelease)
		case "/dists/stable/Release":
			_, _ = w.Write(detachedRelease)
		case "/dists/stable/Release.gpg":
			_, _ = w.Write(detachedSig)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	runner, client := testAPTRunnerAndClient(t, server.URL)
	_, _, metadata, err := runner.fetchRelease(context.Background(), client, keyring, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := metadataPaths(metadata), []string{"dists/stable/InRelease"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata paths = %#v, want %#v", got, want)
	}
}

func TestFetchReleaseUsesValidDetachedPairWhenInReleaseMalformed(t *testing.T) {
	release := []byte("Origin: fallback\n")
	_, keyring, _ := signedInRelease(t, release)
	detachedSig := armoredDetachedSignature(t, keyring[0], release)
	releaseHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dists/stable/InRelease":
			_, _ = w.Write([]byte("unsigned prefix\n-----BEGIN PGP SIGNED MESSAGE-----\n"))
		case "/dists/stable/Release":
			releaseHits++
			_, _ = w.Write(release)
		case "/dists/stable/Release.gpg":
			_, _ = w.Write(detachedSig)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	runner, client := testAPTRunnerAndClient(t, server.URL)
	_, _, metadata, err := runner.fetchRelease(context.Background(), client, keyring, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if releaseHits != 1 {
		t.Fatalf("Release hits = %d, want 1", releaseHits)
	}
	want := []string{"dists/stable/Release", "dists/stable/Release.gpg"}
	if got := metadataPaths(metadata); !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata paths = %#v, want %#v", got, want)
	}
}

func TestFetchReleaseSignedFormAvailabilityAndFailures(t *testing.T) {
	release := []byte("Origin: example\n")
	inRelease, keyring, _ := signedInRelease(t, release)
	validSig := detachedSignature(t, keyring[0], release)

	tests := []struct {
		name      string
		responses map[string]testHTTPResponse
		wantPaths []string
		wantErr   string
	}{
		{
			name:      "only InRelease",
			responses: map[string]testHTTPResponse{"/dists/stable/InRelease": {data: inRelease}},
			wantPaths: []string{"dists/stable/InRelease"},
		},
		{
			name: "only detached pair",
			responses: map[string]testHTTPResponse{
				"/dists/stable/Release":     {data: release},
				"/dists/stable/Release.gpg": {data: validSig},
			},
			wantPaths: []string{"dists/stable/Release", "dists/stable/Release.gpg"},
		},
		{
			name: "partial detached pair with valid InRelease",
			responses: map[string]testHTTPResponse{
				"/dists/stable/InRelease": {data: inRelease},
				"/dists/stable/Release":   {data: release},
			},
			wantPaths: []string{"dists/stable/InRelease"},
		},
		{
			name: "detached Release missing with valid InRelease",
			responses: map[string]testHTTPResponse{
				"/dists/stable/InRelease":   {data: inRelease},
				"/dists/stable/Release.gpg": {data: validSig},
			},
			wantPaths: []string{"dists/stable/InRelease"},
		},
		{
			name: "invalid detached pair with valid InRelease",
			responses: map[string]testHTTPResponse{
				"/dists/stable/InRelease":   {data: inRelease},
				"/dists/stable/Release":     {data: release},
				"/dists/stable/Release.gpg": {data: []byte("invalid")},
			},
			wantPaths: []string{"dists/stable/InRelease"},
		},
		{
			name:      "all forms absent",
			responses: map[string]testHTTPResponse{},
			wantErr:   "no valid signed Release metadata",
		},
		{
			name: "all forms invalid",
			responses: map[string]testHTTPResponse{
				"/dists/stable/InRelease":   {data: []byte("invalid")},
				"/dists/stable/Release":     {data: release},
				"/dists/stable/Release.gpg": {data: []byte("invalid")},
			},
			wantErr: "no valid signed Release metadata",
		},
		{
			name: "non-404 InRelease failure is fatal",
			responses: map[string]testHTTPResponse{
				"/dists/stable/InRelease":   {status: http.StatusBadGateway},
				"/dists/stable/Release":     {data: release},
				"/dists/stable/Release.gpg": {data: validSig},
			},
			wantErr: "502 Bad Gateway",
		},
		{
			name: "non-404 detached failure is fatal despite valid InRelease",
			responses: map[string]testHTTPResponse{
				"/dists/stable/InRelease": {data: inRelease},
				"/dists/stable/Release":   {status: http.StatusInternalServerError},
			},
			wantErr: "500 Internal Server Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response, ok := tt.responses[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				if response.status != 0 {
					http.Error(w, http.StatusText(response.status), response.status)
					return
				}
				_, _ = w.Write(response.data)
			}))
			defer server.Close()

			runner, client := testAPTRunnerAndClient(t, server.URL)
			_, _, metadata, err := runner.fetchRelease(context.Background(), client, keyring, "stable")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("fetchRelease error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := metadataPaths(metadata); !reflect.DeepEqual(got, tt.wantPaths) {
				t.Fatalf("metadata paths = %#v, want %#v", got, tt.wantPaths)
			}
		})
	}
}

type testHTTPResponse struct {
	status int
	data   []byte
}

func TestValidateClearsignedStructureRejectsTrailingContent(t *testing.T) {
	inRelease, _, _ := signedInRelease(t, []byte("Origin: example\n"))
	err := validateClearsignedStructure(append(inRelease, []byte("\nunsigned trailer\n")...))
	if err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("validateClearsignedStructure error = %v, want trailing content error", err)
	}
}

func TestPruneStateRemovesStaleAlternateMetadata(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"dists/stable/InRelease", "dists/stable/Release"} {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(rel), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &Runner{Repo: config.APTRepository{AbsPublishPath: root}}
	removed, err := runner.pruneState(model.RepositoryState{
		Packages: map[string]model.Package{},
		Metadata: []model.MetadataFile{{Path: "dists/stable/Release"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{"dists/stable/InRelease"}) {
		t.Fatalf("removed = %#v, want stale InRelease only", removed)
	}
	if _, err := os.Stat(filepath.Join(root, "dists", "stable", "Release")); err != nil {
		t.Fatalf("Release was not kept: %v", err)
	}
}

func TestParsePackagesFiltersArchitecturesAndCarriesChecksums(t *testing.T) {
	pkgs, err := parsePackages([]byte(`Package: native
Architecture: amd64
Filename: pool/main/n/native/native_1_amd64.deb
Size: 10
SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Package: indep
Architecture: all
Filename: pool/main/i/indep/indep_1_all.deb
Size: 11
SHA512: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

Package: foreign
Architecture: arm64
Filename: pool/main/f/foreign/foreign_1_arm64.deb
Size: 12
SHA256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
`), nil, map[string]bool{"amd64": true, "all": true})
	if err != nil {
		t.Fatal(err)
	}
	got := packagePaths(pkgs)
	want := []string{
		"pool/main/i/indep/indep_1_all.deb",
		"pool/main/n/native/native_1_amd64.deb",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packages = %#v, want %#v", got, want)
	}
	if pkgs[1].Checksums["SHA512"] == "" {
		t.Fatalf("checksums = %#v, want SHA512 on arch-all package", pkgs[1].Checksums)
	}
}

func TestParseSourcesExpandsSourcePayloads(t *testing.T) {
	pkgs, err := parseSources([]byte(`Package: hello
Directory: pool/main/h/hello
Files:
 11111111111111111111111111111111 5 hello_1.dsc
 22222222222222222222222222222222 6 hello_1.tar.xz
Checksums-Sha256:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 5 hello_1.dsc
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 6 hello_1.tar.xz
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := packagePaths(pkgs)
	want := []string{
		"pool/main/h/hello/hello_1.dsc",
		"pool/main/h/hello/hello_1.tar.xz",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("source payloads = %#v, want %#v", got, want)
	}
	if pkgs[0].Checksums["MD5Sum"] == "" || pkgs[0].Checksums["SHA256"] == "" {
		t.Fatalf("checksums = %#v, want MD5Sum and SHA256", pkgs[0].Checksums)
	}
}

func TestAptFileExpectedUsesOnlyExactAdvertisedPaths(t *testing.T) {
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
	wantIconSources := []string{}
	if got := sourceDescriptions(rawIcons.Sources); !reflect.DeepEqual(got, wantIconSources) {
		t.Fatalf("raw icon sources = %#v, want %#v", got, wantIconSources)
	}
	rawYML := expected[0]
	wantYMLSources := []string{}
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
		out[p] = releaseFile{Size: int64(i + 1), Checksums: map[string]string{"SHA256": "sha"}}
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

func packagePaths(packages []model.Package) []string {
	out := make([]string, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, pkg.Path)
	}
	sort.Strings(out)
	return out
}

func sourceDescriptions(sources []download.Source) []string {
	out := make([]string, 0, len(sources))
	for _, source := range sources {
		out = append(out, source.RelPath+":"+source.Decompress)
	}
	return out
}

func metadataPaths(files []model.MetadataFile) []string {
	out := make([]string, 0, len(files))
	for _, file := range files {
		out = append(out, file.Path)
	}
	sort.Strings(out)
	return out
}

func metadataData(files []model.MetadataFile, path string) ([]byte, bool) {
	for _, file := range files {
		if file.Path == path {
			return file.Data, true
		}
	}
	return nil, false
}

func signedInRelease(t *testing.T, release []byte) ([]byte, openpgp.EntityList, []byte) {
	t.Helper()
	entity, err := openpgp.NewEntity("Mirror Sync", "Test Key", "mirror-sync@example.com", &packet.Config{RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, err := clearsign.Encode(&out, entity.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(release); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	plain, err := verifyInRelease(out.Bytes(), openpgp.EntityList{entity})
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), openpgp.EntityList{entity}, plain
}

func detachedSignature(t *testing.T, entity *openpgp.Entity, release []byte) []byte {
	t.Helper()
	var signature bytes.Buffer
	if err := openpgp.DetachSign(&signature, entity, bytes.NewReader(release), nil); err != nil {
		t.Fatal(err)
	}
	return signature.Bytes()
}

func armoredDetachedSignature(t *testing.T, entity *openpgp.Entity, release []byte) []byte {
	t.Helper()
	var signature bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&signature, entity, bytes.NewReader(release), nil); err != nil {
		t.Fatal(err)
	}
	return signature.Bytes()
}

func writePublishedInRelease(t *testing.T, root, suite string, inRelease []byte) {
	t.Helper()
	writeTestFile(t, root, pathJoin("dists", suite, "InRelease"), inRelease)
}

func writeTestKeyring(t *testing.T, keyring openpgp.EntityList) string {
	t.Helper()
	var out bytes.Buffer
	if err := keyring[0].Serialize(&out); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "keyring.gpg")
	if err := os.WriteFile(p, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeTestFile(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func xzTestData(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := xz.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func mustVerifyInRelease(t *testing.T, data []byte, keyring openpgp.EntityList) []byte {
	t.Helper()
	plain, err := verifyInRelease(data, keyring)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func mustReadPublishedState(t *testing.T, runner *Runner) model.RepositoryState {
	t.Helper()
	state, err := runner.readPublishedState()
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func testFetchStateRunner(t *testing.T, url, keyringPath, publishRoot string, archs []string) *Runner {
	t.Helper()
	cfg := &config.Config{Storage: config.Storage{Staging: t.TempDir()}, Sync: config.Sync{Download: config.Download{MaxInFlightRequests: 4}}}
	factory := httpx.NewFactory(0, limit.New(cfg.MaxInFlightRequests()))
	return &Runner{
		Config: cfg,
		Repo: config.APTRepository{
			Name:           "repo",
			AbsPublishPath: publishRoot,
			AbsKeyring:     keyringPath,
			PrimarySource:  config.Source{URL: url},
			Architectures:  archs,
			Suites:         []config.APTSuite{{Name: "stable", Components: []string{"main"}}},
		},
		HTTP: factory,
	}
}

func pathJoin(elem ...string) string {
	return strings.Join(elem, "/")
}

func testAPTRunnerAndClient(t *testing.T, url string) (*Runner, *httpx.Client) {
	t.Helper()
	cfg := &config.Config{Sync: config.Sync{Download: config.Download{MaxInFlightRequests: 4}}}
	src, err := cfg.Source("repo", config.RepoAPT, config.SourcePrimary, 0, config.Source{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	factory := httpx.NewFactory(0, limit.New(cfg.MaxInFlightRequests()))
	client, err := factory.Client(src)
	if err != nil {
		t.Fatal(err)
	}
	return &Runner{Config: cfg, Repo: config.APTRepository{Name: "repo"}, HTTP: factory}, client
}
