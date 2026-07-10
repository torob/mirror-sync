package apt

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/httpx"
	"github.com/torob/mirror-sync/internal/limit"
	"github.com/torob/mirror-sync/internal/model"
)

func TestParseAcquireByHash(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    bool
		wantErr bool
	}{
		{name: "absent", text: "Origin: example\n"},
		{name: "yes", text: "Acquire-By-Hash: yes\n", want: true},
		{name: "mixed-case", text: "acquire-by-hash: YeS\n", want: true},
		{name: "no", text: "Acquire-By-Hash: no\n"},
		{name: "matching-duplicate", text: "Acquire-By-Hash: YES\nAcquire-By-Hash: yes\n", want: true},
		{name: "conflicting-duplicate", text: "Acquire-By-Hash: yes\nAcquire-By-Hash: no\n", wantErr: true},
		{name: "invalid", text: "Acquire-By-Hash: maybe\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAcquireByHash(tt.text)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAcquireByHash() error = %v, wantErr %t", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("parseAcquireByHash() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestFetchDetachedReleaseRejectsConflictingAcquireByHash(t *testing.T) {
	entity, err := openpgp.NewEntity("Mirror Sync", "Detached Test", "mirror-sync@example.com", &packet.Config{RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}
	release := []byte("Acquire-By-Hash: yes\nAcquire-By-Hash: no\nSHA256:\n " + strings.Repeat("0", 64) + " 0 main/binary-amd64/Packages\n")
	var signature bytes.Buffer
	if err := openpgp.DetachSign(&signature, entity, bytes.NewReader(release), nil); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/dists/stable/Release":
			_, _ = w.Write(release)
		case "/dists/stable/Release.gpg":
			_, _ = w.Write(signature.Bytes())
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	runner, client := testAPTRunnerAndClient(t, server.URL)
	_, _, _, err = runner.fetchRelease(context.Background(), client, openpgp.EntityList{entity}, "stable")
	if err == nil || !strings.Contains(err.Error(), "conflicting Acquire-By-Hash") {
		t.Fatalf("fetchRelease() error = %v, want conflicting Acquire-By-Hash", err)
	}
}

func TestDeriveByHashFilesUsesEveryAdvertisedAlgorithmAndLayout(t *testing.T) {
	files := []model.RepositoryFile{
		{
			Path: "dists/noble/Contents-amd64.gz", Size: 7,
			Checksums: map[string]string{
				"MD5Sum": strings.Repeat("1", 32),
				"SHA256": strings.Repeat("2", 64),
			},
		},
		{
			Path: "dists/noble/main/binary-amd64/Packages.xz", Size: 9,
			Checksums: map[string]string{
				"MD5Sum": strings.Repeat("3", 32),
				"SHA1":   strings.Repeat("4", 40),
				"SHA256": strings.Repeat("5", 64),
				"SHA512": strings.Repeat("6", 128),
			},
		},
	}
	got, err := deriveByHashFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, file := range got {
		paths = append(paths, file.Path)
	}
	want := []string{
		"dists/noble/by-hash/SHA256/" + strings.Repeat("2", 64),
		"dists/noble/by-hash/MD5Sum/" + strings.Repeat("1", 32),
		"dists/noble/main/binary-amd64/by-hash/SHA512/" + strings.Repeat("6", 128),
		"dists/noble/main/binary-amd64/by-hash/SHA256/" + strings.Repeat("5", 64),
		"dists/noble/main/binary-amd64/by-hash/SHA1/" + strings.Repeat("4", 40),
		"dists/noble/main/binary-amd64/by-hash/MD5Sum/" + strings.Repeat("3", 32),
	}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("by-hash paths = %#v, want %#v", paths, want)
	}
}

func TestDeriveByHashFilesRejectsMalformedDigest(t *testing.T) {
	for _, digest := range []string{"short", strings.Repeat("z", 64)} {
		_, err := deriveByHashFiles([]model.RepositoryFile{{
			Path: "dists/noble/main/binary-amd64/Packages", Size: 1,
			Checksums: map[string]string{"SHA256": digest},
		}})
		if err == nil {
			t.Fatalf("deriveByHashFiles accepted digest %q", digest)
		}
	}
}

func TestDeriveByHashFilesCoversRepresentativeReleaseIndexes(t *testing.T) {
	canonicalPaths := []string{
		"dists/noble/Contents-amd64.gz",
		"dists/noble/main/binary-amd64/Packages.xz",
		"dists/noble/main/binary-amd64/Release",
		"dists/noble/main/cnf/Commands-amd64.xz",
		"dists/noble/main/debian-installer/binary-amd64/Packages.gz",
		"dists/noble/main/dep11/Components-amd64.yml.xz",
		"dists/noble/main/i18n/Translation-en.xz",
		"dists/noble/main/source/Sources.xz",
	}
	files := make([]model.RepositoryFile, 0, len(canonicalPaths))
	for i, canonical := range canonicalPaths {
		digest := fmt.Sprintf("%064x", i+1)
		files = append(files, model.RepositoryFile{Path: canonical, Size: int64(i), Checksums: map[string]string{"SHA256": digest}})
	}
	derived, err := deriveByHashFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(derived) != len(canonicalPaths) {
		t.Fatalf("derived files = %d, want %d", len(derived), len(canonicalPaths))
	}
	for _, file := range derived {
		wantPrefix := filepath.ToSlash(filepath.Join(filepath.Dir(file.CanonicalPath), "by-hash", "SHA256")) + "/"
		if !strings.HasPrefix(file.Path, wantPrefix) {
			t.Fatalf("%s destination = %s, want prefix %s", file.CanonicalPath, file.Path, wantPrefix)
		}
	}
}

func TestUpdateByHashHistoryKeepsNewestThreeDistinctGenerations(t *testing.T) {
	history := emptyByHashHistory()
	canonical := "dists/stable/main/binary-amd64/Packages"
	for i, digit := range []string{"1", "2", "3", "4"} {
		digest := strings.Repeat(digit, 64)
		destination, err := byHashDestination(canonical, "SHA256", digest)
		if err != nil {
			t.Fatal(err)
		}
		history = updateByHashHistory(history, model.RepositoryState{
			ByHashEnabled: map[string]bool{"stable": true},
			ByHashFiles: []model.ByHashFile{{
				CanonicalPath: canonical, Path: destination, Algorithm: "SHA256", Digest: digest, Size: int64(i + 1),
			}},
		})
	}
	if len(history.Records) != 1 || len(history.Records[0].Generations) != 3 {
		t.Fatalf("history = %#v, want one record with three generations", history)
	}
	var digests []string
	for _, generation := range history.Records[0].Generations {
		digests = append(digests, generation.Digest[:1])
	}
	if !reflect.DeepEqual(digests, []string{"4", "3", "2"}) {
		t.Fatalf("history digests = %v, want newest three", digests)
	}
	history = updateByHashHistory(history, model.RepositoryState{ByHashEnabled: map[string]bool{"stable": false}})
	if len(history.Records) != 0 {
		t.Fatalf("disabled history records = %#v, want none", history.Records)
	}
}

func TestPruneWithCorruptHistoryPreservesUnknownByHash(t *testing.T) {
	root := t.TempDir()
	staging := t.TempDir()
	unknown := "dists/stable/main/binary-amd64/by-hash/SHA256/" + strings.Repeat("f", 64)
	stale := "dists/stable/stale"
	writeTestFile(t, root, unknown, []byte("historic"))
	writeTestFile(t, root, stale, []byte("stale"))
	runner := &Runner{
		Config: &config.Config{Storage: config.Storage{Staging: staging}},
		Repo:   config.APTRepository{Name: "repo", AbsPublishPath: root},
	}
	manifest := runner.byHashHistoryPath()
	if err := os.MkdirAll(filepath.Dir(manifest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed, err := runner.pruneState(model.RepositoryState{Packages: map[string]model.Package{}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{stale}) {
		t.Fatalf("removed = %#v, want only stale non-by-hash file", removed)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(unknown))); err != nil {
		t.Fatalf("unknown by-hash object was not preserved: %v", err)
	}
}

func TestByHashSyncLifecycle(t *testing.T) {
	entity, err := openpgp.NewEntity("Mirror Sync", "By Hash Test", "mirror-sync@example.com", &packet.Config{RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	staging := t.TempDir()
	keyringPath := writeTestKeyring(t, openpgp.EntityList{entity})

	type generation struct {
		data      []byte
		release   []byte
		inRelease []byte
		checksums map[string]string
	}
	makeGeneration := func(number int, enabled bool) generation {
		data := []byte(fmt.Sprintf("# index generation %d\n", number))
		release, checksums := releaseForByHashTest(data, enabled)
		return generation{data: data, release: release, inRelease: signRelease(t, entity, release), checksums: checksums}
	}
	current := makeGeneration(1, true)
	byHashRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/dists/stable/InRelease":
			_, _ = w.Write(current.inRelease)
		case "/dists/stable/Release":
			_, _ = w.Write(current.release)
		case "/dists/stable/main/binary-amd64/Packages":
			_, _ = w.Write(current.data)
		default:
			if strings.Contains(request.URL.Path, "/by-hash/") {
				byHashRequests++
			}
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	// Simulate an upgrade from a published repository that advertised by-hash
	// but predates mirror-sync's local by-hash materialization.
	writeTestFile(t, root, "dists/stable/InRelease", current.inRelease)
	writeTestFile(t, root, "dists/stable/Release", current.release)
	writeTestFile(t, root, "dists/stable/main/binary-amd64/Packages", current.data)

	cfg := &config.Config{
		Storage: config.Storage{Staging: staging},
		Sync: config.Sync{
			Prune:    true,
			Download: config.Download{MaxInFlightRequests: 4},
		},
	}
	runner := &Runner{
		Config: cfg,
		Repo: config.APTRepository{
			Name:           "repo",
			AbsPublishPath: root,
			AbsKeyring:     keyringPath,
			PrimarySource:  config.Source{URL: server.URL},
			Architectures:  []string{"amd64"},
			Suites:         []config.APTSuite{{Name: "stable", Components: []string{"main"}}},
		},
		HTTP: httpx.NewFactory(0, limit.New(cfg.MaxInFlightRequests())),
	}
	repositoryPlan, err := runner.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if repositoryPlan.MetadataFiles != 6 {
		t.Fatalf("plan metadata files = %d, want InRelease + canonical + four by-hash objects", repositoryPlan.MetadataFiles)
	}

	oldSHA256Path, _ := byHashDestination("dists/stable/main/binary-amd64/Packages", "SHA256", current.checksums["SHA256"])
	for number := 2; number <= 5; number++ {
		current = makeGeneration(number, true)
		if _, err := runner.Sync(context.Background()); err != nil {
			t.Fatalf("generation %d sync: %v", number, err)
		}
		if number == 2 {
			got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(oldSHA256Path)))
			if err != nil {
				t.Fatalf("first-upgrade old by-hash object: %v", err)
			}
			if string(got) != "# index generation 1\n" {
				t.Fatalf("first-upgrade object = %q", got)
			}
		}
	}
	if byHashRequests != 0 {
		t.Fatalf("upstream by-hash requests = %d, want zero", byHashRequests)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(oldSHA256Path))); !os.IsNotExist(err) {
		t.Fatalf("oldest generation stat error = %v, want pruned", err)
	}
	history, status, err := runner.loadByHashHistory()
	if err != nil || status != byHashHistoryValid {
		t.Fatalf("history status = %v, error = %v", status, err)
	}
	shaRecord := findHistoryRecord(history, "SHA256")
	if len(shaRecord.Generations) != 3 {
		t.Fatalf("SHA256 generations = %d, want 3", len(shaRecord.Generations))
	}

	currentSHA256Path, _ := byHashDestination("dists/stable/main/binary-amd64/Packages", "SHA256", current.checksums["SHA256"])
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(currentSHA256Path))); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Verify(context.Background()); err != nil {
		t.Fatalf("verify repair: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(currentSHA256Path))); err != nil || !bytes.Equal(got, current.data) {
		t.Fatalf("repaired current by-hash = %q, %v", got, err)
	}
	if byHashRequests != 0 {
		t.Fatalf("verify fetched upstream by-hash URL; requests = %d", byHashRequests)
	}

	unknown := "dists/stable/main/binary-amd64/by-hash/SHA256/" + strings.Repeat("f", 64)
	writeTestFile(t, root, unknown, []byte("unknown history"))
	if err := os.WriteFile(runner.byHashHistoryPath(), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	current = makeGeneration(6, true)
	if _, err := runner.Sync(context.Background()); err != nil {
		t.Fatalf("corrupt-history sync: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(unknown))); err != nil {
		t.Fatalf("unknown object was deleted during corrupt-manifest cycle: %v", err)
	}
	current = makeGeneration(7, true)
	if _, err := runner.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(unknown))); !os.IsNotExist(err) {
		t.Fatalf("unknown object stat error = %v, want pruned after repaired history", err)
	}

	current = makeGeneration(8, false)
	if _, err := runner.Sync(context.Background()); err != nil {
		t.Fatalf("disabled by-hash sync: %v", err)
	}
	if paths := existingByHashTestPaths(t, root); len(paths) != 0 {
		t.Fatalf("by-hash disabled but objects remain: %v", paths)
	}
}

func TestSyncLeavesOldSignedMetadataWhenByHashMaterializationFails(t *testing.T) {
	entity, err := openpgp.NewEntity("Mirror Sync", "By Hash Failure Test", "mirror-sync@example.com", &packet.Config{RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	staging := t.TempDir()
	oldData := []byte("# index generation 1\n")
	oldRelease, _ := releaseForByHashTest(oldData, true)
	oldInRelease := signRelease(t, entity, oldRelease)
	writeTestFile(t, root, "dists/stable/InRelease", oldInRelease)
	writeTestFile(t, root, "dists/stable/Release", oldRelease)
	writeTestFile(t, root, "dists/stable/main/binary-amd64/Packages", oldData)
	writeTestFile(t, root, "dists/stable/main/binary-amd64/by-hash", []byte("not a directory"))

	newData := []byte("# index generation 2\n")
	newRelease, _ := releaseForByHashTest(newData, true)
	newInRelease := signRelease(t, entity, newRelease)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/dists/stable/InRelease":
			_, _ = w.Write(newInRelease)
		case "/dists/stable/Release":
			_, _ = w.Write(newRelease)
		case "/dists/stable/main/binary-amd64/Packages":
			_, _ = w.Write(newData)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	cfg := &config.Config{Storage: config.Storage{Staging: staging}, Sync: config.Sync{Download: config.Download{MaxInFlightRequests: 4}}}
	runner := &Runner{
		Config: cfg,
		Repo: config.APTRepository{
			Name:           "repo",
			AbsPublishPath: root,
			AbsKeyring:     writeTestKeyring(t, openpgp.EntityList{entity}),
			PrimarySource:  config.Source{URL: server.URL},
			Architectures:  []string{"amd64"},
			Suites:         []config.APTSuite{{Name: "stable", Components: []string{"main"}}},
		},
		HTTP: httpx.NewFactory(0, limit.New(cfg.MaxInFlightRequests())),
	}
	if _, err := runner.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "materialize by-hash") {
		t.Fatalf("Sync() error = %v, want by-hash materialization failure", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "dists", "stable", "InRelease"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, oldInRelease) {
		t.Fatal("new signed metadata became visible after by-hash materialization failure")
	}
}

func releaseForByHashTest(data []byte, enabled bool) ([]byte, map[string]string) {
	md5Digest := md5.Sum(data)
	sha1Digest := sha1.Sum(data)
	sha256Digest := sha256.Sum256(data)
	sha512Digest := sha512.Sum512(data)
	checksums := map[string]string{
		"MD5Sum": hex.EncodeToString(md5Digest[:]),
		"SHA1":   hex.EncodeToString(sha1Digest[:]),
		"SHA256": hex.EncodeToString(sha256Digest[:]),
		"SHA512": hex.EncodeToString(sha512Digest[:]),
	}
	acquire := "no"
	if enabled {
		acquire = "yes"
	}
	release := fmt.Sprintf("Origin: example\nAcquire-By-Hash: %s\nMD5Sum:\n %s %d main/binary-amd64/Packages\nSHA1:\n %s %d main/binary-amd64/Packages\nSHA256:\n %s %d main/binary-amd64/Packages\nSHA512:\n %s %d main/binary-amd64/Packages\n",
		acquire,
		checksums["MD5Sum"], len(data),
		checksums["SHA1"], len(data),
		checksums["SHA256"], len(data),
		checksums["SHA512"], len(data),
	)
	return []byte(release), checksums
}

func signRelease(t *testing.T, entity *openpgp.Entity, release []byte) []byte {
	t.Helper()
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
	return out.Bytes()
}

func findHistoryRecord(history byHashHistory, algorithm string) byHashHistoryRecord {
	for _, record := range history.Records {
		if record.Algorithm == algorithm {
			return record
		}
	}
	return byHashHistoryRecord{}
}

func existingByHashTestPaths(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	if err := filepath.WalkDir(root, func(file string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, file)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.Contains(rel, "/by-hash/") {
			out = append(out, rel)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
