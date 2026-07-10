package apt

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/model"
)

func TestLoadResolvedReleaseStateUpgradesVersionOneWithoutInferringMissingPaths(t *testing.T) {
	staging := t.TempDir()
	runner := &Runner{
		Config: &config.Config{Storage: config.Storage{Staging: staging}},
		Repo:   config.APTRepository{Name: "repo"},
	}
	manifest := runner.resolvedReleaseStatePath()
	if err := os.MkdirAll(filepath.Dir(manifest), 0o755); err != nil {
		t.Fatal(err)
	}
	fingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	data := `{"version":1,"releases":[{"suite":"stable","fingerprint":"` + fingerprint + `","paths":["dists/stable/main/binary-amd64/Packages.xz"]}]}`
	if err := os.WriteFile(manifest, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	state, status, err := runner.loadResolvedReleaseState()
	if err != nil {
		t.Fatal(err)
	}
	if status != resolvedReleaseStateValid || state.Version != resolvedReleaseStateVersion {
		t.Fatalf("status=%v version=%d", status, state.Version)
	}
	selected, resolved, complete, found := state.resolution("stable", fingerprint)
	path := "dists/stable/main/binary-amd64/Packages.xz"
	if !found || !complete || !selected[path] || !resolved[path] {
		t.Fatalf("resolution selected=%v resolved=%v complete=%t found=%t", selected, resolved, complete, found)
	}
	newPath := "dists/stable/main/binary-amd64/Packages"
	files := releaseFilesToResolve([]model.RepositoryFile{{Path: path}, {Path: newPath}}, selected, resolved, complete)
	if want := []model.RepositoryFile{{Path: path}, {Path: newPath}}; !reflect.DeepEqual(files, want) {
		t.Fatalf("files=%#v want known positive plus unknown path %#v", files, want)
	}
}

func TestResolvedRecordsTrackSelectedAndResolvedPaths(t *testing.T) {
	fingerprint := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	records := resolvedRecords(model.RepositoryState{
		ReleaseFingerprints: map[string]string{"stable": fingerprint},
		SelectedFiles: []model.RepositoryFile{
			{Path: "dists/stable/main/binary-amd64/Packages"},
			{Path: "dists/stable/main/binary-amd64/Packages.xz"},
		},
		Files: []model.RepositoryFile{{Path: "dists/stable/main/binary-amd64/Packages.xz"}},
	})
	if len(records) != 1 {
		t.Fatalf("records=%#v", records)
	}
	record := records[0]
	wantSelected := []string{
		"dists/stable/main/binary-amd64/Packages",
		"dists/stable/main/binary-amd64/Packages.xz",
	}
	if !record.SelectionComplete || !reflect.DeepEqual(record.SelectedPaths, wantSelected) {
		t.Fatalf("record=%#v", record)
	}
	if want := []string{"dists/stable/main/binary-amd64/Packages.xz"}; !reflect.DeepEqual(record.ResolvedPaths, want) {
		t.Fatalf("resolved=%#v want=%#v", record.ResolvedPaths, want)
	}
}

func TestValidateResolvedReleaseStateRejectsResolvedPathOutsideSelection(t *testing.T) {
	err := validateResolvedReleaseState(resolvedReleaseState{
		Version: resolvedReleaseStateVersion,
		Releases: []resolvedReleaseRecord{{
			Suite:             "stable",
			Fingerprint:       "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			SelectedPaths:     []string{"dists/stable/main/binary-amd64/Packages.xz"},
			ResolvedPaths:     []string{"dists/stable/main/binary-amd64/Packages.gz"},
			SelectionComplete: true,
		}},
	})
	if err == nil {
		t.Fatal("validation succeeded, want resolved path outside selection error")
	}
}

func TestReleaseFilesToResolveSkipsKnownMissingAndIncludesNewSelection(t *testing.T) {
	advertised := []model.RepositoryFile{
		{Path: "dists/stable/main/binary-amd64/Packages.xz"},
		{Path: "dists/stable/main/binary-amd64/Packages"},
		{Path: "dists/stable/new-component/binary-amd64/Packages.xz"},
	}
	selected := map[string]bool{
		advertised[0].Path: true,
		advertised[1].Path: true,
	}
	resolved := map[string]bool{advertised[0].Path: true}
	got := releaseFilesToResolve(advertised, selected, resolved, true)
	want := []model.RepositoryFile{advertised[0], advertised[2]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("files=%#v want=%#v", got, want)
	}
	if got := releaseFilesToResolve(advertised, selected, resolved, false); !reflect.DeepEqual(got, advertised) {
		t.Fatalf("incomplete-cache files=%#v want all", got)
	}
}

func TestChangedReleaseFingerprintForcesFullResolution(t *testing.T) {
	oldFingerprint := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	newFingerprint := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	advertised := []model.RepositoryFile{
		{Path: "dists/stable/main/binary-amd64/Packages.xz"},
		{Path: "dists/stable/main/binary-amd64/Packages"},
	}
	state := resolvedReleaseState{
		Version: resolvedReleaseStateVersion,
		Releases: []resolvedReleaseRecord{{
			Suite:             "stable",
			Fingerprint:       oldFingerprint,
			SelectedPaths:     []string{advertised[0].Path, advertised[1].Path},
			ResolvedPaths:     []string{advertised[0].Path},
			SelectionComplete: true,
		}},
	}
	selected, resolved, complete, found := state.resolution("stable", newFingerprint)
	if found || complete {
		t.Fatalf("changed fingerprint reused cache: found=%t complete=%t", found, complete)
	}
	if got := releaseFilesToResolve(advertised, selected, resolved, complete && found); !reflect.DeepEqual(got, advertised) {
		t.Fatalf("files=%#v want full resolution %#v", got, advertised)
	}
}

func TestMergeResolvedReleaseRecordsPreservesSelectionsAcrossPlans(t *testing.T) {
	fingerprint := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	got := mergeResolvedReleaseRecords(
		resolvedReleaseRecord{
			Suite: "stable", Fingerprint: fingerprint,
			SelectedPaths: []string{"dists/stable/main/Packages.xz"},
			ResolvedPaths: []string{"dists/stable/main/Packages.xz"},
		},
		resolvedReleaseRecord{
			Suite: "stable", Fingerprint: fingerprint,
			SelectedPaths: []string{"dists/stable/contrib/Packages", "dists/stable/contrib/Packages.xz"},
			ResolvedPaths: []string{"dists/stable/contrib/Packages.xz"}, SelectionComplete: true,
		},
	)
	wantSelected := []string{
		"dists/stable/contrib/Packages",
		"dists/stable/contrib/Packages.xz",
		"dists/stable/main/Packages.xz",
	}
	wantResolved := []string{
		"dists/stable/contrib/Packages.xz",
		"dists/stable/main/Packages.xz",
	}
	if !got.SelectionComplete || !reflect.DeepEqual(got.SelectedPaths, wantSelected) || !reflect.DeepEqual(got.ResolvedPaths, wantResolved) {
		t.Fatalf("merged=%#v", got)
	}
}

func TestMergeResolvedReleaseRecordsReplacesCurrentSelectionResult(t *testing.T) {
	fingerprint := "abababababababababababababababababababababababababababababababab"
	path := "dists/stable/main/Packages.xz"
	got := mergeResolvedReleaseRecords(
		resolvedReleaseRecord{
			Suite: "stable", Fingerprint: fingerprint,
			SelectedPaths: []string{path}, ResolvedPaths: []string{path}, SelectionComplete: true,
		},
		resolvedReleaseRecord{
			Suite: "stable", Fingerprint: fingerprint,
			SelectedPaths: []string{path}, SelectionComplete: true,
		},
	)
	if !reflect.DeepEqual(got.SelectedPaths, []string{path}) || len(got.ResolvedPaths) != 0 {
		t.Fatalf("merged=%#v, want current selection recorded missing", got)
	}
}
