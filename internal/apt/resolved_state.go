package apt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/torob/mirror-sync/internal/model"
	"github.com/torob/mirror-sync/internal/publish"
	"github.com/torob/mirror-sync/internal/safe"
)

const (
	resolvedReleaseStateVersion = 2
	resolvedReleaseStateFile    = "resolved-release-files.json"
)

type resolvedReleaseStateStatus int

const (
	resolvedReleaseStateValid resolvedReleaseStateStatus = iota
	resolvedReleaseStateMissing
)

type resolvedReleaseState struct {
	Version  int                     `json:"version"`
	Releases []resolvedReleaseRecord `json:"releases"`
}

type resolvedReleaseRecord struct {
	Suite             string   `json:"suite"`
	Fingerprint       string   `json:"fingerprint"`
	SelectedPaths     []string `json:"selected_paths,omitempty"`
	ResolvedPaths     []string `json:"resolved_paths,omitempty"`
	SelectionComplete bool     `json:"selection_complete"`
	Paths             []string `json:"paths,omitempty"` // version 1 compatibility
}

func emptyResolvedReleaseState() resolvedReleaseState {
	return resolvedReleaseState{Version: resolvedReleaseStateVersion, Releases: []resolvedReleaseRecord{}}
}

func (s resolvedReleaseState) paths(suite, fingerprint string) (map[string]bool, bool) {
	for _, record := range s.Releases {
		if record.Suite == suite && strings.EqualFold(record.Fingerprint, fingerprint) {
			paths := make(map[string]bool, len(record.ResolvedPaths))
			for _, rel := range record.ResolvedPaths {
				paths[rel] = true
			}
			return paths, true
		}
	}
	return nil, false
}

func (s resolvedReleaseState) resolution(suite, fingerprint string) (selected, resolved map[string]bool, complete bool, found bool) {
	for _, record := range s.Releases {
		if record.Suite != suite || !strings.EqualFold(record.Fingerprint, fingerprint) {
			continue
		}
		selected = setFromSlice(record.SelectedPaths)
		resolved = setFromSlice(record.ResolvedPaths)
		return selected, resolved, record.SelectionComplete, true
	}
	return nil, nil, false, false
}

func (r *Runner) resolvedReleaseStatePath() string {
	if r.Config == nil || r.Config.Storage.Staging == "" || r.Repo.Name == "" {
		return ""
	}
	return filepath.Join(repoStaging(r.Config, "apt", r.Repo.Name), resolvedReleaseStateFile)
}

func (r *Runner) loadResolvedReleaseState() (resolvedReleaseState, resolvedReleaseStateStatus, error) {
	manifest := r.resolvedReleaseStatePath()
	if manifest == "" {
		return emptyResolvedReleaseState(), resolvedReleaseStateMissing, nil
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyResolvedReleaseState(), resolvedReleaseStateMissing, nil
		}
		return resolvedReleaseState{}, resolvedReleaseStateMissing, err
	}
	var state resolvedReleaseState
	if err := json.Unmarshal(data, &state); err != nil {
		return resolvedReleaseState{}, resolvedReleaseStateValid, fmt.Errorf("decode %s: %w", resolvedReleaseStateFile, err)
	}
	if err := validateResolvedReleaseState(state); err != nil {
		return resolvedReleaseState{}, resolvedReleaseStateValid, err
	}
	if state.Version == 1 {
		state = upgradeResolvedReleaseStateV1(state)
	}
	return state, resolvedReleaseStateValid, nil
}

func validateResolvedReleaseState(state resolvedReleaseState) error {
	if state.Version != 1 && state.Version != resolvedReleaseStateVersion {
		return fmt.Errorf("unsupported resolved Release state version %d", state.Version)
	}
	seen := map[string]bool{}
	for _, record := range state.Releases {
		if record.Suite == "" || strings.Contains(record.Suite, "/") {
			return fmt.Errorf("invalid resolved Release suite %q", record.Suite)
		}
		if len(record.Fingerprint) != 64 {
			return fmt.Errorf("invalid resolved Release fingerprint for suite %s", record.Suite)
		}
		if _, err := hex.DecodeString(record.Fingerprint); err != nil {
			return fmt.Errorf("invalid resolved Release fingerprint for suite %s", record.Suite)
		}
		key := record.Suite + "\x00" + strings.ToLower(record.Fingerprint)
		if seen[key] {
			return fmt.Errorf("duplicate resolved Release record for suite %s", record.Suite)
		}
		seen[key] = true
		selectedPaths := record.SelectedPaths
		resolvedPaths := record.ResolvedPaths
		if state.Version == 1 {
			selectedPaths = record.Paths
			resolvedPaths = record.Paths
		}
		seenSelected := map[string]bool{}
		prefix := "dists/" + record.Suite + "/"
		for _, rel := range selectedPaths {
			clean, err := safe.Rel(rel)
			if err != nil || clean != rel || !strings.HasPrefix(rel, prefix) {
				return fmt.Errorf("invalid resolved Release path %q", rel)
			}
			if seenSelected[rel] {
				return fmt.Errorf("duplicate selected Release path %q", rel)
			}
			seenSelected[rel] = true
		}
		seenResolved := map[string]bool{}
		for _, rel := range resolvedPaths {
			clean, err := safe.Rel(rel)
			if err != nil || clean != rel || !strings.HasPrefix(rel, prefix) {
				return fmt.Errorf("invalid resolved Release path %q", rel)
			}
			if seenResolved[rel] {
				return fmt.Errorf("duplicate resolved Release path %q", rel)
			}
			seenResolved[rel] = true
			if !seenSelected[rel] {
				return fmt.Errorf("resolved Release path %q was not selected", rel)
			}
		}
	}
	return nil
}

func upgradeResolvedReleaseStateV1(state resolvedReleaseState) resolvedReleaseState {
	state.Version = resolvedReleaseStateVersion
	for i := range state.Releases {
		paths := append([]string(nil), state.Releases[i].Paths...)
		state.Releases[i].SelectedPaths = append([]string(nil), paths...)
		state.Releases[i].ResolvedPaths = paths
		state.Releases[i].SelectionComplete = true
		state.Releases[i].Paths = nil
	}
	return state
}

func resolvedRecords(state model.RepositoryState) []resolvedReleaseRecord {
	selectedBySuite := map[string][]string{}
	for _, file := range state.SelectedFiles {
		suite := suiteFromCanonical(file.Path)
		selectedBySuite[suite] = append(selectedBySuite[suite], file.Path)
	}
	pathsBySuite := map[string][]string{}
	for _, file := range state.Files {
		suite := suiteFromCanonical(file.Path)
		pathsBySuite[suite] = append(pathsBySuite[suite], file.Path)
	}
	records := make([]resolvedReleaseRecord, 0, len(state.ReleaseFingerprints))
	for suite, fingerprint := range state.ReleaseFingerprints {
		selected := append([]string(nil), selectedBySuite[suite]...)
		paths := append([]string(nil), pathsBySuite[suite]...)
		sort.Strings(selected)
		sort.Strings(paths)
		records = append(records, resolvedReleaseRecord{
			Suite: suite, Fingerprint: fingerprint, SelectedPaths: selected, ResolvedPaths: paths, SelectionComplete: true,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Suite < records[j].Suite })
	return records
}

func (r *Runner) prepareResolvedReleaseState(state model.RepositoryState) error {
	current, _, err := r.loadResolvedReleaseState()
	if err != nil {
		return err
	}
	for _, incoming := range resolvedRecords(state) {
		found := false
		for i, existing := range current.Releases {
			if existing.Suite == incoming.Suite && strings.EqualFold(existing.Fingerprint, incoming.Fingerprint) {
				current.Releases[i] = mergeResolvedReleaseRecords(existing, incoming)
				found = true
				break
			}
		}
		if !found {
			current.Releases = append(current.Releases, incoming)
		}
	}
	return r.writeResolvedReleaseState(current)
}

func mergeResolvedReleaseRecords(a, b resolvedReleaseRecord) resolvedReleaseRecord {
	selected := setFromSlice(a.SelectedPaths)
	for _, rel := range b.SelectedPaths {
		selected[rel] = true
	}
	resolved := setFromSlice(a.ResolvedPaths)
	for _, rel := range b.SelectedPaths {
		delete(resolved, rel)
	}
	for _, rel := range b.ResolvedPaths {
		resolved[rel] = true
	}
	out := resolvedReleaseRecord{
		Suite:             b.Suite,
		Fingerprint:       b.Fingerprint,
		SelectedPaths:     sortedSet(selected),
		ResolvedPaths:     sortedSet(resolved),
		SelectionComplete: a.SelectionComplete || b.SelectionComplete,
	}
	return out
}

func sortedSet(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (r *Runner) commitResolvedReleaseState(state model.RepositoryState) error {
	return r.writeResolvedReleaseState(resolvedReleaseState{Version: resolvedReleaseStateVersion, Releases: resolvedRecords(state)})
}

func (r *Runner) writeResolvedReleaseState(state resolvedReleaseState) error {
	manifest := r.resolvedReleaseStatePath()
	if manifest == "" {
		return nil
	}
	sort.Slice(state.Releases, func(i, j int) bool {
		if state.Releases[i].Suite != state.Releases[j].Suite {
			return state.Releases[i].Suite < state.Releases[j].Suite
		}
		return state.Releases[i].Fingerprint < state.Releases[j].Fingerprint
	})
	if err := validateResolvedReleaseState(state); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	root := filepath.Dir(manifest)
	return publish.AtomicWrite(root, root, resolvedReleaseStateFile, data)
}
