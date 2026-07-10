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
	resolvedReleaseStateVersion = 1
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
	Suite       string   `json:"suite"`
	Fingerprint string   `json:"fingerprint"`
	Paths       []string `json:"paths"`
}

func emptyResolvedReleaseState() resolvedReleaseState {
	return resolvedReleaseState{Version: resolvedReleaseStateVersion, Releases: []resolvedReleaseRecord{}}
}

func (s resolvedReleaseState) paths(suite, fingerprint string) (map[string]bool, bool) {
	for _, record := range s.Releases {
		if record.Suite == suite && strings.EqualFold(record.Fingerprint, fingerprint) {
			paths := make(map[string]bool, len(record.Paths))
			for _, rel := range record.Paths {
				paths[rel] = true
			}
			return paths, true
		}
	}
	return nil, false
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
	return state, resolvedReleaseStateValid, nil
}

func validateResolvedReleaseState(state resolvedReleaseState) error {
	if state.Version != resolvedReleaseStateVersion {
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
		seenPaths := map[string]bool{}
		prefix := "dists/" + record.Suite + "/"
		for _, rel := range record.Paths {
			clean, err := safe.Rel(rel)
			if err != nil || clean != rel || !strings.HasPrefix(rel, prefix) {
				return fmt.Errorf("invalid resolved Release path %q", rel)
			}
			if seenPaths[rel] {
				return fmt.Errorf("duplicate resolved Release path %q", rel)
			}
			seenPaths[rel] = true
		}
	}
	return nil
}

func resolvedRecords(state model.RepositoryState) []resolvedReleaseRecord {
	pathsBySuite := map[string][]string{}
	for _, file := range state.Files {
		suite := suiteFromCanonical(file.Path)
		pathsBySuite[suite] = append(pathsBySuite[suite], file.Path)
	}
	records := make([]resolvedReleaseRecord, 0, len(state.ReleaseFingerprints))
	for suite, fingerprint := range state.ReleaseFingerprints {
		paths := append([]string(nil), pathsBySuite[suite]...)
		sort.Strings(paths)
		records = append(records, resolvedReleaseRecord{Suite: suite, Fingerprint: fingerprint, Paths: paths})
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
				current.Releases[i] = incoming
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
