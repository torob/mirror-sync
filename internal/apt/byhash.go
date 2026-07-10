package apt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/torob/mirror-sync/internal/model"
	"github.com/torob/mirror-sync/internal/publish"
	"github.com/torob/mirror-sync/internal/safe"
)

const (
	byHashHistoryVersion = 1
	byHashHistoryFile    = "by-hash-history.json"
)

type byHashHistoryStatus int

const (
	byHashHistoryValid byHashHistoryStatus = iota
	byHashHistoryMissing
	byHashHistoryCorrupt
)

type byHashHistory struct {
	Version int                   `json:"version"`
	Records []byHashHistoryRecord `json:"records"`
}

type byHashHistoryRecord struct {
	CanonicalPath string                    `json:"canonical_path"`
	Algorithm     string                    `json:"algorithm"`
	Generations   []byHashHistoryGeneration `json:"generations"`
}

type byHashHistoryGeneration struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

func parseAcquireByHash(text string) (bool, error) {
	var value bool
	seen := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name, raw, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "Acquire-By-Hash") {
			continue
		}
		var parsed bool
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "yes":
			parsed = true
		case "no":
			parsed = false
		default:
			return false, fmt.Errorf("invalid Acquire-By-Hash value %q", strings.TrimSpace(raw))
		}
		if seen && parsed != value {
			return false, fmt.Errorf("conflicting Acquire-By-Hash values")
		}
		seen = true
		value = parsed
	}
	return seen && value, nil
}

func deriveByHashFiles(files []model.RepositoryFile) ([]model.ByHashFile, error) {
	files = sortedFiles(files)
	byPath := map[string]model.ByHashFile{}
	for _, file := range files {
		if !strings.HasPrefix(file.Path, "dists/") {
			return nil, fmt.Errorf("by-hash canonical path %q is outside dists", file.Path)
		}
		found := false
		for _, algorithm := range []string{"SHA512", "SHA256", "SHA1", "MD5Sum"} {
			digest := checksumFromMap(file.Checksums, algorithm)
			if digest == "" {
				continue
			}
			found = true
			if err := validateByHashDigest(algorithm, digest); err != nil {
				return nil, fmt.Errorf("%s %s: %w", file.Path, algorithm, err)
			}
			destination, err := byHashDestination(file.Path, algorithm, digest)
			if err != nil {
				return nil, err
			}
			expected := model.ByHashFile{
				CanonicalPath: file.Path,
				Path:          destination,
				Algorithm:     algorithm,
				Digest:        digest,
				Size:          file.Size,
				Checksums:     cloneChecksums(file.Checksums),
			}
			if existing, ok := byPath[destination]; ok {
				if existing.Size != expected.Size || existing.Algorithm != expected.Algorithm ||
					!strings.EqualFold(existing.Digest, expected.Digest) || !sameChecksums(existing.Checksums, expected.Checksums) {
					return nil, fmt.Errorf("conflicting by-hash destination %s", destination)
				}
				continue
			}
			byPath[destination] = expected
		}
		if !found {
			return nil, fmt.Errorf("%s has no supported checksum for by-hash", file.Path)
		}
	}
	out := make([]model.ByHashFile, 0, len(byPath))
	for _, file := range byPath {
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CanonicalPath != out[j].CanonicalPath {
			return out[i].CanonicalPath < out[j].CanonicalPath
		}
		return checksumRank(out[i].Algorithm) < checksumRank(out[j].Algorithm)
	})
	return out, nil
}

func checksumRank(algorithm string) int {
	for i, candidate := range []string{"SHA512", "SHA256", "SHA1", "MD5Sum"} {
		if algorithm == candidate {
			return i
		}
	}
	return 4
}

func validateByHashDigest(algorithm, digest string) error {
	want := map[string]int{"MD5Sum": 32, "SHA1": 40, "SHA256": 64, "SHA512": 128}[algorithm]
	if want == 0 {
		return fmt.Errorf("unsupported checksum algorithm %q", algorithm)
	}
	if len(digest) != want {
		return fmt.Errorf("digest length is %d, want %d", len(digest), want)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("digest is not hexadecimal")
	}
	return nil
}

func byHashDestination(canonical, algorithm, digest string) (string, error) {
	canonical, err := safe.Rel(canonical)
	if err != nil {
		return "", err
	}
	destination, err := safe.Rel(path.Join(path.Dir(canonical), "by-hash", algorithm, digest))
	if err != nil {
		return "", err
	}
	return destination, nil
}

func (r *Runner) materializeByHash(files []model.ByHashFile) error {
	for _, file := range files {
		if err := publish.MaterializeByHash(r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), file); err != nil {
			return fmt.Errorf("materialize by-hash %s: %w", file.Path, err)
		}
	}
	return nil
}

func (r *Runner) preserveByHash(files []model.ByHashFile) {
	for _, file := range files {
		_ = publish.MaterializeByHash(r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), file)
	}
}

func (r *Runner) readPublishedReleaseStateOptional() (model.RepositoryState, bool, error) {
	found := false
	for _, suite := range r.Repo.Suites {
		for _, name := range []string{"InRelease", "Release"} {
			_, err := os.Lstat(filepathFor(r.Repo.AbsPublishPath, path.Join("dists", suite.Name, name)))
			if err == nil {
				found = true
				break
			}
			if !os.IsNotExist(err) {
				return model.RepositoryState{}, false, err
			}
		}
		if found {
			break
		}
	}
	if !found {
		return model.RepositoryState{}, false, nil
	}
	state, err := r.readPublishedReleaseState()
	return state, err == nil, err
}

func (r *Runner) byHashHistoryPath() string {
	if r.Config == nil || r.Config.Storage.Staging == "" || r.Repo.Name == "" {
		return ""
	}
	return filepath.Join(repoStaging(r.Config, "apt", r.Repo.Name), byHashHistoryFile)
}

func (r *Runner) loadByHashHistory() (byHashHistory, byHashHistoryStatus, error) {
	manifest := r.byHashHistoryPath()
	if manifest == "" {
		return emptyByHashHistory(), byHashHistoryMissing, nil
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyByHashHistory(), byHashHistoryMissing, nil
		}
		return byHashHistory{}, byHashHistoryMissing, err
	}
	var history byHashHistory
	if err := json.Unmarshal(data, &history); err != nil {
		return emptyByHashHistory(), byHashHistoryCorrupt, nil
	}
	if err := validateByHashHistory(history); err != nil {
		return emptyByHashHistory(), byHashHistoryCorrupt, nil
	}
	return history, byHashHistoryValid, nil
}

func emptyByHashHistory() byHashHistory {
	return byHashHistory{Version: byHashHistoryVersion, Records: []byHashHistoryRecord{}}
}

func validateByHashHistory(history byHashHistory) error {
	if history.Version != byHashHistoryVersion {
		return fmt.Errorf("unsupported by-hash history version %d", history.Version)
	}
	seenRecords := map[string]bool{}
	for _, record := range history.Records {
		canonical, err := safe.Rel(record.CanonicalPath)
		if err != nil || canonical != record.CanonicalPath || !strings.HasPrefix(canonical, "dists/") {
			return fmt.Errorf("invalid canonical path %q", record.CanonicalPath)
		}
		if checksumRank(record.Algorithm) == 4 {
			return fmt.Errorf("invalid algorithm %q", record.Algorithm)
		}
		key := historyRecordKey(record.CanonicalPath, record.Algorithm)
		if seenRecords[key] {
			return fmt.Errorf("duplicate history record %s", key)
		}
		seenRecords[key] = true
		if len(record.Generations) > 3 {
			return fmt.Errorf("too many generations for %s", key)
		}
		seenDigests := map[string]bool{}
		for _, generation := range record.Generations {
			if generation.Size < 0 {
				return fmt.Errorf("negative size for %s", key)
			}
			if err := validateByHashDigest(record.Algorithm, generation.Digest); err != nil {
				return err
			}
			expectedPath, err := byHashDestination(record.CanonicalPath, record.Algorithm, generation.Digest)
			if err != nil || expectedPath != generation.Path {
				return fmt.Errorf("invalid history destination %q", generation.Path)
			}
			digestKey := strings.ToLower(generation.Digest)
			if seenDigests[digestKey] {
				return fmt.Errorf("duplicate history digest %s", generation.Digest)
			}
			seenDigests[digestKey] = true
		}
	}
	return nil
}

func updateByHashHistory(history byHashHistory, state model.RepositoryState) byHashHistory {
	records := map[string]byHashHistoryRecord{}
	for _, record := range history.Records {
		if enabled, known := state.ByHashEnabled[suiteFromCanonical(record.CanonicalPath)]; known && !enabled {
			continue
		}
		record.Generations = append([]byHashHistoryGeneration(nil), record.Generations...)
		records[historyRecordKey(record.CanonicalPath, record.Algorithm)] = record
	}
	for _, current := range state.ByHashFiles {
		key := historyRecordKey(current.CanonicalPath, current.Algorithm)
		record := records[key]
		if record.CanonicalPath == "" {
			record.CanonicalPath = current.CanonicalPath
			record.Algorithm = current.Algorithm
		}
		generation := byHashHistoryGeneration{Path: current.Path, Digest: current.Digest, Size: current.Size}
		generations := []byHashHistoryGeneration{generation}
		for _, previous := range record.Generations {
			if strings.EqualFold(previous.Digest, current.Digest) {
				continue
			}
			generations = append(generations, previous)
			if len(generations) == 3 {
				break
			}
		}
		record.Generations = generations
		records[key] = record
	}
	out := emptyByHashHistory()
	for _, record := range records {
		out.Records = append(out.Records, record)
	}
	sort.Slice(out.Records, func(i, j int) bool {
		if out.Records[i].CanonicalPath != out.Records[j].CanonicalPath {
			return out.Records[i].CanonicalPath < out.Records[j].CanonicalPath
		}
		return checksumRank(out.Records[i].Algorithm) < checksumRank(out.Records[j].Algorithm)
	})
	return out
}

func historyRecordKey(canonical, algorithm string) string {
	return canonical + "\x00" + algorithm
}

func suiteFromCanonical(canonical string) string {
	parts := strings.Split(canonical, "/")
	if len(parts) >= 2 && parts[0] == "dists" {
		return parts[1]
	}
	return ""
}

func (r *Runner) writeByHashHistory(history byHashHistory) error {
	manifest := r.byHashHistoryPath()
	if manifest == "" {
		return nil
	}
	if err := validateByHashHistory(history); err != nil {
		return err
	}
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	root := filepath.Dir(manifest)
	return publish.AtomicWrite(root, root, byHashHistoryFile, data)
}

func (r *Runner) verifyHistoricByHash() {
	history, status, err := r.loadByHashHistory()
	if err != nil || status != byHashHistoryValid {
		return
	}
	for _, record := range history.Records {
		for _, generation := range record.Generations {
			full, err := safe.Join(r.Repo.AbsPublishPath, generation.Path)
			if err != nil {
				continue
			}
			_, _ = publish.VerifyByHash(full, generation.Size, record.Algorithm, generation.Digest)
		}
	}
}

func keepExistingByHash(root string, keep map[string]bool) error {
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return filepath.WalkDir(root, func(file string, entry os.DirEntry, err error) error {
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
		if strings.HasPrefix(rel, "by-hash/") || strings.Contains(rel, "/by-hash/") {
			keep[rel] = true
		}
		return nil
	})
}
