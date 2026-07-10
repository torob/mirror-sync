package apt

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ulikunitz/xz"

	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/download"
	"github.com/torob/mirror-sync/internal/httpx"
	"github.com/torob/mirror-sync/internal/model"
	"github.com/torob/mirror-sync/internal/publish"
	"github.com/torob/mirror-sync/internal/safe"
)

type Runner struct {
	Config  *config.Config
	Repo    config.APTRepository
	HTTP    *httpx.Factory
	Staging string
}

type releaseFile struct {
	Size      int64
	SizeSet   bool
	Checksums model.Checksums
}

func (r *Runner) Plan(ctx context.Context) (model.RepositoryPlan, error) {
	lock, err := publish.AcquireLock(r.Config.Storage.Staging, "apt", r.Repo.Name)
	if err != nil {
		return model.RepositoryPlan{}, err
	}
	defer lock.Close()
	state, err := r.fetchState(ctx)
	if err != nil {
		return model.RepositoryPlan{}, err
	}
	if err := r.prepareResolvedReleaseState(state); err != nil {
		return model.RepositoryPlan{}, fmt.Errorf("apt %s write resolved Release state: %w", r.Repo.Name, err)
	}
	var bytes int64
	for _, pkg := range state.Packages {
		bytes += pkg.Size
	}
	return model.RepositoryPlan{
		Name: r.Repo.Name, Kind: "apt", PublishPath: r.Repo.AbsPublishPath,
		MetadataFiles: len(state.Metadata) + len(state.Files) + len(state.ByHashFiles), Packages: len(state.Packages), Bytes: bytes,
		Sources: r.sourceDescriptions(),
	}, nil
}

func (r *Runner) Sync(ctx context.Context) (model.OperationStats, error) {
	var stats model.OperationStats
	lock, err := publish.AcquireLock(r.Config.Storage.Staging, "apt", r.Repo.Name)
	if err != nil {
		return stats, err
	}
	defer lock.Close()
	oldState, oldPublished, err := r.readPublishedReleaseStateOptional()
	oldStateUnsafe := err != nil
	if oldStateUnsafe {
		oldPublished = false
	}
	history, historyStatus, err := r.loadByHashHistory()
	if err != nil {
		return stats, fmt.Errorf("apt %s read by-hash history: %w", r.Repo.Name, err)
	}
	if oldPublished {
		history = updateByHashHistory(history, oldState)
	}
	state, err := r.fetchState(ctx)
	if err != nil {
		return stats, err
	}
	if oldPublished {
		r.preserveByHash(oldState.ByHashFiles)
	}
	clients, err := r.payloadClients()
	if err != nil {
		return stats, err
	}
	packageStats, err := download.EnsureSyncedPayloads(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), clients, state.Packages)
	stats.Add(packageStats)
	if err != nil {
		return stats, fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	fileStats, err := download.EnsureRepaired(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), clients, aptFileExpected(state.Files))
	stats.Add(fileStats)
	if err != nil {
		return stats, fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	if err := r.materializeByHash(state.ByHashFiles); err != nil {
		return stats, fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	if err := r.prepareResolvedReleaseState(state); err != nil {
		return stats, fmt.Errorf("apt %s write resolved Release state: %w", r.Repo.Name, err)
	}
	if err := publish.PublishMetadata(r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), state.Metadata); err != nil {
		return stats, fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	if err := r.commitResolvedReleaseState(state); err != nil {
		return stats, fmt.Errorf("apt %s commit resolved Release state: %w", r.Repo.Name, err)
	}
	history = updateByHashHistory(history, state)
	if err := r.writeByHashHistory(history); err != nil {
		return stats, fmt.Errorf("apt %s write by-hash history: %w", r.Repo.Name, err)
	}
	if r.Config.Sync.Prune {
		removed, err := r.pruneStateWithHistory(state, history, historyStatus == byHashHistoryCorrupt || oldStateUnsafe)
		stats.FilesPruned += len(removed)
		return stats, err
	}
	return stats, nil
}

func (r *Runner) Verify(ctx context.Context) (model.OperationStats, error) {
	var stats model.OperationStats
	lock, err := publish.AcquireLock(r.Config.Storage.Staging, "apt", r.Repo.Name)
	if err != nil {
		return stats, err
	}
	defer lock.Close()
	releaseState, err := r.readPublishedReleaseState()
	if err != nil {
		return stats, err
	}
	clients, err := r.payloadClients()
	if err != nil {
		return stats, err
	}
	fileStats, err := download.EnsureRepaired(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), clients, aptFileExpected(releaseState.Files))
	stats.Add(fileStats)
	if err != nil {
		return stats, fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	if err := r.materializeByHash(releaseState.ByHashFiles); err != nil {
		return stats, fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	r.verifyHistoricByHash()
	state, err := r.readPublishedState()
	if err != nil {
		return stats, err
	}
	packageStats, err := download.EnsureRepairedPayloads(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), clients, state.Packages)
	stats.Add(packageStats)
	if err != nil {
		return stats, fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	return stats, nil
}

func (r *Runner) Prune(ctx context.Context) ([]string, error) {
	lock, err := publish.AcquireLock(r.Config.Storage.Staging, "apt", r.Repo.Name)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	state, err := r.readPublishedState()
	if err != nil {
		return nil, err
	}
	_ = ctx
	return r.pruneState(state)
}

func (r *Runner) pruneState(state model.RepositoryState) ([]string, error) {
	history, status, err := r.loadByHashHistory()
	if err != nil {
		return nil, err
	}
	if status == byHashHistoryMissing {
		history = updateByHashHistory(history, state)
		if err := r.writeByHashHistory(history); err != nil {
			return nil, err
		}
	}
	return r.pruneStateWithHistory(state, history, status == byHashHistoryCorrupt)
}

func (r *Runner) pruneStateWithHistory(state model.RepositoryState, history byHashHistory, protectUnknown bool) ([]string, error) {
	keep := map[string]bool{}
	for _, mf := range state.Metadata {
		keep[mf.Path] = true
	}
	for _, f := range state.Files {
		keep[f.Path] = true
	}
	for _, f := range state.ByHashFiles {
		keep[f.Path] = true
	}
	for _, record := range history.Records {
		for _, generation := range record.Generations {
			keep[generation.Path] = true
		}
	}
	for rel := range state.Packages {
		keep[rel] = true
	}
	if protectUnknown {
		if err := keepExistingByHash(r.Repo.AbsPublishPath, keep); err != nil {
			return nil, err
		}
	}
	return publish.Prune(r.Repo.AbsPublishPath, keep)
}

func (r *Runner) fetchState(ctx context.Context) (model.RepositoryState, error) {
	keyring, err := loadKeyring(r.Repo.AbsKeyring)
	if err != nil {
		return model.RepositoryState{}, err
	}
	primary, err := r.Config.Source(r.Repo.Name, config.RepoAPT, config.SourcePrimary, 0, r.Repo.PrimarySource)
	if err != nil {
		return model.RepositoryState{}, err
	}
	client, err := r.HTTP.Client(primary)
	if err != nil {
		return model.RepositoryState{}, err
	}
	clients, err := r.distsClients()
	if err != nil {
		return model.RepositoryState{}, err
	}
	resolvedState, _, err := r.loadResolvedReleaseState()
	if err != nil {
		return model.RepositoryState{}, err
	}
	out := model.RepositoryState{ByHashEnabled: map[string]bool{}, ReleaseFingerprints: map[string]string{}, Packages: map[string]model.Payload{}}
	for _, suite := range r.Repo.Suites {
		releaseText, releaseHashes, metadata, err := r.fetchRelease(ctx, client, keyring, suite.Name)
		if err != nil {
			return out, err
		}
		byHashEnabled, err := parseAcquireByHash(releaseText)
		if err != nil {
			return out, err
		}
		out.ByHashEnabled[suite.Name] = byHashEnabled
		fingerprint := releaseFingerprint(releaseText)
		out.ReleaseFingerprints[suite.Name] = fingerprint
		out.Metadata = append(out.Metadata, metadata...)
		advertised, err := selectReleaseFiles(suite, r.Repo.Architectures, releaseHashes)
		if err != nil {
			return out, err
		}
		out.SelectedFiles = append(out.SelectedFiles, advertised...)
		selectedBefore, resolvedBefore, complete, found := resolvedState.resolution(suite.Name, fingerprint)
		toResolve := releaseFilesToResolve(advertised, selectedBefore, resolvedBefore, complete && found)
		resolved, err := download.ResolveExact(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), resolvedBefore, clients, aptFileExpected(toResolve))
		if err != nil {
			return out, fmt.Errorf("apt %s resolve suite %s: %w", r.Repo.Name, suite.Name, err)
		}
		files := repositoryFilesFromExpected(resolved)
		out.Files = append(out.Files, files...)
		if byHashEnabled {
			byHashFiles, err := deriveByHashFiles(files)
			if err != nil {
				return out, err
			}
			out.ByHashFiles = append(out.ByHashFiles, byHashFiles...)
		}
		for _, component := range suite.Components {
			for _, arch := range packageIndexArchitectures(r.Repo.Architectures) {
				indexRel, indexFile, found, err := r.openResolvedPackagesIndex(suite.Name, component, arch, releaseHashes, files)
				if err != nil {
					return out, err
				}
				if !found {
					continue
				}
				err = consumeIndex(indexRel, indexFile, func(reader io.Reader) error {
					return parsePackages(reader, allowedPackageArchitectures(r.Repo.Architectures), func(pkg model.Package) error {
						return addPayload(out.Packages, pkg, indexRel)
					})
				})
				if err != nil {
					return out, fmt.Errorf("apt %s parse %s: %w", r.Repo.Name, indexRel, err)
				}
			}
			for _, arch := range selectedArchitectureNames(r.Repo.Architectures) {
				indexRel, indexFile, found, err := r.openResolvedInstallerIndex(suite.Name, component, arch, releaseHashes, files)
				if err != nil {
					return out, err
				}
				if !found {
					continue
				}
				err = consumeIndex(indexRel, indexFile, func(reader io.Reader) error {
					return parsePackages(reader, allowedPackageArchitectures(r.Repo.Architectures), func(pkg model.Package) error {
						return addPayload(out.Packages, pkg, indexRel)
					})
				})
				if err != nil {
					return out, fmt.Errorf("apt %s parse %s: %w", r.Repo.Name, indexRel, err)
				}
			}
			indexRel, indexFile, found, err := r.openResolvedSourcesIndex(suite.Name, component, releaseHashes, files)
			if err != nil {
				return out, err
			}
			if found {
				err := consumeIndex(indexRel, indexFile, func(reader io.Reader) error {
					return parseSources(reader, func(pkg model.Package) error {
						return addPayload(out.Packages, pkg, indexRel)
					})
				})
				if err != nil {
					return out, fmt.Errorf("apt %s parse %s: %w", r.Repo.Name, indexRel, err)
				}
			}
		}
	}
	return out, nil
}

func releaseFilesToResolve(advertised []model.RepositoryFile, selectedBefore, resolvedBefore map[string]bool, selectionComplete bool) []model.RepositoryFile {
	if !selectionComplete {
		return advertised
	}
	out := make([]model.RepositoryFile, 0, len(advertised))
	for _, file := range advertised {
		if resolvedBefore[file.Path] || !selectedBefore[file.Path] {
			out = append(out, file)
		}
	}
	return out
}

func (r *Runner) fetchRelease(ctx context.Context, client *httpx.Client, keyring openpgp.EntityList, suite string) (string, map[string]releaseFile, []model.MetadataFile, error) {
	inReleaseRel := path.Join("dists", suite, "InRelease")
	releaseRel := path.Join("dists", suite, "Release")
	sigRel := path.Join("dists", suite, "Release.gpg")

	inRelease, inPresent, err := fetchOptional(ctx, client, inReleaseRel, 64<<20)
	if err != nil {
		return "", nil, nil, fmt.Errorf("apt %s fetch %s: %w", r.Repo.Name, inReleaseRel, err)
	}
	releaseData, releasePresent, err := fetchOptional(ctx, client, releaseRel, 64<<20)
	if err != nil {
		return "", nil, nil, fmt.Errorf("apt %s fetch %s: %w", r.Repo.Name, releaseRel, err)
	}
	sig, sigPresent, err := fetchOptional(ctx, client, sigRel, 16<<20)
	if err != nil {
		return "", nil, nil, fmt.Errorf("apt %s fetch %s: %w", r.Repo.Name, sigRel, err)
	}
	return r.selectReleaseForms(keyring, suite, inRelease, inPresent, releaseData, releasePresent, sig, sigPresent)
}

func fetchOptional(ctx context.Context, client *httpx.Client, rel string, maxBytes int64) ([]byte, bool, error) {
	data, err := client.GetBytes(ctx, rel, maxBytes)
	if err == nil {
		return data, true, nil
	}
	if httpx.IsStatus(err, http.StatusNotFound) {
		return nil, false, nil
	}
	return nil, false, err
}

type verifiedRelease struct {
	text      string
	cleartext []byte
	hashes    map[string]releaseFile
	metadata  []model.MetadataFile
}

func (r *Runner) selectReleaseForms(keyring openpgp.EntityList, suite string, inRelease []byte, inPresent bool, releaseData []byte, releasePresent bool, sig []byte, sigPresent bool) (string, map[string]releaseFile, []model.MetadataFile, error) {
	inReleaseRel := path.Join("dists", suite, "InRelease")
	releaseRel := path.Join("dists", suite, "Release")
	sigRel := path.Join("dists", suite, "Release.gpg")

	var inForm, detachedForm *verifiedRelease
	var inErr, detachedErr error
	if inPresent {
		plain, err := verifyInRelease(inRelease, keyring)
		if err == nil {
			inForm, err = verifiedReleaseMetadata(plain, []model.MetadataFile{{Path: inReleaseRel, Data: inRelease, SignedLast: true}})
		}
		if err != nil {
			inErr = fmt.Errorf("verify %s: %w", inReleaseRel, err)
		}
	} else {
		inErr = fmt.Errorf("%s not found", inReleaseRel)
	}

	if releasePresent && sigPresent {
		err := verifyDetachedSignature(releaseData, sig, keyring)
		if err == nil {
			detachedForm, err = verifiedReleaseMetadata(releaseData, []model.MetadataFile{
				{Path: releaseRel, Data: releaseData},
				{Path: sigRel, Data: sig, SignedLast: true},
			})
		}
		if err != nil {
			detachedErr = fmt.Errorf("verify %s: %w", sigRel, err)
		}
	} else {
		detachedErr = fmt.Errorf("detached release pair incomplete (%s present: %t, %s present: %t)", releaseRel, releasePresent, sigRel, sigPresent)
	}

	if inForm != nil {
		metadata := append([]model.MetadataFile(nil), inForm.metadata...)
		if detachedForm != nil && releaseMatchesVerifiedCleartext(releaseData, inForm.cleartext) {
			metadata = append(metadata, detachedForm.metadata...)
		}
		return inForm.text, inForm.hashes, metadata, nil
	}
	if detachedForm != nil {
		return detachedForm.text, detachedForm.hashes, detachedForm.metadata, nil
	}
	return "", nil, nil, fmt.Errorf("apt %s has no valid signed Release metadata: %v; %v", r.Repo.Name, inErr, detachedErr)
}

func verifyDetachedSignature(message, signature []byte, keyring openpgp.EntityList) error {
	signatureReader := io.Reader(bytes.NewReader(signature))
	trimmed := bytes.TrimLeft(signature, " \t\r\n")
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		const begin = "-----BEGIN PGP SIGNATURE-----"
		const end = "-----END PGP SIGNATURE-----"
		if !bytes.HasPrefix(trimmed, []byte(begin+"\n")) && !bytes.HasPrefix(trimmed, []byte(begin+"\r\n")) {
			return fmt.Errorf("invalid detached signature armor header")
		}
		normalized := bytes.ReplaceAll(bytes.TrimSpace(trimmed), []byte("\r\n"), []byte("\n"))
		if bytes.ContainsRune(normalized, '\r') {
			return fmt.Errorf("invalid detached signature armor line ending")
		}
		lines := bytes.Split(normalized, []byte("\n"))
		if len(lines) < 4 || !bytes.Equal(lines[len(lines)-1], []byte(end)) {
			return fmt.Errorf("invalid detached signature armor footer")
		}
		checksumSeen := false
		for _, line := range lines[1 : len(lines)-1] {
			line = bytes.TrimSpace(line)
			if bytes.HasPrefix(line, []byte("-----END ")) || (checksumSeen && len(line) != 0) {
				return fmt.Errorf("invalid detached signature armor body")
			}
			if len(line) == 5 && line[0] == '=' {
				checksumSeen = true
			}
		}
		block, err := armor.Decode(bytes.NewReader(trimmed))
		if err != nil {
			return fmt.Errorf("decode detached signature armor: %w", err)
		}
		if block.Type != openpgp.SignatureType {
			return fmt.Errorf("invalid detached signature armor type %q", block.Type)
		}
		decoded, err := io.ReadAll(block.Body)
		if err != nil {
			return fmt.Errorf("decode detached signature armor body: %w", err)
		}
		if len(decoded) == 0 {
			return fmt.Errorf("empty detached signature armor body")
		}
		signatureReader = bytes.NewReader(decoded)
	}
	_, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(message), signatureReader, nil)
	return err
}

func verifiedReleaseMetadata(cleartext []byte, metadata []model.MetadataFile) (*verifiedRelease, error) {
	text := string(cleartext)
	hashes, err := parseReleaseHashes(text)
	if err != nil {
		return nil, err
	}
	if _, err := parseAcquireByHash(text); err != nil {
		return nil, err
	}
	return &verifiedRelease{text: text, cleartext: cleartext, hashes: hashes, metadata: metadata}, nil
}

func repositoryFilesFromExpected(expected []download.Expected) []model.RepositoryFile {
	files := make([]model.RepositoryFile, 0, len(expected))
	for _, exp := range expected {
		checksums := exp.Checksums
		if checksums.Empty() && exp.SHA256 != "" {
			checksums.SHA256 = exp.SHA256
		}
		files = append(files, model.RepositoryFile{
			Path: exp.RelPath, Size: exp.Size, Checksums: checksums,
		})
	}
	return files
}

func (r *Runner) openResolvedPackagesIndex(suite, component, arch string, hashes map[string]releaseFile, files []model.RepositoryFile) (string, *os.File, bool, error) {
	return r.openResolvedNamedIndex(suite, path.Join(component, "binary-"+arch), "Packages", hashes, files)
}

func (r *Runner) openResolvedInstallerIndex(suite, component, arch string, hashes map[string]releaseFile, files []model.RepositoryFile) (string, *os.File, bool, error) {
	return r.openResolvedNamedIndex(suite, path.Join(component, "debian-installer", "binary-"+arch), "Packages", hashes, files)
}

func (r *Runner) openResolvedSourcesIndex(suite, component string, hashes map[string]releaseFile, files []model.RepositoryFile) (string, *os.File, bool, error) {
	return r.openResolvedNamedIndex(suite, path.Join(component, "source"), "Sources", hashes, files)
}

func (r *Runner) openResolvedNamedIndex(suite, dir, name string, hashes map[string]releaseFile, files []model.RepositoryFile) (string, *os.File, bool, error) {
	resolved := map[string]bool{}
	for _, file := range files {
		resolved[file.Path] = true
	}
	for _, rel := range indexCandidates(dir, name) {
		fullRel := path.Join("dists", suite, rel)
		if _, advertised := hashes[rel]; !advertised || !resolved[fullRel] {
			continue
		}
		staged := filepathFor(path.Join(repoStaging(r.Config, "apt", r.Repo.Name), "payloads"), fullRel)
		file, err := os.Open(staged)
		if err == nil {
			return rel, file, true, nil
		}
		if !os.IsNotExist(err) {
			return "", nil, false, err
		}
		file, err = os.Open(filepathFor(r.Repo.AbsPublishPath, fullRel))
		if err != nil {
			return "", nil, false, err
		}
		return rel, file, true, nil
	}
	return "", nil, false, nil
}

func (r *Runner) readPublishedState() (model.RepositoryState, error) {
	out, err := r.readPublishedReleaseState()
	if err != nil {
		return out, err
	}
	hashesBySuite := map[string]map[string]releaseFile{}
	for _, suite := range r.Repo.Suites {
		hashes, err := r.readPublishedReleaseHashes(suite.Name)
		if err != nil {
			return out, err
		}
		resolved := map[string]bool{}
		for _, file := range out.Files {
			resolved[file.Path] = true
		}
		for rel := range hashes {
			if !resolved[path.Join("dists", suite.Name, rel)] {
				delete(hashes, rel)
			}
		}
		hashesBySuite[suite.Name] = hashes
	}
	for _, suite := range r.Repo.Suites {
		hashes := hashesBySuite[suite.Name]
		for _, component := range suite.Components {
			for _, arch := range packageIndexArchitectures(r.Repo.Architectures) {
				indexRel, indexFile, found, err := r.openPublishedIndex(suite.Name, component, arch, hashes)
				if err != nil {
					return out, err
				}
				if !found {
					if !releaseAdvertisesIndex(path.Join(component, "binary-"+arch), "Packages", hashes) {
						continue
					}
					return out, fmt.Errorf("no valid published Packages index for %s/%s/%s", suite.Name, component, arch)
				}
				err = consumeIndex(indexRel, indexFile, func(reader io.Reader) error {
					return parsePackages(reader, allowedPackageArchitectures(r.Repo.Architectures), func(pkg model.Package) error {
						return addPayload(out.Packages, pkg, indexRel)
					})
				})
				if err != nil {
					return out, err
				}
			}
			for _, arch := range selectedArchitectureNames(r.Repo.Architectures) {
				indexRel, indexFile, found, err := r.openPublishedInstallerIndex(suite.Name, component, arch, hashes)
				if err != nil {
					return out, err
				}
				if !found {
					if releaseAdvertisesIndex(path.Join(component, "debian-installer", "binary-"+arch), "Packages", hashes) {
						return out, fmt.Errorf("no valid published Debian Installer Packages index for %s/%s/%s", suite.Name, component, arch)
					}
					continue
				}
				err = consumeIndex(indexRel, indexFile, func(reader io.Reader) error {
					return parsePackages(reader, allowedPackageArchitectures(r.Repo.Architectures), func(pkg model.Package) error {
						return addPayload(out.Packages, pkg, indexRel)
					})
				})
				if err != nil {
					return out, err
				}
			}
			indexRel, indexFile, found, err := r.openPublishedSourcesIndex(suite.Name, component, hashes)
			if err != nil {
				return out, err
			}
			if found {
				err := consumeIndex(indexRel, indexFile, func(reader io.Reader) error {
					return parseSources(reader, func(pkg model.Package) error {
						return addPayload(out.Packages, pkg, indexRel)
					})
				})
				if err != nil {
					return out, err
				}
			} else if releaseAdvertisesIndex(path.Join(component, "source"), "Sources", hashes) {
				return out, fmt.Errorf("no valid published Sources index for %s/%s", suite.Name, component)
			}
		}
	}
	return out, nil
}

func (r *Runner) readPublishedReleaseState() (model.RepositoryState, error) {
	keyring, err := loadKeyring(r.Repo.AbsKeyring)
	if err != nil {
		return model.RepositoryState{}, err
	}
	out := model.RepositoryState{ByHashEnabled: map[string]bool{}, ReleaseFingerprints: map[string]string{}, Packages: map[string]model.Payload{}}
	resolvedState, resolvedStatus, err := r.loadResolvedReleaseState()
	if err != nil {
		return out, err
	}
	for _, suite := range r.Repo.Suites {
		releaseText, hashes, metadata, err := r.readPublishedSuiteRelease(keyring, suite.Name)
		if err != nil {
			return out, err
		}
		out.Metadata = append(out.Metadata, metadata...)
		byHashEnabled, err := parseAcquireByHash(releaseText)
		if err != nil {
			return out, err
		}
		out.ByHashEnabled[suite.Name] = byHashEnabled
		fingerprint := releaseFingerprint(releaseText)
		out.ReleaseFingerprints[suite.Name] = fingerprint
		files, err := selectReleaseFiles(suite, r.Repo.Architectures, hashes)
		if err != nil {
			return out, err
		}
		out.SelectedFiles = append(out.SelectedFiles, files...)
		if resolvedStatus == resolvedReleaseStateValid {
			paths, ok := resolvedState.paths(suite.Name, fingerprint)
			if !ok {
				return out, fmt.Errorf("apt %s has no resolved-path state for suite %s Release %s", r.Repo.Name, suite.Name, fingerprint)
			}
			files = filterRepositoryFiles(files, paths)
		}
		out.Files = append(out.Files, files...)
		if byHashEnabled {
			byHashFiles, err := deriveByHashFiles(files)
			if err != nil {
				return out, err
			}
			out.ByHashFiles = append(out.ByHashFiles, byHashFiles...)
		}
	}
	return out, nil
}

func (r *Runner) readPublishedReleaseHashes(suite string) (map[string]releaseFile, error) {
	keyring, err := loadKeyring(r.Repo.AbsKeyring)
	if err != nil {
		return nil, err
	}
	_, hashes, _, err := r.readPublishedSuiteRelease(keyring, suite)
	return hashes, err
}

func (r *Runner) readPublishedSuiteRelease(keyring openpgp.EntityList, suite string) (string, map[string]releaseFile, []model.MetadataFile, error) {
	inReleaseRel := path.Join("dists", suite, "InRelease")
	releaseRel := path.Join("dists", suite, "Release")
	sigRel := path.Join("dists", suite, "Release.gpg")
	inRelease, inPresent, err := readOptionalPublished(r.Repo.AbsPublishPath, inReleaseRel)
	if err != nil {
		return "", nil, nil, err
	}
	releaseData, releasePresent, err := readOptionalPublished(r.Repo.AbsPublishPath, releaseRel)
	if err != nil {
		return "", nil, nil, err
	}
	sig, sigPresent, err := readOptionalPublished(r.Repo.AbsPublishPath, sigRel)
	if err != nil {
		return "", nil, nil, err
	}
	return r.selectReleaseForms(keyring, suite, inRelease, inPresent, releaseData, releasePresent, sig, sigPresent)
}

func readOptionalPublished(root, rel string) ([]byte, bool, error) {
	data, err := os.ReadFile(filepathFor(root, rel))
	if err == nil {
		return data, true, nil
	}
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, err
}

func (r *Runner) openPublishedIndex(suite, component, arch string, hashes map[string]releaseFile) (string, *os.File, bool, error) {
	return r.openPublishedNamedIndex(suite, path.Join(component, "binary-"+arch), "Packages", hashes)
}

func (r *Runner) openPublishedInstallerIndex(suite, component, arch string, hashes map[string]releaseFile) (string, *os.File, bool, error) {
	return r.openPublishedNamedIndex(suite, path.Join(component, "debian-installer", "binary-"+arch), "Packages", hashes)
}

func (r *Runner) openPublishedSourcesIndex(suite, component string, hashes map[string]releaseFile) (string, *os.File, bool, error) {
	return r.openPublishedNamedIndex(suite, path.Join(component, "source"), "Sources", hashes)
}

func (r *Runner) openPublishedNamedIndex(suite, dir, name string, hashes map[string]releaseFile) (string, *os.File, bool, error) {
	for _, rel := range indexCandidates(dir, name) {
		want, ok := hashes[rel]
		if !ok {
			continue
		}
		filePath := filepathFor(r.Repo.AbsPublishPath, path.Join("dists", suite, rel))
		ok, err := verifyFile(filePath, want)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", nil, false, err
		}
		if !ok {
			continue
		}
		file, err := os.Open(filePath)
		if err != nil {
			return "", nil, false, err
		}
		return rel, file, true, nil
	}
	return "", nil, false, nil
}

func releaseAdvertisesIndex(dir, name string, hashes map[string]releaseFile) bool {
	for _, rel := range indexCandidates(dir, name) {
		if _, ok := hashes[rel]; ok {
			return true
		}
	}
	return false
}

func indexCandidates(dir, name string) []string {
	return []string{
		path.Join(dir, name+".xz"),
		path.Join(dir, name+".gz"),
		path.Join(dir, name+".bz2"),
		path.Join(dir, name),
	}
}

func loadKeyring(path string) (openpgp.EntityList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, err := armor.Decode(bytes.NewReader(data)); err == nil && block.Type == openpgp.PublicKeyType {
		return openpgp.ReadKeyRing(block.Body)
	}
	return openpgp.ReadKeyRing(bytes.NewReader(data))
}

func verifyInRelease(data []byte, keyring openpgp.EntityList) ([]byte, error) {
	if err := validateClearsignedStructure(data); err != nil {
		return nil, err
	}
	block, _ := clearsign.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("not a clearsigned document")
	}
	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
		return nil, err
	}
	return block.Bytes, nil
}

func releaseMatchesVerifiedCleartext(releaseData, verifiedCleartext []byte) bool {
	if bytes.Equal(releaseData, verifiedCleartext) {
		return true
	}
	canonical := canonicalReleaseCleartext(releaseData)
	if bytes.Equal(canonical, verifiedCleartext) {
		return true
	}
	return bytes.Equal(trimTrailingCRLF(canonical), trimTrailingCRLF(verifiedCleartext))
}

func canonicalReleaseCleartext(data []byte) []byte {
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	normalized = bytes.ReplaceAll(normalized, []byte("\r"), []byte("\n"))
	return bytes.ReplaceAll(normalized, []byte("\n"), []byte("\r\n"))
}

func trimTrailingCRLF(data []byte) []byte {
	return bytes.TrimRight(data, "\r\n")
}

func validateClearsignedStructure(data []byte) error {
	const (
		signedBegin = "-----BEGIN PGP SIGNED MESSAGE-----"
		sigBegin    = "-----BEGIN PGP SIGNATURE-----"
		sigEnd      = "-----END PGP SIGNATURE-----"
	)
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if len(lines) == 0 || strings.TrimSuffix(lines[0], "\r") != signedBegin {
		return fmt.Errorf("clearsigned document does not start with signed message block")
	}
	i := 1
	for ; i < len(lines); i++ {
		line := strings.TrimSuffix(lines[i], "\r")
		if line == "" {
			i++
			break
		}
		if strings.HasPrefix(line, "-----BEGIN PGP ") {
			return fmt.Errorf("clearsigned document has malformed signed message headers")
		}
	}
	if i >= len(lines) {
		return fmt.Errorf("clearsigned document missing signed message body")
	}
	foundSignature := false
	for ; i < len(lines); i++ {
		line := strings.TrimSuffix(lines[i], "\r")
		switch line {
		case signedBegin:
			return fmt.Errorf("clearsigned document contains multiple signed message blocks")
		case sigBegin:
			foundSignature = true
			i++
			goto signature
		}
	}
	return fmt.Errorf("clearsigned document missing signature block")

signature:
	foundEnd := false
	for ; i < len(lines); i++ {
		line := strings.TrimSuffix(lines[i], "\r")
		if line == sigBegin || line == signedBegin {
			return fmt.Errorf("clearsigned document contains multiple signature blocks")
		}
		if line == sigEnd {
			foundEnd = true
			i++
			break
		}
	}
	if !foundSignature || !foundEnd {
		return fmt.Errorf("clearsigned document signature block was not closed")
	}
	for ; i < len(lines); i++ {
		if strings.TrimSpace(strings.TrimSuffix(lines[i], "\r")) != "" {
			return fmt.Errorf("clearsigned document contains unsigned trailing content")
		}
	}
	return nil
}

func parseReleaseHashes(text string) (map[string]releaseFile, error) {
	out := map[string]releaseFile{}
	var checksumType string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if name, ok := checksumHeader(line); ok {
			checksumType = name
			continue
		}
		if checksumType != "" {
			if line == "" || (len(line) > 0 && line[0] != ' ') {
				checksumType = ""
				continue
			}
			fields := strings.Fields(line)
			if len(fields) != 3 {
				return nil, fmt.Errorf("invalid %s entry in Release: %q", checksumType, line)
			}
			size, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return nil, err
			}
			if size < 0 {
				return nil, fmt.Errorf("%s has negative size in Release", fields[2])
			}
			existing := out[fields[2]]
			if existing.SizeSet && existing.Size != size {
				return nil, fmt.Errorf("%s has conflicting sizes in Release", fields[2])
			}
			if got := existing.Checksums.Get(checksumType); got != "" && !strings.EqualFold(got, fields[0]) {
				return nil, fmt.Errorf("%s has conflicting %s hashes in Release", fields[2], checksumType)
			}
			existing.Size = size
			existing.SizeSet = true
			existing.Checksums.Set(checksumType, fields[0])
			out[fields[2]] = existing
		}
	}
	return out, nil
}

func checksumHeader(line string) (string, bool) {
	name := strings.TrimSuffix(line, ":")
	switch strings.ToUpper(name) {
	case "MD5SUM":
		return "MD5Sum", true
	case "SHA1":
		return "SHA1", true
	case "SHA256":
		return "SHA256", true
	case "SHA512":
		return "SHA512", true
	default:
		return "", false
	}
}

func selectReleaseFiles(suite config.APTSuite, architectures []string, hashes map[string]releaseFile) ([]model.RepositoryFile, error) {
	components := setFromSlice(suite.Components)
	selected := selectedRealArchitectures(architectures)
	packageArchitectures := setFromSlice(packageIndexArchitectures(architectures))
	rels := make([]string, 0, len(hashes))
	for rel := range hashes {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	var out []model.RepositoryFile
	for _, rel := range rels {
		cleanRel, err := safe.Rel(rel)
		if err != nil {
			return nil, err
		}
		if !shouldMirrorReleaseFile(cleanRel, components, selected, packageArchitectures) {
			continue
		}
		publishedRel, err := safe.Rel(path.Join("dists", suite.Name, cleanRel))
		if err != nil {
			return nil, err
		}
		file := hashes[rel]
		out = append(out, model.RepositoryFile{Path: publishedRel, Size: file.Size, Checksums: file.Checksums})
	}
	return out, nil
}

func shouldMirrorReleaseFile(rel string, components, selectedArchs, packageArchs map[string]bool) bool {
	parts := strings.Split(rel, "/")
	if len(parts) == 1 {
		if arch, ok := contentsArch(parts[0]); ok {
			return packageArchs[arch]
		}
		return false
	}
	if !components[parts[0]] {
		return false
	}
	rest := strings.Join(parts[1:], "/")
	if arch, ok := binaryDirArch(rest); ok {
		return packageArchs[arch]
	}
	if arch, ok := installerBinaryArch(rest); ok {
		return selectedArchs[arch]
	}
	if arch, ok := cnfArch(rest); ok {
		return selectedArchs[arch]
	}
	if arch, ok := dep11ComponentsArch(rest); ok {
		return selectedArchs[arch]
	}
	if arch, ok := dep11CIDIndexArch(rest); ok {
		return selectedArchs[arch]
	}
	if arch, ok := contentsArch(path.Base(rest)); ok {
		return packageArchs[arch]
	}
	return true
}

func packageIndexArchitectures(architectures []string) []string {
	out := make([]string, 0, len(architectures)+1)
	seen := map[string]bool{}
	for _, arch := range architectures {
		if arch == "" || seen[arch] {
			continue
		}
		seen[arch] = true
		out = append(out, arch)
	}
	if !seen["all"] {
		out = append(out, "all")
	}
	return out
}

func selectedRealArchitectures(architectures []string) map[string]bool {
	out := map[string]bool{}
	for _, arch := range architectures {
		if arch != "" && arch != "all" {
			out[arch] = true
		}
	}
	return out
}

func selectedArchitectureNames(architectures []string) []string {
	selected := selectedRealArchitectures(architectures)
	out := make([]string, 0, len(selected))
	for arch := range selected {
		out = append(out, arch)
	}
	sort.Strings(out)
	return out
}

func allowedPackageArchitectures(architectures []string) map[string]bool {
	return setFromSlice(packageIndexArchitectures(architectures))
}

func setFromSlice(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func binaryDirArch(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "binary-") {
		return "", false
	}
	return strings.TrimPrefix(parts[0], "binary-"), true
}

func installerBinaryArch(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	if len(parts) < 3 || parts[0] != "debian-installer" || !strings.HasPrefix(parts[1], "binary-") {
		return "", false
	}
	return strings.TrimPrefix(parts[1], "binary-"), true
}

func cnfArch(rel string) (string, bool) {
	base := trimIndexCompression(path.Base(rel))
	if !strings.HasPrefix(base, "Commands-") {
		return "", false
	}
	return strings.TrimPrefix(base, "Commands-"), true
}

func dep11ComponentsArch(rel string) (string, bool) {
	base := trimIndexCompression(path.Base(rel))
	if !strings.HasPrefix(base, "Components-") || !strings.HasSuffix(base, ".yml") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(base, "Components-"), ".yml"), true
}

func dep11CIDIndexArch(rel string) (string, bool) {
	base := trimIndexCompression(path.Base(rel))
	if !strings.HasPrefix(base, "CID-Index-") || !strings.HasSuffix(base, ".json") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(base, "CID-Index-"), ".json"), true
}

func contentsArch(name string) (string, bool) {
	base := trimIndexCompression(name)
	if !strings.HasPrefix(base, "Contents-") {
		return "", false
	}
	arch := strings.TrimPrefix(base, "Contents-")
	arch = strings.TrimPrefix(arch, "udeb-")
	if arch == "" {
		return "", false
	}
	return arch, true
}

func trimIndexCompression(name string) string {
	for _, suffix := range []string{".gz", ".xz", ".bz2"} {
		name = strings.TrimSuffix(name, suffix)
	}
	return name
}

func consumeIndex(rel string, file *os.File, consume func(io.Reader) error) (err error) {
	if file == nil {
		return fmt.Errorf("nil index file")
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	var reader io.Reader = file
	var closer io.Closer
	switch {
	case strings.HasSuffix(rel, ".gz"):
		zr, err := gzip.NewReader(bufio.NewReaderSize(file, 128*1024))
		if err != nil {
			return err
		}
		reader, closer = zr, zr
	case strings.HasSuffix(rel, ".xz"):
		xzr, err := xz.NewReader(bufio.NewReaderSize(file, 128*1024))
		if err != nil {
			return err
		}
		reader = xzr
	case strings.HasSuffix(rel, ".bz2"):
		reader = bzip2.NewReader(bufio.NewReaderSize(file, 128*1024))
	}
	err = consume(reader)
	if closer != nil {
		err = errors.Join(err, closer.Close())
	}
	return err
}

func parsePackages(reader io.Reader, allowedArchs map[string]bool, yield func(model.Package) error) error {
	type packageFields struct {
		filename     string
		architecture string
		size         string
		checksums    model.Checksums
	}
	var fields packageFields
	finish := func() error {
		defer func() { fields = packageFields{} }()
		if fields.filename == "" {
			return nil
		}
		if len(allowedArchs) > 0 && !allowedArchs[fields.architecture] {
			return nil
		}
		size, err := strconv.ParseInt(fields.size, 10, 64)
		if err != nil {
			return fmt.Errorf("%s Size: %w", fields.filename, err)
		}
		rel, err := safe.Rel(fields.filename)
		if err != nil {
			return err
		}
		if fields.checksums.Empty() {
			return fmt.Errorf("%s has no supported checksum", fields.filename)
		}
		return yield(model.Package{Path: rel, Size: size, Checksums: fields.checksums})
	}
	return scanControl(reader, func(line []byte) error {
		if line[0] == ' ' || line[0] == '\t' {
			return nil
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			return nil
		}
		value = bytes.TrimSpace(value)
		switch string(name) {
		case "Filename":
			fields.filename = string(value)
		case "Architecture":
			fields.architecture = string(value)
		case "Size":
			fields.size = string(value)
		case "MD5sum", "MD5Sum":
			fields.checksums.MD5Sum = string(value)
		case "SHA1":
			fields.checksums.SHA1 = string(value)
		case "SHA256":
			fields.checksums.SHA256 = string(value)
		case "SHA512":
			fields.checksums.SHA512 = string(value)
		}
		return nil
	}, finish)
}

type sourcePayload struct {
	Size      int64
	SizeSet   bool
	Checksums model.Checksums
}

func parseSources(reader io.Reader, yield func(model.Package) error) error {
	var directory string
	var checksumName string
	files := map[string]sourcePayload{}
	addEntry := func(line []byte) error {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			return nil
		}
		parts := bytes.Fields(line)
		if len(parts) != 3 {
			return fmt.Errorf("%s: invalid source file entry %q", directory, string(line))
		}
		size, err := strconv.ParseInt(string(parts[1]), 10, 64)
		if err != nil {
			return fmt.Errorf("%s/%s Size: %w", directory, string(parts[2]), err)
		}
		name := string(parts[2])
		payload := files[name]
		if payload.SizeSet && payload.Size != size {
			return fmt.Errorf("%s/%s has conflicting sizes", directory, name)
		}
		digest := string(parts[0])
		if got := payload.Checksums.Get(checksumName); got != "" && !strings.EqualFold(got, digest) {
			return fmt.Errorf("%s/%s has conflicting %s hashes", directory, name, checksumName)
		}
		payload.Size, payload.SizeSet = size, true
		payload.Checksums.Set(checksumName, digest)
		files[name] = payload
		return nil
	}
	finish := func() error {
		defer func() {
			directory = ""
			checksumName = ""
			files = map[string]sourcePayload{}
		}()
		if directory == "" {
			return nil
		}
		names := make([]string, 0, len(files))
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			info := files[name]
			if info.Checksums.Empty() {
				return fmt.Errorf("%s/%s has no supported checksum", directory, name)
			}
			rel, err := safe.Rel(path.Join(directory, name))
			if err != nil {
				return err
			}
			if err := yield(model.Package{Path: rel, Size: info.Size, Checksums: info.Checksums}); err != nil {
				return err
			}
		}
		return nil
	}
	return scanControl(reader, func(line []byte) error {
		if line[0] == ' ' || line[0] == '\t' {
			if checksumName != "" {
				return addEntry(line)
			}
			return nil
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			checksumName = ""
			return nil
		}
		if bytes.Equal(name, []byte("Directory")) {
			directory = string(bytes.TrimSpace(value))
			checksumName = ""
			return nil
		}
		checksumName, ok = sourceChecksumField(string(name))
		if ok {
			return addEntry(value)
		}
		checksumName = ""
		return nil
	}, finish)
}

func sourceChecksumField(field string) (string, bool) {
	switch {
	case strings.EqualFold(field, "Files"):
		return "MD5Sum", true
	case strings.EqualFold(field, "Checksums-Sha1"):
		return "SHA1", true
	case strings.EqualFold(field, "Checksums-Sha256"):
		return "SHA256", true
	case strings.EqualFold(field, "Checksums-Sha512"):
		return "SHA512", true
	default:
		return "", false
	}
}

func scanControl(reader io.Reader, line func([]byte) error, finish func() error) error {
	buffered := bufio.NewReaderSize(reader, 64*1024)
	haveFields := false
	var pending []byte
	for {
		raw, prefix, err := buffered.ReadLine()
		if len(pending) > 0 {
			pending = append(pending, raw...)
			raw = pending
		}
		if prefix {
			if len(pending) == 0 {
				pending = append([]byte(nil), raw...)
			}
			continue
		}
		pending = nil
		if len(raw) > 0 || err == nil {
			if len(raw) == 0 {
				if haveFields {
					if finishErr := finish(); finishErr != nil {
						return finishErr
					}
					haveFields = false
				}
			} else {
				haveFields = true
				if lineErr := line(raw); lineErr != nil {
					return lineErr
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				return err
			}
			if haveFields {
				return finish()
			}
			return nil
		}
	}
}

func addPayload(payloads map[string]model.Payload, pkg model.Package, source string) error {
	if existing, ok := payloads[pkg.Path]; ok {
		if existing.Size != pkg.Size || !sameChecksums(existing.Checksums, pkg.Checksums) {
			return fmt.Errorf("%s: conflicting metadata for payload %s", source, pkg.Path)
		}
		existing.Checksums = mergeChecksums(existing.Checksums, pkg.Checksums)
		payloads[pkg.Path] = existing
		return nil
	}
	payloads[pkg.Path] = model.Payload{Size: pkg.Size, Checksums: pkg.Checksums}
	return nil
}

func sameChecksums(a, b model.Checksums) bool {
	if a.Empty() && b.Empty() {
		return true
	}
	for _, alg := range []string{"SHA512", "SHA256", "SHA1", "MD5Sum", "MD5"} {
		av := checksumFromMap(a, alg)
		bv := checksumFromMap(b, alg)
		if av != "" && bv != "" && !strings.EqualFold(av, bv) {
			return false
		}
	}
	return true
}

func verifyFile(file string, want releaseFile) (bool, error) {
	alg, hexWant := strongestReleaseChecksum(want)
	if alg == "" {
		return false, fmt.Errorf("no supported checksum")
	}
	return publish.Verify(file, publish.WithSize(want.Size), publish.WithChecksum(alg, hexWant))
}

func strongestReleaseChecksum(file releaseFile) (string, string) {
	for _, alg := range []string{"SHA512", "SHA256", "SHA1", "MD5Sum", "MD5"} {
		if value := checksumFromMap(file.Checksums, alg); value != "" {
			return canonicalChecksumName(alg), value
		}
	}
	return "", ""
}

func checksumFromMap(checksums model.Checksums, algorithm string) string {
	return checksums.Get(algorithm)
}

func canonicalChecksumName(name string) string {
	if strings.EqualFold(name, "MD5sum") || strings.EqualFold(name, "MD5Sum") || strings.EqualFold(name, "MD5") {
		return "MD5Sum"
	}
	return strings.ToUpper(name)
}

func mergeChecksums(a, b model.Checksums) model.Checksums {
	out := a
	for _, name := range []string{"MD5Sum", "SHA1", "SHA256", "SHA512"} {
		if value := b.Get(name); value != "" {
			out.Set(name, value)
		}
	}
	return out
}

func (r *Runner) payloadClients() ([]*httpx.Client, error) {
	sources, err := r.Config.PayloadSources(r.Repo.Name, config.RepoAPT, r.Repo.PrimarySource, r.Repo.MirrorSources)
	if err != nil {
		return nil, err
	}
	var out []*httpx.Client
	for _, eff := range sources {
		client, err := r.HTTP.Client(eff)
		if err != nil {
			return nil, err
		}
		out = append(out, client)
	}
	return out, nil
}

func (r *Runner) sourceDescriptions() []string {
	var out []string
	sources, err := r.Config.PayloadSources(r.Repo.Name, config.RepoAPT, r.Repo.PrimarySource, r.Repo.MirrorSources)
	if err != nil {
		return out
	}
	for _, eff := range sources {
		mode := "direct"
		if !eff.DirectProxy && eff.ProxyURL != "" {
			mode = eff.ProxyURL
		}
		out = append(out, fmt.Sprintf("%s proxy=%s max_connections=%d max_in_flight_requests=%d", eff.URL, mode, eff.MaxConnections, eff.MaxInFlightRequests))
	}
	return out
}

func aptFileExpected(files []model.RepositoryFile) []download.Expected {
	files = sortedFiles(files)
	expected := make([]download.Expected, 0, len(files))
	for _, f := range files {
		expected = append(expected, download.Expected{
			RelPath:      f.Path,
			Size:         f.Size,
			Checksums:    f.Checksums,
			VerifyOnSync: true,
		})
	}
	return expected
}

func sortedFiles(files []model.RepositoryFile) []model.RepositoryFile {
	out := append([]model.RepositoryFile(nil), files...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func repoStaging(cfg *config.Config, kind, name string) string {
	return path.Join(cfg.Storage.Staging, "repos", kind, name)
}

func releaseFingerprint(text string) string {
	digest := sha256.Sum256([]byte(text))
	return hex.EncodeToString(digest[:])
}

func filterRepositoryFiles(files []model.RepositoryFile, paths map[string]bool) []model.RepositoryFile {
	out := make([]model.RepositoryFile, 0, len(files))
	for _, file := range files {
		if paths[file.Path] {
			out = append(out, file)
		}
	}
	return out
}

func (r *Runner) distsClients() ([]*httpx.Client, error) {
	sources := make([]config.EffectiveSource, 0, len(r.Repo.MirrorSources)+1)
	for i, mirror := range r.Repo.MirrorSources {
		effective, err := r.Config.Source(r.Repo.Name, config.RepoAPT, config.SourceMirror, i, mirror)
		if err != nil {
			return nil, err
		}
		sources = append(sources, effective)
	}
	primary, err := r.Config.Source(r.Repo.Name, config.RepoAPT, config.SourcePrimary, 0, r.Repo.PrimarySource)
	if err != nil {
		return nil, err
	}
	sources = append(sources, primary)
	clients := make([]*httpx.Client, 0, len(sources))
	for _, source := range sources {
		client, err := r.HTTP.Client(source)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, nil
}

func filepathFor(root, rel string) string {
	p, _ := safe.Join(root, rel)
	return p
}
