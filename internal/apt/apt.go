package apt

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
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
	Checksums map[string]string
}

func (r *Runner) Plan(ctx context.Context) (model.RepositoryPlan, error) {
	state, err := r.fetchState(ctx)
	if err != nil {
		return model.RepositoryPlan{}, err
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

func (r *Runner) Sync(ctx context.Context) error {
	lock, err := publish.AcquireLock(r.Config.Storage.Staging, "apt", r.Repo.Name)
	if err != nil {
		return err
	}
	defer lock.Close()
	oldState, oldPublished, err := r.readPublishedReleaseStateOptional()
	oldStateUnsafe := err != nil
	if oldStateUnsafe {
		oldPublished = false
	}
	history, historyStatus, err := r.loadByHashHistory()
	if err != nil {
		return fmt.Errorf("apt %s read by-hash history: %w", r.Repo.Name, err)
	}
	if oldPublished {
		history = updateByHashHistory(history, oldState)
	}
	state, err := r.fetchState(ctx)
	if err != nil {
		return err
	}
	if oldPublished {
		r.preserveByHash(oldState.ByHashFiles)
	}
	clients, err := r.payloadClients()
	if err != nil {
		return err
	}
	if err := download.EnsureSynced(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), clients, aptExpected(state)); err != nil {
		return fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	if err := r.materializeByHash(state.ByHashFiles); err != nil {
		return fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	if err := publish.PublishMetadata(r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), state.Metadata); err != nil {
		return fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	history = updateByHashHistory(history, state)
	if err := r.writeByHashHistory(history); err != nil {
		return fmt.Errorf("apt %s write by-hash history: %w", r.Repo.Name, err)
	}
	if r.Config.Sync.Prune {
		_, err := r.pruneStateWithHistory(state, history, historyStatus == byHashHistoryCorrupt || oldStateUnsafe)
		return err
	}
	return nil
}

func (r *Runner) Verify(ctx context.Context) error {
	lock, err := publish.AcquireLock(r.Config.Storage.Staging, "apt", r.Repo.Name)
	if err != nil {
		return err
	}
	defer lock.Close()
	releaseState, err := r.readPublishedReleaseState()
	if err != nil {
		return err
	}
	clients, err := r.payloadClients()
	if err != nil {
		return err
	}
	if err := download.EnsureRepaired(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), clients, aptFileExpected(releaseState.Files)); err != nil {
		return fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	if err := r.materializeByHash(releaseState.ByHashFiles); err != nil {
		return fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	r.verifyHistoricByHash()
	state, err := r.readPublishedState()
	if err != nil {
		return err
	}
	if err := download.EnsureRepaired(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), clients, aptPackageExpected(state.Packages)); err != nil {
		return fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	return nil
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
	out := model.RepositoryState{ByHashEnabled: map[string]bool{}, Packages: map[string]model.Package{}}
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
		out.Metadata = append(out.Metadata, metadata...)
		files, err := selectReleaseFiles(suite, r.Repo.Architectures, releaseHashes)
		if err != nil {
			return out, err
		}
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
				indexRel, indexData, found, err := r.fetchPackagesIndex(ctx, client, suite.Name, component, arch, releaseHashes)
				if err != nil {
					return out, err
				}
				if !found {
					continue
				}
				indexPlain, err := decompressIndex(indexRel, indexData)
				pkgs, err := parsePackages(indexPlain, err, allowedPackageArchitectures(r.Repo.Architectures))
				if err != nil {
					return out, fmt.Errorf("apt %s parse %s: %w", r.Repo.Name, indexRel, err)
				}
				for _, pkg := range pkgs {
					if err := addPayload(out.Packages, pkg, indexRel); err != nil {
						return out, err
					}
				}
			}
			for _, arch := range selectedArchitectureNames(r.Repo.Architectures) {
				indexRel, indexData, found, err := r.fetchInstallerPackagesIndex(ctx, client, suite.Name, component, arch, releaseHashes)
				if err != nil {
					return out, err
				}
				if !found {
					continue
				}
				indexPlain, err := decompressIndex(indexRel, indexData)
				pkgs, err := parsePackages(indexPlain, err, allowedPackageArchitectures(r.Repo.Architectures))
				if err != nil {
					return out, fmt.Errorf("apt %s parse %s: %w", r.Repo.Name, indexRel, err)
				}
				for _, pkg := range pkgs {
					if err := addPayload(out.Packages, pkg, indexRel); err != nil {
						return out, err
					}
				}
			}
			indexRel, indexData, found, err := r.fetchSourcesIndex(ctx, client, suite.Name, component, releaseHashes)
			if err != nil {
				return out, err
			}
			if found {
				pkgs, err := parseSources(decompressIndex(indexRel, indexData))
				if err != nil {
					return out, fmt.Errorf("apt %s parse %s: %w", r.Repo.Name, indexRel, err)
				}
				for _, pkg := range pkgs {
					if err := addPayload(out.Packages, pkg, indexRel); err != nil {
						return out, err
					}
				}
			}
		}
	}
	return out, nil
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

func (r *Runner) fetchPackagesIndex(ctx context.Context, client *httpx.Client, suite, component, arch string, hashes map[string]releaseFile) (string, []byte, bool, error) {
	return r.fetchIndex(ctx, client, suite, path.Join(component, "binary-"+arch), "Packages", hashes)
}

func (r *Runner) fetchInstallerPackagesIndex(ctx context.Context, client *httpx.Client, suite, component, arch string, hashes map[string]releaseFile) (string, []byte, bool, error) {
	return r.fetchIndex(ctx, client, suite, path.Join(component, "debian-installer", "binary-"+arch), "Packages", hashes)
}

func (r *Runner) fetchSourcesIndex(ctx context.Context, client *httpx.Client, suite, component string, hashes map[string]releaseFile) (string, []byte, bool, error) {
	return r.fetchIndex(ctx, client, suite, path.Join(component, "source"), "Sources", hashes)
}

func (r *Runner) fetchIndex(ctx context.Context, client *httpx.Client, suite, dir, name string, hashes map[string]releaseFile) (string, []byte, bool, error) {
	candidates := indexCandidates(dir, name)
	for _, rel := range candidates {
		want, ok := hashes[rel]
		if !ok {
			continue
		}
		data, err := client.GetBytes(ctx, path.Join("dists", suite, rel), want.Size+1)
		if err != nil {
			return "", nil, false, err
		}
		if err := verifyBytes(data, want); err != nil {
			return "", nil, false, fmt.Errorf("apt %s index %s checksum mismatch", r.Repo.Name, rel)
		}
		return rel, data, true, nil
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
		hashesBySuite[suite.Name] = hashes
	}
	for _, suite := range r.Repo.Suites {
		hashes := hashesBySuite[suite.Name]
		for _, component := range suite.Components {
			for _, arch := range packageIndexArchitectures(r.Repo.Architectures) {
				indexRel, data, found, err := r.readPublishedIndex(suite.Name, component, arch, hashes)
				if err != nil {
					return out, err
				}
				if !found {
					if !releaseAdvertisesIndex(path.Join(component, "binary-"+arch), "Packages", hashes) {
						continue
					}
					return out, fmt.Errorf("no valid published Packages index for %s/%s/%s", suite.Name, component, arch)
				}
				indexPlain, err := decompressIndex(indexRel, data)
				pkgs, err := parsePackages(indexPlain, err, allowedPackageArchitectures(r.Repo.Architectures))
				if err != nil {
					return out, err
				}
				for _, pkg := range pkgs {
					if err := addPayload(out.Packages, pkg, indexRel); err != nil {
						return out, err
					}
				}
			}
			for _, arch := range selectedArchitectureNames(r.Repo.Architectures) {
				indexRel, data, found, err := r.readPublishedInstallerIndex(suite.Name, component, arch, hashes)
				if err != nil {
					return out, err
				}
				if !found {
					if releaseAdvertisesIndex(path.Join(component, "debian-installer", "binary-"+arch), "Packages", hashes) {
						return out, fmt.Errorf("no valid published Debian Installer Packages index for %s/%s/%s", suite.Name, component, arch)
					}
					continue
				}
				indexPlain, err := decompressIndex(indexRel, data)
				pkgs, err := parsePackages(indexPlain, err, allowedPackageArchitectures(r.Repo.Architectures))
				if err != nil {
					return out, err
				}
				for _, pkg := range pkgs {
					if err := addPayload(out.Packages, pkg, indexRel); err != nil {
						return out, err
					}
				}
			}
			indexRel, data, found, err := r.readPublishedSourcesIndex(suite.Name, component, hashes)
			if err != nil {
				return out, err
			}
			if found {
				pkgs, err := parseSources(decompressIndex(indexRel, data))
				if err != nil {
					return out, err
				}
				for _, pkg := range pkgs {
					if err := addPayload(out.Packages, pkg, indexRel); err != nil {
						return out, err
					}
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
	out := model.RepositoryState{ByHashEnabled: map[string]bool{}, Packages: map[string]model.Package{}}
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
		files, err := selectReleaseFiles(suite, r.Repo.Architectures, hashes)
		if err != nil {
			return out, err
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

func (r *Runner) readPublishedIndex(suite, component, arch string, hashes map[string]releaseFile) (string, []byte, bool, error) {
	return r.readPublishedNamedIndex(suite, path.Join(component, "binary-"+arch), "Packages", hashes)
}

func (r *Runner) readPublishedInstallerIndex(suite, component, arch string, hashes map[string]releaseFile) (string, []byte, bool, error) {
	return r.readPublishedNamedIndex(suite, path.Join(component, "debian-installer", "binary-"+arch), "Packages", hashes)
}

func (r *Runner) readPublishedSourcesIndex(suite, component string, hashes map[string]releaseFile) (string, []byte, bool, error) {
	return r.readPublishedNamedIndex(suite, path.Join(component, "source"), "Sources", hashes)
}

func (r *Runner) readPublishedNamedIndex(suite, dir, name string, hashes map[string]releaseFile) (string, []byte, bool, error) {
	for _, rel := range indexCandidates(dir, name) {
		want, ok := hashes[rel]
		if !ok {
			continue
		}
		data, err := os.ReadFile(filepathFor(r.Repo.AbsPublishPath, path.Join("dists", suite, rel)))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", nil, false, err
		}
		if err := verifyBytes(data, want); err != nil {
			continue
		}
		return rel, data, true, nil
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
			if existing.Checksums == nil {
				existing.Checksums = map[string]string{}
			}
			if existing.SizeSet && existing.Size != size {
				return nil, fmt.Errorf("%s has conflicting sizes in Release", fields[2])
			}
			if got := existing.Checksums[checksumType]; got != "" && !strings.EqualFold(got, fields[0]) {
				return nil, fmt.Errorf("%s has conflicting %s hashes in Release", fields[2], checksumType)
			}
			existing.Size = size
			existing.SizeSet = true
			existing.Checksums[checksumType] = fields[0]
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
		out = append(out, model.RepositoryFile{Path: publishedRel, Size: file.Size, Checksums: cloneChecksums(file.Checksums)})
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

func decompressIndex(rel string, data []byte) ([]byte, error) {
	switch {
	case strings.HasSuffix(rel, ".gz"):
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
	case strings.HasSuffix(rel, ".xz"):
		xzr, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(xzr)
	case strings.HasSuffix(rel, ".bz2"):
		return io.ReadAll(bzip2.NewReader(bytes.NewReader(data)))
	default:
		return data, nil
	}
}

func parsePackages(data []byte, err error, allowedArchs map[string]bool) ([]model.Package, error) {
	if err != nil {
		return nil, err
	}
	var out []model.Package
	for _, para := range strings.Split(string(data), "\n\n") {
		fields := parseParagraph(para)
		if fields["Filename"] == "" {
			continue
		}
		if arch := fields["Architecture"]; len(allowedArchs) > 0 && !allowedArchs[arch] {
			continue
		}
		size, err := strconv.ParseInt(fields["Size"], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s Size: %w", fields["Filename"], err)
		}
		rel, err := safe.Rel(fields["Filename"])
		if err != nil {
			return nil, err
		}
		checksums := paragraphChecksums(fields)
		if len(checksums) == 0 {
			return nil, fmt.Errorf("%s has no supported checksum", fields["Filename"])
		}
		out = append(out, model.Package{Path: rel, Size: size, SHA256: checksums["SHA256"], Checksums: checksums})
	}
	return out, nil
}

func parseSources(data []byte, err error) ([]model.Package, error) {
	if err != nil {
		return nil, err
	}
	var out []model.Package
	for _, para := range strings.Split(string(data), "\n\n") {
		fields := parseParagraph(para)
		dir := fields["Directory"]
		if dir == "" {
			continue
		}
		files, err := sourcePayloads(fields)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(files))
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			info := files[name]
			rel, err := safe.Rel(path.Join(dir, name))
			if err != nil {
				return nil, err
			}
			out = append(out, model.Package{Path: rel, Size: info.Size, SHA256: info.Checksums["SHA256"], Checksums: cloneChecksums(info.Checksums)})
		}
	}
	return out, nil
}

func paragraphChecksums(fields map[string]string) map[string]string {
	out := map[string]string{}
	for _, key := range []string{"MD5sum", "MD5Sum", "SHA1", "SHA256", "SHA512"} {
		if fields[key] != "" {
			out[canonicalChecksumName(key)] = fields[key]
		}
	}
	return out
}

type sourcePayload struct {
	Size      int64
	Checksums map[string]string
}

func sourcePayloads(fields map[string]string) (map[string]sourcePayload, error) {
	out := map[string]sourcePayload{}
	for field, value := range fields {
		checksumName, ok := sourceChecksumField(field)
		if !ok {
			continue
		}
		for _, line := range strings.Split(value, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) != 3 {
				return nil, fmt.Errorf("%s: invalid source file entry %q", fields["Directory"], line)
			}
			size, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%s/%s Size: %w", fields["Directory"], parts[2], err)
			}
			payload := out[parts[2]]
			if payload.Checksums == nil {
				payload.Checksums = map[string]string{}
			}
			if payload.Size != 0 && payload.Size != size {
				return nil, fmt.Errorf("%s/%s has conflicting sizes", fields["Directory"], parts[2])
			}
			if got := payload.Checksums[checksumName]; got != "" && !strings.EqualFold(got, parts[0]) {
				return nil, fmt.Errorf("%s/%s has conflicting %s hashes", fields["Directory"], parts[2], checksumName)
			}
			payload.Size = size
			payload.Checksums[checksumName] = parts[0]
			out[parts[2]] = payload
		}
	}
	for name, payload := range out {
		if len(payload.Checksums) == 0 {
			return nil, fmt.Errorf("%s/%s has no supported checksum", fields["Directory"], name)
		}
	}
	return out, nil
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

func parseParagraph(text string) map[string]string {
	out := map[string]string{}
	var last string
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last != "" {
				out[last] += "\n" + line
			}
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		last = k
		out[k] = strings.TrimSpace(v)
	}
	return out
}

func addPayload(payloads map[string]model.Package, pkg model.Package, source string) error {
	if existing, ok := payloads[pkg.Path]; ok {
		if existing.Size != pkg.Size || !sameChecksums(existing.Checksums, pkg.Checksums) {
			return fmt.Errorf("%s: conflicting metadata for payload %s", source, pkg.Path)
		}
		existing.Checksums = mergeChecksums(existing.Checksums, pkg.Checksums)
		if existing.SHA256 == "" {
			existing.SHA256 = pkg.SHA256
		}
		payloads[pkg.Path] = existing
		return nil
	}
	payloads[pkg.Path] = pkg
	return nil
}

func sameChecksums(a, b map[string]string) bool {
	if len(a) == 0 && len(b) == 0 {
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

func verifyBytes(data []byte, want releaseFile) error {
	if int64(len(data)) != want.Size {
		return fmt.Errorf("size mismatch got %d want %d", len(data), want.Size)
	}
	alg, hexWant := strongestReleaseChecksum(want)
	if alg == "" {
		return fmt.Errorf("no supported checksum")
	}
	h, err := newHash(alg)
	if err != nil {
		return err
	}
	if _, err := h.Write(data); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, hexWant) {
		return fmt.Errorf("%s mismatch got %s want %s", strings.ToLower(alg), got, hexWant)
	}
	return nil
}

func strongestReleaseChecksum(file releaseFile) (string, string) {
	for _, alg := range []string{"SHA512", "SHA256", "SHA1", "MD5Sum", "MD5"} {
		if value := checksumFromMap(file.Checksums, alg); value != "" {
			return canonicalChecksumName(alg), value
		}
	}
	return "", ""
}

func checksumFromMap(checksums map[string]string, algorithm string) string {
	for name, value := range checksums {
		if strings.EqualFold(canonicalChecksumName(name), canonicalChecksumName(algorithm)) {
			return value
		}
	}
	return ""
}

func canonicalChecksumName(name string) string {
	if strings.EqualFold(name, "MD5sum") || strings.EqualFold(name, "MD5Sum") || strings.EqualFold(name, "MD5") {
		return "MD5Sum"
	}
	return strings.ToUpper(name)
}

func cloneChecksums(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for name, value := range in {
		out[canonicalChecksumName(name)] = value
	}
	return out
}

func mergeChecksums(a, b map[string]string) map[string]string {
	out := cloneChecksums(a)
	if out == nil {
		out = map[string]string{}
	}
	for name, value := range b {
		out[canonicalChecksumName(name)] = value
	}
	return out
}

func newHash(algorithm string) (hash.Hash, error) {
	switch canonicalChecksumName(algorithm) {
	case "MD5Sum":
		return md5.New(), nil
	case "SHA1":
		return sha1.New(), nil
	case "SHA256":
		return sha256.New(), nil
	case "SHA512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported checksum algorithm %q", algorithm)
	}
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

func sortedPackages(m map[string]model.Package) []model.Package {
	out := make([]model.Package, 0, len(m))
	for _, pkg := range m {
		out = append(out, pkg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func aptExpected(state model.RepositoryState) []download.Expected {
	var expected []download.Expected
	expected = append(expected, aptFileExpected(state.Files)...)
	expected = append(expected, aptPackageExpected(state.Packages)...)
	return expected
}

func aptPackageExpected(packages map[string]model.Package) []download.Expected {
	var expected []download.Expected
	for _, pkg := range sortedPackages(packages) {
		expected = append(expected, download.Expected{
			RelPath: pkg.Path, Size: pkg.Size, SHA256: pkg.SHA256, Checksums: cloneChecksums(pkg.Checksums),
		})
	}
	return expected
}

func aptFileExpected(files []model.RepositoryFile) []download.Expected {
	files = sortedFiles(files)
	fileSet := map[string]bool{}
	for _, f := range files {
		fileSet[f.Path] = true
	}
	expected := make([]download.Expected, 0, len(files))
	for _, f := range files {
		expected = append(expected, download.Expected{
			RelPath:      f.Path,
			Size:         f.Size,
			SHA256:       f.SHA256,
			Checksums:    cloneChecksums(f.Checksums),
			VerifyOnSync: true,
			Sources:      releaseFileSources(f.Path, fileSet),
		})
	}
	return expected
}

func sortedFiles(files []model.RepositoryFile) []model.RepositoryFile {
	out := append([]model.RepositoryFile(nil), files...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func releaseFileSources(rel string, fileSet map[string]bool) []download.Source {
	sources := []download.Source{{RelPath: rel}}
	if strings.HasSuffix(rel, ".gz") || strings.HasSuffix(rel, ".xz") {
		return sources
	}
	if fileSet[rel+".xz"] {
		sources = append(sources, download.Source{RelPath: rel + ".xz", Decompress: "xz"})
	}
	if fileSet[rel+".gz"] {
		sources = append(sources, download.Source{RelPath: rel + ".gz", Decompress: "gzip"})
	}
	return sources
}

func repoStaging(cfg *config.Config, kind, name string) string {
	return path.Join(cfg.Storage.Staging, "repos", kind, name)
}

func filepathFor(root, rel string) string {
	p, _ := safe.Join(root, rel)
	return p
}
