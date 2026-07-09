package apt

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
	Size   int64
	SHA256 string
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
		MetadataFiles: len(state.Metadata) + len(state.Files), Packages: len(state.Packages), Bytes: bytes,
		Sources: r.sourceDescriptions(),
	}, nil
}

func (r *Runner) Sync(ctx context.Context) error {
	lock, err := publish.AcquireLock(r.Config.Storage.Staging, "apt", r.Repo.Name)
	if err != nil {
		return err
	}
	defer lock.Close()
	state, err := r.fetchState(ctx)
	if err != nil {
		return err
	}
	clients, err := r.payloadClients()
	if err != nil {
		return err
	}
	if err := download.EnsureSynced(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), clients, aptExpected(state)); err != nil {
		return fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	if err := publish.PublishMetadata(r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), state.Metadata); err != nil {
		return fmt.Errorf("apt %s: %w", r.Repo.Name, err)
	}
	if r.Config.Sync.Prune {
		_, err := r.Prune(ctx)
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
	state, err := r.readPublishedState()
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, mf := range state.Metadata {
		keep[mf.Path] = true
	}
	for _, f := range state.Files {
		keep[f.Path] = true
	}
	for rel := range state.Packages {
		keep[rel] = true
	}
	_ = ctx
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
	out := model.RepositoryState{Packages: map[string]model.Package{}}
	for _, suite := range r.Repo.Suites {
		releaseText, releaseHashes, metadata, err := r.fetchRelease(ctx, client, keyring, suite.Name)
		if err != nil {
			return out, err
		}
		_ = releaseText
		out.Metadata = append(out.Metadata, metadata...)
		files, err := selectReleaseFiles(suite, r.Repo.Architectures, releaseHashes)
		if err != nil {
			return out, err
		}
		out.Files = append(out.Files, files...)
		for _, component := range suite.Components {
			for _, arch := range packageIndexArchitectures(r.Repo.Architectures) {
				indexRel, indexData, found, err := r.fetchPackagesIndex(ctx, client, suite.Name, component, arch, releaseHashes)
				if err != nil {
					return out, err
				}
				if !found {
					if arch == "all" {
						continue
					}
					return out, fmt.Errorf("apt %s no Packages index for %s/%s/%s", r.Repo.Name, suite.Name, component, arch)
				}
				pkgs, err := parsePackages(decompressIndex(indexRel, indexData))
				if err != nil {
					return out, fmt.Errorf("apt %s parse %s: %w", r.Repo.Name, indexRel, err)
				}
				for _, pkg := range pkgs {
					out.Packages[pkg.Path] = pkg
				}
			}
		}
	}
	return out, nil
}

func (r *Runner) fetchRelease(ctx context.Context, client *httpx.Client, keyring openpgp.EntityList, suite string) (string, map[string]releaseFile, []model.MetadataFile, error) {
	inReleaseRel := path.Join("dists", suite, "InRelease")
	inRelease, err := client.GetBytes(ctx, inReleaseRel, 64<<20)
	if err == nil {
		plain, err := verifyInRelease(inRelease, keyring)
		if err != nil {
			return "", nil, nil, fmt.Errorf("apt %s verify %s: %w", r.Repo.Name, inReleaseRel, err)
		}
		hashes, err := parseReleaseHashes(string(plain))
		if err != nil {
			return "", nil, nil, err
		}
		return string(plain), hashes, []model.MetadataFile{{Path: inReleaseRel, Data: inRelease, SignedLast: true}}, nil
	}
	releaseRel := path.Join("dists", suite, "Release")
	sigRel := path.Join("dists", suite, "Release.gpg")
	releaseData, rerr := client.GetBytes(ctx, releaseRel, 64<<20)
	if rerr != nil {
		return "", nil, nil, fmt.Errorf("apt %s fetch %s failed after InRelease failed (%v): %w", r.Repo.Name, releaseRel, err, rerr)
	}
	sig, err := client.GetBytes(ctx, sigRel, 16<<20)
	if err != nil {
		return "", nil, nil, err
	}
	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(releaseData), bytes.NewReader(sig), nil); err != nil {
		return "", nil, nil, fmt.Errorf("apt %s verify %s: %w", r.Repo.Name, sigRel, err)
	}
	hashes, err := parseReleaseHashes(string(releaseData))
	if err != nil {
		return "", nil, nil, err
	}
	return string(releaseData), hashes, []model.MetadataFile{
		{Path: releaseRel, Data: releaseData},
		{Path: sigRel, Data: sig, SignedLast: true},
	}, nil
}

func (r *Runner) fetchPackagesIndex(ctx context.Context, client *httpx.Client, suite, component, arch string, hashes map[string]releaseFile) (string, []byte, bool, error) {
	candidates := []string{
		path.Join(component, "binary-"+arch, "Packages.xz"),
		path.Join(component, "binary-"+arch, "Packages.gz"),
		path.Join(component, "binary-"+arch, "Packages"),
	}
	for _, rel := range candidates {
		want, ok := hashes[rel]
		if !ok {
			continue
		}
		data, err := client.GetBytes(ctx, path.Join("dists", suite, rel), want.Size+1)
		if err != nil {
			return "", nil, false, err
		}
		got := sha256.Sum256(data)
		if int64(len(data)) != want.Size || !strings.EqualFold(hex.EncodeToString(got[:]), want.SHA256) {
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
					if arch == "all" {
						continue
					}
					return out, fmt.Errorf("no published Packages index for %s/%s/%s", suite.Name, component, arch)
				}
				pkgs, err := parsePackages(decompressIndex(indexRel, data))
				if err != nil {
					return out, err
				}
				for _, pkg := range pkgs {
					out.Packages[pkg.Path] = pkg
				}
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
	out := model.RepositoryState{Packages: map[string]model.Package{}}
	for _, suite := range r.Repo.Suites {
		var releaseText string
		var hashes map[string]releaseFile
		inReleaseRel := path.Join("dists", suite.Name, "InRelease")
		if data, err := os.ReadFile(filepathFor(r.Repo.AbsPublishPath, inReleaseRel)); err == nil {
			plain, err := verifyInRelease(data, keyring)
			if err != nil {
				return out, err
			}
			releaseText = string(plain)
			hashes, err = parseReleaseHashes(releaseText)
			if err != nil {
				return out, err
			}
			out.Metadata = append(out.Metadata, model.MetadataFile{Path: inReleaseRel, Data: data, SignedLast: true})
		} else {
			releaseRel := path.Join("dists", suite.Name, "Release")
			sigRel := path.Join("dists", suite.Name, "Release.gpg")
			releaseData, err := os.ReadFile(filepathFor(r.Repo.AbsPublishPath, releaseRel))
			if err != nil {
				return out, err
			}
			sig, err := os.ReadFile(filepathFor(r.Repo.AbsPublishPath, sigRel))
			if err != nil {
				return out, err
			}
			if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(releaseData), bytes.NewReader(sig), nil); err != nil {
				return out, err
			}
			releaseText = string(releaseData)
			hashes, err = parseReleaseHashes(releaseText)
			if err != nil {
				return out, err
			}
			out.Metadata = append(out.Metadata, model.MetadataFile{Path: releaseRel, Data: releaseData}, model.MetadataFile{Path: sigRel, Data: sig, SignedLast: true})
		}
		_ = releaseText
		files, err := selectReleaseFiles(suite, r.Repo.Architectures, hashes)
		if err != nil {
			return out, err
		}
		out.Files = append(out.Files, files...)
	}
	return out, nil
}

func (r *Runner) readPublishedReleaseHashes(suite string) (map[string]releaseFile, error) {
	keyring, err := loadKeyring(r.Repo.AbsKeyring)
	if err != nil {
		return nil, err
	}
	inReleaseRel := path.Join("dists", suite, "InRelease")
	if data, err := os.ReadFile(filepathFor(r.Repo.AbsPublishPath, inReleaseRel)); err == nil {
		plain, err := verifyInRelease(data, keyring)
		if err != nil {
			return nil, err
		}
		return parseReleaseHashes(string(plain))
	}
	releaseRel := path.Join("dists", suite, "Release")
	sigRel := path.Join("dists", suite, "Release.gpg")
	releaseData, err := os.ReadFile(filepathFor(r.Repo.AbsPublishPath, releaseRel))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepathFor(r.Repo.AbsPublishPath, sigRel))
	if err != nil {
		return nil, err
	}
	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(releaseData), bytes.NewReader(sig), nil); err != nil {
		return nil, err
	}
	return parseReleaseHashes(string(releaseData))
}

func (r *Runner) readPublishedIndex(suite, component, arch string, hashes map[string]releaseFile) (string, []byte, bool, error) {
	for _, rel := range []string{path.Join(component, "binary-"+arch, "Packages.xz"), path.Join(component, "binary-"+arch, "Packages.gz"), path.Join(component, "binary-"+arch, "Packages")} {
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
		got := sha256.Sum256(data)
		if int64(len(data)) != want.Size || !strings.EqualFold(hex.EncodeToString(got[:]), want.SHA256) {
			continue
		}
		return rel, data, true, nil
	}
	return "", nil, false, nil
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
	block, _ := clearsign.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("not a clearsigned document")
	}
	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
		return nil, err
	}
	return block.Bytes, nil
}

func parseReleaseHashes(text string) (map[string]releaseFile, error) {
	out := map[string]releaseFile{}
	inSHA := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "SHA256:") {
			inSHA = true
			continue
		}
		if inSHA {
			if line == "" || (len(line) > 0 && line[0] != ' ') {
				inSHA = false
				continue
			}
			fields := strings.Fields(line)
			if len(fields) != 3 {
				continue
			}
			size, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return nil, err
			}
			out[fields[2]] = releaseFile{Size: size, SHA256: fields[0]}
		}
	}
	return out, nil
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
		out = append(out, model.RepositoryFile{Path: publishedRel, Size: file.Size, SHA256: file.SHA256})
	}
	return out, nil
}

func shouldMirrorReleaseFile(rel string, components, selectedArchs, packageArchs map[string]bool) bool {
	parts := strings.Split(rel, "/")
	if len(parts) == 1 {
		if arch, ok := contentsArch(parts[0]); ok {
			return selectedArchs[arch]
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
		return selectedArchs[arch]
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
	for _, suffix := range []string{".gz", ".xz"} {
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
	default:
		return data, nil
	}
}

func parsePackages(data []byte, err error) ([]model.Package, error) {
	if err != nil {
		return nil, err
	}
	var out []model.Package
	for _, para := range strings.Split(string(data), "\n\n") {
		fields := parseParagraph(para)
		if fields["Filename"] == "" {
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
		out = append(out, model.Package{Path: rel, Size: size, SHA256: fields["SHA256"]})
	}
	return out, nil
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
			RelPath: pkg.Path, Size: pkg.Size, SHA256: pkg.SHA256,
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
