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
		MetadataFiles: len(state.Metadata), Packages: len(state.Packages), Bytes: bytes,
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
	var expected []download.Expected
	for _, pkg := range sortedPackages(state.Packages) {
		expected = append(expected, download.Expected{
			RelPath: pkg.Path, Size: pkg.Size, SHA256: pkg.SHA256,
		})
	}
	if err := download.EnsureMany(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apt", r.Repo.Name), clients, expected); err != nil {
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
	state, err := r.readPublishedState()
	if err != nil {
		return err
	}
	for _, pkg := range state.Packages {
		final, err := safe.Join(r.Repo.AbsPublishPath, pkg.Path)
		if err != nil {
			return err
		}
		ok, err := publish.VerifyPublished(final, pkg.Size, pkg.SHA256)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("apt %s package %s failed verification", r.Repo.Name, pkg.Path)
		}
	}
	_ = ctx
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
		for _, component := range suite.Components {
			for _, arch := range r.Repo.Architectures {
				indexRel, indexData, err := r.fetchPackagesIndex(ctx, client, suite.Name, component, arch, releaseHashes)
				if err != nil {
					return out, err
				}
				out.Metadata = append(out.Metadata, model.MetadataFile{Path: path.Join("dists", suite.Name, indexRel), Data: indexData})
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

func (r *Runner) fetchPackagesIndex(ctx context.Context, client *httpx.Client, suite, component, arch string, hashes map[string]releaseFile) (string, []byte, error) {
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
			return "", nil, err
		}
		got := sha256.Sum256(data)
		if int64(len(data)) != want.Size || !strings.EqualFold(hex.EncodeToString(got[:]), want.SHA256) {
			return "", nil, fmt.Errorf("apt %s index %s checksum mismatch", r.Repo.Name, rel)
		}
		return rel, data, nil
	}
	return "", nil, fmt.Errorf("apt %s no Packages index for %s/%s/%s", r.Repo.Name, suite, component, arch)
}

func (r *Runner) readPublishedState() (model.RepositoryState, error) {
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
		for _, component := range suite.Components {
			for _, arch := range r.Repo.Architectures {
				indexRel, data, err := r.readPublishedIndex(suite.Name, component, arch, hashes)
				if err != nil {
					return out, err
				}
				out.Metadata = append(out.Metadata, model.MetadataFile{Path: path.Join("dists", suite.Name, indexRel), Data: data})
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

func (r *Runner) readPublishedIndex(suite, component, arch string, hashes map[string]releaseFile) (string, []byte, error) {
	for _, rel := range []string{path.Join(component, "binary-"+arch, "Packages.xz"), path.Join(component, "binary-"+arch, "Packages.gz"), path.Join(component, "binary-"+arch, "Packages")} {
		want, ok := hashes[rel]
		if !ok {
			continue
		}
		data, err := os.ReadFile(filepathFor(r.Repo.AbsPublishPath, path.Join("dists", suite, rel)))
		if err != nil {
			return "", nil, err
		}
		got := sha256.Sum256(data)
		if int64(len(data)) != want.Size || !strings.EqualFold(hex.EncodeToString(got[:]), want.SHA256) {
			return "", nil, fmt.Errorf("published apt index %s checksum mismatch", rel)
		}
		return rel, data, nil
	}
	return "", nil, fmt.Errorf("no published Packages index for %s/%s/%s", suite, component, arch)
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

func repoStaging(cfg *config.Config, kind, name string) string {
	return path.Join(cfg.Storage.Staging, "repos", kind, name)
}

func filepathFor(root, rel string) string {
	p, _ := safe.Join(root, rel)
	return p
}
