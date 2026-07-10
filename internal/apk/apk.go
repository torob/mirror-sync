package apk

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/download"
	"github.com/torob/mirror-sync/internal/httpx"
	"github.com/torob/mirror-sync/internal/model"
	"github.com/torob/mirror-sync/internal/publish"
	"github.com/torob/mirror-sync/internal/safe"
)

type Runner struct {
	Config *config.Config
	Repo   config.APKRepository
	HTTP   *httpx.Factory
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
		Name: r.Repo.Name, Kind: "apk", PublishPath: r.Repo.AbsPublishPath,
		MetadataFiles: len(state.Metadata), Packages: len(state.Packages), Bytes: bytes,
		Sources: r.sourceDescriptions(),
	}, nil
}

func (r *Runner) Sync(ctx context.Context) (model.OperationStats, error) {
	var stats model.OperationStats
	lock, err := publish.AcquireLock(r.Config.Storage.Staging, "apk", r.Repo.Name)
	if err != nil {
		return stats, err
	}
	defer lock.Close()
	state, err := r.fetchState(ctx)
	if err != nil {
		return stats, err
	}
	clients, err := r.payloadClients()
	if err != nil {
		return stats, err
	}
	downloadStats, err := download.EnsureSyncedPayloads(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apk", r.Repo.Name), clients, state.Packages)
	stats.Add(downloadStats)
	if err != nil {
		return stats, fmt.Errorf("apk %s: %w", r.Repo.Name, err)
	}
	if err := publish.PublishMetadata(r.Repo.AbsPublishPath, repoStaging(r.Config, "apk", r.Repo.Name), state.Metadata); err != nil {
		return stats, fmt.Errorf("apk %s: %w", r.Repo.Name, err)
	}
	if r.Config.Sync.Prune {
		removed, err := r.Prune(ctx)
		stats.FilesPruned += len(removed)
		return stats, err
	}
	return stats, nil
}

func (r *Runner) Verify(ctx context.Context) (model.OperationStats, error) {
	var stats model.OperationStats
	lock, err := publish.AcquireLock(r.Config.Storage.Staging, "apk", r.Repo.Name)
	if err != nil {
		return stats, err
	}
	defer lock.Close()
	state, err := r.readPublishedState()
	if err != nil {
		return stats, err
	}
	clients, err := r.payloadClients()
	if err != nil {
		return stats, err
	}
	downloadStats, err := download.EnsureRepairedPayloads(ctx, r.Repo.AbsPublishPath, repoStaging(r.Config, "apk", r.Repo.Name), clients, state.Packages)
	stats.Add(downloadStats)
	if err != nil {
		return stats, fmt.Errorf("apk %s: %w", r.Repo.Name, err)
	}
	return stats, nil
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
	primary, err := r.Config.Source(r.Repo.Name, config.RepoAPK, config.SourcePrimary, 0, r.Repo.PrimarySource)
	if err != nil {
		return model.RepositoryState{}, err
	}
	client, err := r.HTTP.Client(primary)
	if err != nil {
		return model.RepositoryState{}, err
	}
	out := model.RepositoryState{Packages: map[string]model.Payload{}}
	for _, version := range r.Repo.Versions {
		for _, repoName := range version.Repositories {
			for _, arch := range r.Repo.Architectures {
				rel := path.Join(version.Name, repoName, arch, "APKINDEX.tar.gz")
				data, err := client.GetBytes(ctx, rel, 128<<20)
				if err != nil {
					return out, err
				}
				out.Metadata = append(out.Metadata, model.MetadataFile{Path: rel, Data: data, SignedLast: true})
				err = verifyAPKIndex(data, r.Repo.AbsKeysDir, func(index io.Reader) error {
					return parseIndex(index, path.Join(version.Name, repoName, arch), func(pkg model.Package) error {
						addAPKPayload(out.Packages, pkg)
						return nil
					})
				})
				if err != nil {
					return out, fmt.Errorf("apk %s verify or parse %s: %w", r.Repo.Name, rel, err)
				}
			}
		}
	}
	return out, nil
}

func (r *Runner) readPublishedState() (model.RepositoryState, error) {
	out := model.RepositoryState{Packages: map[string]model.Payload{}}
	for _, version := range r.Repo.Versions {
		for _, repoName := range version.Repositories {
			for _, arch := range r.Repo.Architectures {
				rel := path.Join(version.Name, repoName, arch, "APKINDEX.tar.gz")
				data, err := os.ReadFile(filepathFor(r.Repo.AbsPublishPath, rel))
				if err != nil {
					return out, err
				}
				out.Metadata = append(out.Metadata, model.MetadataFile{Path: rel, Data: data, SignedLast: true})
				err = verifyAPKIndex(data, r.Repo.AbsKeysDir, func(index io.Reader) error {
					return parseIndex(index, path.Join(version.Name, repoName, arch), func(pkg model.Package) error {
						addAPKPayload(out.Packages, pkg)
						return nil
					})
				})
				if err != nil {
					return out, err
				}
			}
		}
	}
	return out, nil
}

func verifyAPKIndex(data []byte, keysDir string, consume func(io.Reader) error) error {
	signature, keyName, signed, err := splitSignedGzipTar(data)
	if err != nil {
		return err
	}
	pub, err := loadRSAPublicKey(path.Join(keysDir, keyName))
	if err != nil {
		return err
	}
	sum := sha1.Sum(signed)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, sum[:], signature); err != nil {
		return err
	}
	zr, err := gzip.NewReader(bytes.NewReader(signed))
	if err != nil {
		return err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Name == "APKINDEX" {
			return consume(tr)
		}
	}
	return fmt.Errorf("APKINDEX member not found")
}

func splitSignedGzipTar(data []byte) ([]byte, string, []byte, error) {
	br := bytes.NewReader(data)
	zr, err := gzip.NewReader(br)
	if err != nil {
		return nil, "", nil, err
	}
	zr.Multistream(false)
	sigTar, err := io.ReadAll(zr)
	if err != nil {
		zr.Close()
		return nil, "", nil, err
	}
	if err := zr.Close(); err != nil {
		return nil, "", nil, err
	}
	offset := len(data) - br.Len()
	tr := tar.NewReader(bytes.NewReader(sigTar))
	hdr, err := tr.Next()
	if err != nil {
		return nil, "", nil, err
	}
	if !strings.HasPrefix(hdr.Name, ".SIGN.RSA.") || !strings.HasSuffix(hdr.Name, ".rsa.pub") {
		return nil, "", nil, fmt.Errorf("first tar member is not an RSA signature")
	}
	sig, err := io.ReadAll(tr)
	if err != nil {
		return nil, "", nil, err
	}
	keyName := strings.TrimPrefix(hdr.Name, ".SIGN.RSA.")
	return sig, keyName, data[offset:], nil
}

func loadRSAPublicKey(file string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM public key %s", file)
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported RSA public key %s", file)
}

func parseIndex(reader io.Reader, base string, yield func(model.Package) error) error {
	var name, version, sizeText, checksum string
	finish := func() error {
		defer func() { name, version, sizeText, checksum = "", "", "", "" }()
		if name == "" || version == "" {
			return nil
		}
		size, err := strconv.ParseInt(sizeText, 10, 64)
		if err != nil {
			return err
		}
		rel, err := safe.Rel(path.Join(base, name+"-"+version+".apk"))
		if err != nil {
			return err
		}
		return yield(model.Package{Path: rel, Size: size, APKHash: checksum})
	}
	buffered := bufio.NewReaderSize(reader, 64*1024)
	haveFields := false
	var pending []byte
	for {
		line, prefix, err := buffered.ReadLine()
		if len(pending) > 0 {
			pending = append(pending, line...)
			line = pending
		}
		if prefix {
			if len(pending) == 0 {
				pending = append([]byte(nil), line...)
			}
			continue
		}
		pending = nil
		if len(line) > 0 || err == nil {
			if len(line) == 0 {
				if haveFields {
					if finishErr := finish(); finishErr != nil {
						return finishErr
					}
					haveFields = false
				}
			} else {
				haveFields = true
				key, value, ok := bytes.Cut(line, []byte(":"))
				if ok {
					value = bytes.TrimSpace(value)
					switch string(key) {
					case "P":
						name = string(value)
					case "V":
						version = string(value)
					case "S":
						sizeText = string(value)
					case "C":
						checksum = string(value)
					}
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

func addAPKPayload(payloads map[string]model.Payload, pkg model.Package) {
	checksum := pkg.APKHash
	payloads[pkg.Path] = model.Payload{Size: pkg.Size, Verify: func(file string) error {
		return verifyAPKPayload(file, checksum)
	}}
}

func verifyAPKPayload(file, checksum string) error {
	if checksum == "" {
		return fmt.Errorf("missing APKINDEX C checksum")
	}
	got, err := controlSegmentSHA1(file)
	if err != nil {
		return err
	}
	want, err := decodeAPKChecksum(checksum)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("control checksum mismatch")
	}
	return nil
}

func controlSegmentSHA1(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	first, firstName, err := readGzipMemberHash(f)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(firstName, ".SIGN.") {
		return first, nil
	}
	second, _, err := readGzipMemberHash(f)
	return second, err
}

func readGzipMemberHash(r io.Reader) ([]byte, string, error) {
	cr := &countHashReader{r: r, h: sha1.New()}
	zr, err := gzip.NewReader(cr)
	if err != nil {
		return nil, "", err
	}
	zr.Multistream(false)
	tr := tar.NewReader(zr)
	hdr, err := tr.Next()
	if err == nil {
		_, err = io.Copy(io.Discard, zr)
	}
	closeErr := zr.Close()
	if err != nil {
		return nil, "", err
	}
	if closeErr != nil {
		return nil, "", closeErr
	}
	return cr.h.Sum(nil), hdr.Name, nil
}

type countHashReader struct {
	r io.Reader
	h hashHash
}

func (r *countHashReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.h.Write(p[:n])
	}
	return n, err
}

func (r *countHashReader) ReadByte() (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(r.r, b[:])
	if err != nil {
		return 0, err
	}
	r.h.Write(b[:])
	return b[0], nil
}

type hashHash interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func decodeAPKChecksum(s string) ([]byte, error) {
	if strings.HasPrefix(s, "Q1") {
		s = strings.TrimPrefix(s, "Q1")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func (r *Runner) payloadClients() ([]*httpx.Client, error) {
	sources, err := r.Config.PayloadSources(r.Repo.Name, config.RepoAPK, r.Repo.PrimarySource, r.Repo.MirrorSources)
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
	sources, err := r.Config.PayloadSources(r.Repo.Name, config.RepoAPK, r.Repo.PrimarySource, r.Repo.MirrorSources)
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

func repoStaging(cfg *config.Config, kind, name string) string {
	return path.Join(cfg.Storage.Staging, "repos", kind, name)
}

func filepathFor(root, rel string) string {
	p, _ := safe.Join(root, rel)
	return p
}
