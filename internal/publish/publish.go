package publish

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/torob/mirror-sync/internal/model"
	"github.com/torob/mirror-sync/internal/safe"
)

type Lock struct {
	file *os.File
}

const (
	PublishedFileMode os.FileMode = 0o644
	PublishedDirMode  os.FileMode = 0o755
)

func AcquireLock(stagingRoot, kind, name string) (*Lock, error) {
	lockName := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(kind + "-" + name + ".lock")
	lockPath := filepath.Join(stagingRoot, "locks", lockName)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return &Lock{file: f}, nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	defer l.file.Close()
	return unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
}

type VerifyOption interface {
	Verify(path string, stat os.FileInfo) (bool, error)
}

type SizeCheck struct {
	Size int64
}

func (c SizeCheck) Verify(_ string, stat os.FileInfo) (bool, error) {
	return stat.Size() == c.Size, nil
}

type SHA256Check struct {
	SHA256 string
}

func (c SHA256Check) Verify(path string, _ os.FileInfo) (bool, error) {
	if c.SHA256 == "" {
		return true, nil
	}
	got, err := sha256File(path)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(got, c.SHA256), nil
}

type ChecksumCheck struct {
	Algorithm string
	Hex       string
}

func (c ChecksumCheck) Verify(path string, _ os.FileInfo) (bool, error) {
	if c.Hex == "" {
		return true, nil
	}
	got, err := checksumFile(path, c.Algorithm)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(got, c.Hex), nil
}

type FuncCheck struct {
	Check func(path string) error
}

func (c FuncCheck) Verify(path string, _ os.FileInfo) (bool, error) {
	if c.Check == nil {
		return true, nil
	}
	if err := c.Check(path); err != nil {
		return false, nil
	}
	return true, nil
}

func WithSize(size int64) VerifyOption {
	return SizeCheck{Size: size}
}

func WithSHA256(shaHex string) VerifyOption {
	return SHA256Check{SHA256: shaHex}
}

func WithChecksum(algorithm, hex string) VerifyOption {
	return ChecksumCheck{Algorithm: algorithm, Hex: hex}
}

func WithCheck(check func(path string) error) VerifyOption {
	return FuncCheck{Check: check}
}

func Verify(path string, options ...VerifyOption) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !st.Mode().IsRegular() {
		return false, nil
	}
	for _, option := range options {
		if option == nil {
			continue
		}
		ok, err := option.Verify(path, st)
		if err != nil || !ok {
			return ok, err
		}
	}
	return true, nil
}

func sha256File(path string) (string, error) {
	return checksumFile(path, "SHA256")
}

func checksumFile(path, algorithm string) (string, error) {
	h, err := newHash(algorithm)
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func newHash(algorithm string) (hash.Hash, error) {
	switch strings.ToUpper(algorithm) {
	case "MD5", "MD5SUM":
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

func AtomicWrite(root, stagingRoot, rel string, data []byte) error {
	final, err := safe.Join(root, rel)
	if err != nil {
		return err
	}
	tmpDir := filepath.Join(stagingRoot, "metadata-tmp", filepath.Dir(filepath.FromSlash(rel)))
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(tmpDir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, PublishedFileMode); err != nil {
		return err
	}
	if err := ensurePublishedDirs(root, filepath.Dir(final)); err != nil {
		return err
	}
	if err := os.Rename(tmpName, final); err != nil {
		return err
	}
	ok = true
	return syncDir(filepath.Dir(final))
}

func PublishMetadata(root, stagingRoot string, files []model.MetadataFile) error {
	sort.SliceStable(files, func(i, j int) bool {
		pi, pj := metadataPriority(files[i]), metadataPriority(files[j])
		if pi != pj {
			return pi < pj
		}
		return files[i].Path < files[j].Path
	})
	for _, f := range files {
		if err := AtomicWrite(root, stagingRoot, f.Path, f.Data); err != nil {
			return fmt.Errorf("publish metadata %s: %w", f.Path, err)
		}
	}
	return nil
}

func PublishFile(root, staged, final string) error {
	if err := ensurePublishedDirs(root, filepath.Dir(final)); err != nil {
		return err
	}
	if err := os.Chmod(staged, PublishedFileMode); err != nil {
		return err
	}
	if err := os.Rename(staged, final); err != nil {
		return err
	}
	return syncDir(filepath.Dir(final))
}

func ensurePublishedDirs(root, dir string) error {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return err
	}
	dirAbs, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootAbs, dirAbs)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("published directory %s escapes root %s", dirAbs, rootAbs)
	}
	if err := os.MkdirAll(dirAbs, PublishedDirMode); err != nil {
		return err
	}
	cur := rootAbs
	if err := os.Chmod(cur, PublishedDirMode); err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	for _, elem := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, elem)
		if err := os.Chmod(cur, PublishedDirMode); err != nil {
			return err
		}
	}
	return nil
}

func metadataPriority(f model.MetadataFile) int {
	if f.SignedLast {
		return 2
	}
	if filepath.Base(filepath.FromSlash(f.Path)) == "Release" {
		return 1
	}
	return 0
}

func Prune(root string, keep map[string]bool) ([]string, error) {
	var removed []string
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil, nil
	}
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !keep[rel] {
			if err := os.Remove(path); err != nil {
				return err
			}
			removed = append(removed, rel)
		}
		return nil
	}); err != nil {
		return removed, err
	}
	pruneEmptyDirs(root)
	sort.Strings(removed)
	return removed, nil
}

func pruneEmptyDirs(root string) {
	var dirs []string
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && path != root {
			dirs = append(dirs, path)
		}
		return nil
	})
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, dir := range dirs {
		os.Remove(dir)
	}
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
