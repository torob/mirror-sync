package publish

import (
	"bytes"
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

var linkFile = os.Link

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
	if unchanged, err := preserveMatchingFile(final, data); err != nil {
		return err
	} else if unchanged {
		return nil
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

// preserveMatchingFile avoids replacing byte-identical regular files so their
// inode and modification time remain stable. Comparison is streamed because
// metadata such as APKINDEX may already occupy a large in-memory buffer.
func preserveMatchingFile(path string, data []byte) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(data)) {
		return false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return false, nil
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return false, nil
	}

	var buf [128 * 1024]byte
	for offset := 0; offset < len(data); {
		chunk := len(data) - offset
		if chunk > len(buf) {
			chunk = len(buf)
		}
		if _, err := io.ReadFull(f, buf[:chunk]); err != nil {
			return false, nil
		}
		if !bytes.Equal(buf[:chunk], data[offset:offset+chunk]) {
			return false, nil
		}
		offset += chunk
	}
	if openedInfo.Mode() != PublishedFileMode {
		if err := f.Chmod(PublishedFileMode); err != nil {
			return false, err
		}
	}
	return true, nil
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

// MaterializeByHash publishes an immutable hash-addressed copy of a verified
// canonical repository file. It prefers a hard link and falls back to a
// bounded, checksum-verifying copy when links are unavailable.
func MaterializeByHash(root, stagingRoot string, expected model.ByHashFile) error {
	canonical, err := safe.Join(root, expected.CanonicalPath)
	if err != nil {
		return err
	}
	final, err := safe.Join(root, expected.Path)
	if err != nil {
		return err
	}
	if ok, err := verifyRegularNoSymlink(final, expected.Size, expected.Algorithm, expected.Digest); err != nil {
		return err
	} else if ok {
		if err := ensurePublishedDirs(root, filepath.Dir(final)); err != nil {
			return err
		}
		if err := os.Chmod(final, PublishedFileMode); err != nil {
			return err
		}
		return syncFile(final)
	}
	if ok, err := verifyRegularNoSymlink(canonical, expected.Size, expected.Algorithm, expected.Digest); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("canonical file %s does not match %s:%s", expected.CanonicalPath, expected.Algorithm, expected.Digest)
	}

	staged, err := safe.Join(filepath.Join(stagingRoot, "by-hash"), expected.Path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(staged), PublishedDirMode); err != nil {
		return err
	}
	if err := os.Remove(staged); err != nil && !os.IsNotExist(err) {
		return err
	}
	partial := staged + ".partial"
	if err := os.Remove(partial); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := linkFile(canonical, staged); err != nil {
		if err := copyByHash(canonical, partial, expected); err != nil {
			return err
		}
		if err := os.Rename(partial, staged); err != nil {
			os.Remove(partial)
			return err
		}
	}
	complete := false
	defer func() {
		if !complete {
			os.Remove(staged)
			os.Remove(partial)
		}
	}()
	if ok, err := verifyRegularNoSymlink(staged, expected.Size, expected.Algorithm, expected.Digest); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("staged by-hash file %s failed verification", expected.Path)
	}
	if err := os.Chmod(staged, PublishedFileMode); err != nil {
		return err
	}
	if err := syncFile(staged); err != nil {
		return err
	}
	if err := PublishFile(root, staged, final); err != nil {
		return err
	}
	complete = true
	return nil
}

func VerifyByHash(path string, size int64, algorithm, digest string) (bool, error) {
	return verifyRegularNoSymlink(path, size, algorithm, digest)
}

func verifyRegularNoSymlink(file string, size int64, algorithm, digest string) (bool, error) {
	st, err := os.Lstat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !st.Mode().IsRegular() || st.Size() != size {
		return false, nil
	}
	got, err := checksumFile(file, algorithm)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(got, digest), nil
}

func copyByHash(source, destination string, expected model.ByHashFile) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, PublishedFileMode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(destination)
		}
	}()
	h, err := newHash(expected.Algorithm)
	if err != nil {
		return err
	}
	written, err := io.CopyBuffer(io.MultiWriter(out, h), in, make([]byte, 128*1024))
	if err != nil {
		return err
	}
	if written != expected.Size {
		return fmt.Errorf("size mismatch got %d want %d", written, expected.Size)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expected.Digest) {
		return fmt.Errorf("%s mismatch got %s want %s", strings.ToLower(expected.Algorithm), got, expected.Digest)
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func syncFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
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
