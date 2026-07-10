package publish

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/torob/mirror-sync/internal/model"
)

func TestMetadataPriorityPublishesIndexesBeforeReleaseBeforeSignatures(t *testing.T) {
	files := []model.MetadataFile{
		{Path: "dists/noble/InRelease", SignedLast: true},
		{Path: "dists/noble/Release"},
		{Path: "dists/noble/main/binary-amd64/Packages.xz"},
		{Path: "dists/noble/Release.gpg", SignedLast: true},
	}

	sort.SliceStable(files, func(i, j int) bool {
		pi, pj := metadataPriority(files[i]), metadataPriority(files[j])
		if pi != pj {
			return pi < pj
		}
		return files[i].Path < files[j].Path
	})

	want := []string{
		"dists/noble/main/binary-amd64/Packages.xz",
		"dists/noble/Release",
		"dists/noble/InRelease",
		"dists/noble/Release.gpg",
	}
	for i := range want {
		if files[i].Path != want[i] {
			t.Fatalf("files[%d] = %s, want %s", i, files[i].Path, want[i])
		}
	}
}

func TestAtomicWritePublishesReadableFileAndDirectoriesWithRestrictiveUmask(t *testing.T) {
	oldUmask := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(oldUmask) })

	root := t.TempDir()
	staging := t.TempDir()
	rel := "dists/noble/main/binary-amd64/Packages"
	if err := AtomicWrite(root, staging, rel, []byte("metadata")); err != nil {
		t.Fatal(err)
	}

	assertMode(t, filepath.Join(root, rel), PublishedFileMode)
	assertMode(t, root, PublishedDirMode)
	assertMode(t, filepath.Join(root, "dists"), PublishedDirMode)
	assertMode(t, filepath.Join(root, "dists", "noble"), PublishedDirMode)
	assertMode(t, filepath.Join(root, "dists", "noble", "main", "binary-amd64"), PublishedDirMode)
}

func TestVerifyOptions(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "payload")
	data := []byte("package-a")
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	shaHex := hex.EncodeToString(sum[:])
	sha512Sum := sha512.Sum512(data)
	sha512Hex := hex.EncodeToString(sha512Sum[:])

	tests := []struct {
		name string
		path string
		opts []VerifyOption
		want bool
	}{
		{
			name: "existing regular file without options",
			path: file,
			want: true,
		},
		{
			name: "missing file",
			path: filepath.Join(dir, "missing"),
			want: false,
		},
		{
			name: "directory",
			path: dir,
			want: false,
		},
		{
			name: "matching size",
			path: file,
			opts: []VerifyOption{SizeCheck{Size: int64(len(data))}},
			want: true,
		},
		{
			name: "wrong size",
			path: file,
			opts: []VerifyOption{SizeCheck{Size: 1}},
			want: false,
		},
		{
			name: "matching sha256",
			path: file,
			opts: []VerifyOption{SHA256Check{SHA256: shaHex}},
			want: true,
		},
		{
			name: "matching generic sha512",
			path: file,
			opts: []VerifyOption{ChecksumCheck{Algorithm: "SHA512", Hex: sha512Hex}},
			want: true,
		},
		{
			name: "wrong sha256",
			path: file,
			opts: []VerifyOption{SHA256Check{SHA256: "000000"}},
			want: false,
		},
		{
			name: "empty sha256",
			path: file,
			opts: []VerifyOption{SHA256Check{}},
			want: true,
		},
		{
			name: "nil custom check",
			path: file,
			opts: []VerifyOption{FuncCheck{}},
			want: true,
		},
		{
			name: "passing custom check",
			path: file,
			opts: []VerifyOption{FuncCheck{Check: func(string) error { return nil }}},
			want: true,
		},
		{
			name: "failing custom check",
			path: file,
			opts: []VerifyOption{FuncCheck{Check: func(string) error { return fmt.Errorf("invalid") }}},
			want: false,
		},
		{
			name: "helper constructors",
			path: file,
			opts: []VerifyOption{
				WithSize(int64(len(data))),
				WithSHA256(shaHex),
				WithChecksum("SHA512", sha512Hex),
				WithCheck(func(string) error { return nil }),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.path, tt.opts...)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("Verify() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestMaterializeByHashHardLinksImmutableContent(t *testing.T) {
	oldUmask := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(oldUmask) })

	root := t.TempDir()
	staging := t.TempDir()
	canonicalRel := "dists/noble/main/binary-amd64/Packages"
	canonical := filepath.Join(root, filepath.FromSlash(canonicalRel))
	if err := os.MkdirAll(filepath.Dir(canonical), 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte("old-index")
	if err := os.WriteFile(canonical, data, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	digestHex := hex.EncodeToString(digest[:])
	destinationRel := "dists/noble/main/binary-amd64/by-hash/SHA256/" + digestHex
	expected := model.ByHashFile{
		CanonicalPath: canonicalRel,
		Path:          destinationRel,
		Algorithm:     "SHA256",
		Digest:        digestHex,
		Size:          int64(len(data)),
	}
	if err := MaterializeByHash(root, staging, expected); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, filepath.FromSlash(destinationRel))
	canonicalInfo, err := os.Stat(canonical)
	if err != nil {
		t.Fatal(err)
	}
	destinationInfo, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(canonicalInfo, destinationInfo) {
		t.Fatal("by-hash object is not hard-linked to the canonical file")
	}
	assertMode(t, destination, PublishedFileMode)
	assertMode(t, filepath.Dir(destination), PublishedDirMode)
	if err := os.Chmod(destination, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := MaterializeByHash(root, staging, expected); err != nil {
		t.Fatal(err)
	}
	assertMode(t, destination, PublishedFileMode)
	assertMode(t, filepath.Dir(destination), PublishedDirMode)

	replacement := canonical + ".replacement"
	if err := os.WriteFile(replacement, []byte("new-index"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, canonical); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("by-hash content = %q, want immutable old bytes %q", got, data)
	}
}

func TestMaterializeByHashFallsBackToCopyAndReplacesSymlink(t *testing.T) {
	root := t.TempDir()
	staging := t.TempDir()
	canonicalRel := "dists/noble/main/source/Sources.xz"
	canonical := filepath.Join(root, filepath.FromSlash(canonicalRel))
	if err := os.MkdirAll(filepath.Dir(canonical), 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte("source-index")
	if err := os.WriteFile(canonical, data, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512(data)
	digestHex := hex.EncodeToString(digest[:])
	destinationRel := "dists/noble/main/source/by-hash/SHA512/" + digestHex
	destination := filepath.Join(root, filepath.FromSlash(destinationRel))
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canonical, destination); err != nil {
		t.Fatal(err)
	}

	oldLinkFile := linkFile
	linkFile = func(string, string) error { return errors.New("injected link failure") }
	t.Cleanup(func() { linkFile = oldLinkFile })
	expected := model.ByHashFile{
		CanonicalPath: canonicalRel,
		Path:          destinationRel,
		Algorithm:     "SHA512",
		Digest:        digestHex,
		Size:          int64(len(data)),
	}
	if err := MaterializeByHash(root, staging, expected); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("destination mode = %s, want regular file", info.Mode())
	}
	canonicalInfo, _ := os.Stat(canonical)
	if os.SameFile(canonicalInfo, info) {
		t.Fatal("copy fallback unexpectedly shares the canonical inode")
	}
	if matches, err := VerifyByHash(destination, int64(len(data)), "SHA512", digestHex); err != nil || !matches {
		t.Fatalf("VerifyByHash() = %t, %v", matches, err)
	}
	var partials []string
	err = filepath.WalkDir(staging, func(file string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && filepath.Ext(file) == ".partial" {
			partials = append(partials, file)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(partials) != 0 {
		t.Fatalf("partial files remain: %v", partials)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}
