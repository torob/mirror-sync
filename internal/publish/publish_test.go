package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

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

func TestVerifyOptions(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "payload")
	data := []byte("package-a")
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	shaHex := hex.EncodeToString(sum[:])

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
