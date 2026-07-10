package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torob/mirror-sync/internal/model"
)

func TestParseIndexStreamsFinalCRLFParagraph(t *testing.T) {
	index := "P:example\r\nV:1.2.3-r0\r\nS:42\r\nC:Q1checksum\r\nD:" + strings.Repeat("ignored", 100_000)
	var packages []model.Package
	if err := parseIndex(strings.NewReader(index), "v3.24/main/x86_64", func(pkg model.Package) error {
		packages = append(packages, pkg)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 {
		t.Fatalf("packages = %d, want 1", len(packages))
	}
	wantPath := "v3.24/main/x86_64/example-1.2.3-r0.apk"
	if packages[0].Path != wantPath || packages[0].Size != 42 || packages[0].APKHash != "Q1checksum" {
		t.Fatalf("package = %#v", packages[0])
	}
}

func TestControlSegmentSHA1StreamsSignedControlMember(t *testing.T) {
	signature := gzipTarMember(t, ".SIGN.RSA.test.rsa.pub", []byte("signature"))
	controlBody := bytes.Repeat([]byte("control-data"), 1<<18)
	control := gzipTarMember(t, ".PKGINFO", controlBody)
	file := filepath.Join(t.TempDir(), "package.apk")
	if err := os.WriteFile(file, append(signature, control...), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := controlSegmentSHA1(file)
	if err != nil {
		t.Fatal(err)
	}
	want := sha1.Sum(control)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("control checksum = %x, want %x", got, want)
	}
}

func gzipTarMember(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
