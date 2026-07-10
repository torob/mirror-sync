package model

import "strings"

// Checksums stores the only digest algorithms understood by mirrorsync without
// allocating a map for every repository payload.
type Checksums struct {
	MD5Sum string
	SHA1   string
	SHA256 string
	SHA512 string
}

func (c Checksums) Get(algorithm string) string {
	switch {
	case strings.EqualFold(algorithm, "MD5"), strings.EqualFold(algorithm, "MD5Sum"):
		return c.MD5Sum
	case strings.EqualFold(algorithm, "SHA1"):
		return c.SHA1
	case strings.EqualFold(algorithm, "SHA256"):
		return c.SHA256
	case strings.EqualFold(algorithm, "SHA512"):
		return c.SHA512
	default:
		return ""
	}
}

func (c *Checksums) Set(algorithm, value string) bool {
	if c == nil {
		return false
	}
	switch {
	case strings.EqualFold(algorithm, "MD5"), strings.EqualFold(algorithm, "MD5Sum"):
		c.MD5Sum = value
	case strings.EqualFold(algorithm, "SHA1"):
		c.SHA1 = value
	case strings.EqualFold(algorithm, "SHA256"):
		c.SHA256 = value
	case strings.EqualFold(algorithm, "SHA512"):
		c.SHA512 = value
	default:
		return false
	}
	return true
}

func (c Checksums) Empty() bool {
	return c.MD5Sum == "" && c.SHA1 == "" && c.SHA256 == "" && c.SHA512 == ""
}

type Payload struct {
	Size      int64
	Checksums Checksums
	Verify    func(path string) error
}

// Package is a transient parser result. RepositoryState stores the compact
// Payload value keyed by Package.Path instead of retaining this structure.
type Package struct {
	Path      string
	Size      int64
	Checksums Checksums
	APKHash   string
}

type MetadataFile struct {
	Path       string
	Data       []byte
	SignedLast bool
}

type RepositoryFile struct {
	Path      string
	Size      int64
	Checksums Checksums
}

type ByHashFile struct {
	CanonicalPath string
	Path          string
	Algorithm     string
	Digest        string
	Size          int64
	Checksums     Checksums
}

type RepositoryPlan struct {
	Name          string
	Kind          string
	PublishPath   string
	MetadataFiles int
	Packages      int
	Bytes         int64
	Sources       []string
	PruneFiles    []string
}

type RepositoryState struct {
	Metadata            []MetadataFile
	SelectedFiles       []RepositoryFile
	Files               []RepositoryFile
	ByHashFiles         []ByHashFile
	ByHashEnabled       map[string]bool
	ReleaseFingerprints map[string]string
	Packages            map[string]Payload
}

type OperationStats struct {
	FilesChecked    int
	FilesReused     int
	FilesDownloaded int
	FilesRepaired   int
	BytesDownloaded int64
	FilesPruned     int
}

func (s *OperationStats) Add(other OperationStats) {
	s.FilesChecked += other.FilesChecked
	s.FilesReused += other.FilesReused
	s.FilesDownloaded += other.FilesDownloaded
	s.FilesRepaired += other.FilesRepaired
	s.BytesDownloaded += other.BytesDownloaded
	s.FilesPruned += other.FilesPruned
}
