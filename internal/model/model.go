package model

type Package struct {
	Path      string
	Size      int64
	SHA256    string
	Checksums map[string]string
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
	SHA256    string
	Checksums map[string]string
}

type ByHashFile struct {
	CanonicalPath string
	Path          string
	Algorithm     string
	Digest        string
	Size          int64
	Checksums     map[string]string
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
	Metadata      []MetadataFile
	Files         []RepositoryFile
	ByHashFiles   []ByHashFile
	ByHashEnabled map[string]bool
	Packages      map[string]Package
}
