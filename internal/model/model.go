package model

type Package struct {
	Path    string
	Size    int64
	SHA256  string
	APKHash string
}

type MetadataFile struct {
	Path       string
	Data       []byte
	SignedLast bool
}

type RepositoryFile struct {
	Path   string
	Size   int64
	SHA256 string
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
	Metadata []MetadataFile
	Files    []RepositoryFile
	Packages map[string]Package
}
