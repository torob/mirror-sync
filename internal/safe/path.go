package safe

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

func Rel(p string) (string, error) {
	p = path.Clean(strings.TrimPrefix(p, "/"))
	if p == "." || p == ".." || strings.HasPrefix(p, "../") {
		return "", fmt.Errorf("unsafe relative path %q", p)
	}
	return p, nil
}

func Join(root, rel string) (string, error) {
	rel, err := Rel(rel)
	if err != nil {
		return "", err
	}
	joined := filepath.Join(root, filepath.FromSlash(rel))
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	r, err := filepath.Rel(cleanRoot, abs)
	if err != nil {
		return "", err
	}
	if r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes %s", rel, root)
	}
	return abs, nil
}
