package safe

import "testing"

func TestRelRejectsEscapes(t *testing.T) {
	for _, input := range []string{"../x", "/../x", ".."} {
		if _, err := Rel(input); err == nil {
			t.Fatalf("Rel(%q) succeeded, want error", input)
		}
	}
}

func TestRelCleansSafePath(t *testing.T) {
	got, err := Rel("/pool/../pool/pkg.deb")
	if err != nil {
		t.Fatal(err)
	}
	if got != "pool/pkg.deb" {
		t.Fatalf("got %q", got)
	}
}
