package redact

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// newTestEngineWithDetectors builds an Engine over a fresh store using
// exactly the given detectors, for tests that need a filtered/custom
// subset rather than the full default set.
func newTestEngineWithDetectors(t *testing.T, detectors []Detector) (*Engine, *tokenstore.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatalf("tokenstore.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return New(store, detectors...), store
}

func TestDefaultCategorizedDetectors_MatchesDefaultDetectors(t *testing.T) {
	cats := DefaultCategorizedDetectors()
	def := DefaultDetectors()
	if len(cats) != len(def) {
		t.Fatalf("count mismatch: categorized=%d default=%d; DefaultDetectors must stay a pure projection of DefaultCategorizedDetectors", len(cats), len(def))
	}
}

func TestDefaultCategorizedDetectors_NoDuplicateNames(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range DefaultCategorizedDetectors() {
		name := c.Name()
		if seen[name] {
			t.Errorf("duplicate category.subcategory name: %s", name)
		}
		seen[name] = true
	}
}

func TestFilterDetectors_DisableWholeCategory(t *testing.T) {
	cats := DefaultCategorizedDetectors()
	filtered := FilterDetectors(cats, map[string]bool{"cloud": true})

	// Every cloud.* subcategory should be gone; everything else present.
	var wantMinus int
	for _, c := range cats {
		if c.Category == "cloud" {
			wantMinus++
		}
	}
	if len(filtered) != len(cats)-wantMinus {
		t.Fatalf("expected %d detectors after disabling category 'cloud', got %d", len(cats)-wantMinus, len(filtered))
	}
}

func TestFilterDetectors_DisableSingleSubcategory(t *testing.T) {
	cats := DefaultCategorizedDetectors()
	filtered := FilterDetectors(cats, map[string]bool{"cloud.aws": true})

	if len(filtered) != len(cats)-1 {
		t.Fatalf("expected exactly one detector removed, got %d removed", len(cats)-len(filtered))
	}

	// Confirm it's specifically AWS detection that's gone: an AWS key
	// should no longer be caught, but another cloud subcategory
	// (DigitalOcean) still is.
	e, _ := newTestEngineWithDetectors(t, filtered)
	out, err := e.Tokenize("key AKIAIOSFODNN7EXAMPLE and token dop_v1_" + repeatHex(64))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("expected AWS key to survive untouched (category disabled), got %q", out)
	}
	if strings.Contains(out, "dop_v1_"+repeatHex(64)) {
		t.Errorf("expected DigitalOcean token to still be redacted (different subcategory), got %q", out)
	}
}

func repeatHex(n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[i%len(hex)]
	}
	return string(b)
}
