package redact

import (
	"regexp"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// TestFilterAlreadyTokenized_DomainBlockCollision pins the core case
// filterAlreadyTokenized exists for: a block pattern that happens to
// match a short substring of an already-minted domain token's random
// hex must not corrupt that token when the token is re-scanned on a
// later Tokenize call (conversation history containing a prior turn's
// token, resent and re-checked against a rules.json block entry added
// since). Without the filter, the block detector has no way to know
// the substring it matched sits inside a different entity's token, and
// splices a new opaque token into the middle of it.
func TestFilterAlreadyTokenized_DomainBlockCollision(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(dir + "/tokens.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	base := FilterDetectors(DefaultCategorizedDetectors(), nil)
	e := New(store, base...)

	turn1, err := e.Tokenize("their domain is widgetcorp-fixture.com")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`tok([0-9a-f]{16})\.com`).FindStringSubmatch(turn1)
	if m == nil {
		t.Fatalf("expected a minted domain token in %q", turn1)
	}
	hex := m[1]
	// A 4-char substring of the token's own hex, used as the block
	// value -- stands in for a short block-listed word that happens to
	// be valid hex (real English words like "cafe"/"face"/"beef" all
	// are).
	substr := hex[4:8]

	blockDet := NewBlockDetector([]*regexp.Regexp{regexp.MustCompile(`(?i)` + regexp.QuoteMeta(substr))})
	e2 := New(store, append(append([]Detector{}, base...), blockDet)...)

	turn2Input := turn1 + "\nalso mentioning our internal codename " + substr + " separately"
	turn2, err := e2.Tokenize(turn2Input)
	if err != nil {
		t.Fatal(err)
	}

	wantIntact := "tok" + hex + ".com"
	if !strings.Contains(turn2, wantIntact) {
		t.Errorf("original domain token %q not intact in %q", wantIntact, turn2)
	}

	back := e2.Detokenize(turn2)
	wantBack := "their domain is widgetcorp-fixture.com\nalso mentioning our internal codename " + substr + " separately"
	if back != wantBack {
		t.Errorf("round-trip mismatch:\n  want: %q\n  got:  %q", wantBack, back)
	}

	// The separate, standalone later occurrence of the same literal
	// text must still be redacted -- the fix only protects the span
	// that's provably already a token, never a genuinely different
	// occurrence elsewhere in the text.
	if strings.Contains(turn2, substr) && !strings.Contains(turn2, "tok"+hex) {
		t.Errorf("standalone occurrence of %q leaked unredacted: %q", substr, turn2)
	}
}

// TestFilterAlreadyTokenized_HashDetectorInsideBlockToken covers the
// same class of bug for a BUILT-IN detector, not just the block
// detector: tok-blocked-<32hex> tokens are exactly MD5 length, and
// hashKeywordRe looks for exactly a 32/40/64-hex run near a hash
// keyword. A hash-related keyword (routine in pentest report text)
// appearing near an already-blocked term must not let hashDetector
// re-claim the block token's own hex body as if it were a real hash.
func TestFilterAlreadyTokenized_HashDetectorInsideBlockToken(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(dir + "/tokens.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	base := FilterDetectors(DefaultCategorizedDetectors(), nil)
	blockDet := NewBlockDetector([]*regexp.Regexp{regexp.MustCompile(`(?i)xyzexamplecorp`)})
	e := New(store, append(append([]Detector{}, base...), blockDet)...)

	turn1, err := e.Tokenize("the client is XyzExampleCorp")
	if err != nil {
		t.Fatal(err)
	}
	turn2Input := "dumped NTLM hash for " + turn1 + "'s domain admin"
	turn2, err := e.Tokenize(turn2Input)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(turn2, "tok-blocked-") || strings.Contains(turn2, "FAKEHASH") {
		t.Errorf("block token corrupted into a hash token: %q", turn2)
	}

	back := e.Detokenize(turn2)
	wantBack := "dumped NTLM hash for the client is XyzExampleCorp's domain admin"
	if back != wantBack {
		t.Errorf("round-trip mismatch:\n  want: %q\n  got:  %q", wantBack, back)
	}
}

// TestFilterAlreadyTokenized_NewValueResemblingTokenStillCaught is the
// safety check that matters most: a genuinely new real value that
// merely resembles a token shape, but was never actually minted, must
// still be detected and redacted normally. filterAlreadyTokenized
// checks against the store's actual set of minted spans, never a shape
// heuristic, specifically so this can't happen.
func TestFilterAlreadyTokenized_NewValueResemblingTokenStillCaught(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(dir + "/tokens.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	base := FilterDetectors(DefaultCategorizedDetectors(), nil)
	blockDet := NewBlockDetector([]*regexp.Regexp{regexp.MustCompile(`(?i)xyzexamplecorp`)})
	e := New(store, append(append([]Detector{}, base...), blockDet)...)

	in := "the client is XyzExampleCorp, confirmed via nmap"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "XyzExampleCorp") {
		t.Fatalf("real value leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Errorf("round-trip mismatch: in=%q back=%q", in, back)
	}
}

// TestFilterAlreadyTokenized_AdjacentNotOverlapping pins the boundary
// case: a detection immediately adjacent to (but not overlapping) a
// registered token span must not be filtered.
func TestFilterAlreadyTokenized_AdjacentNotOverlapping(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(dir + "/tokens.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	base := FilterDetectors(DefaultCategorizedDetectors(), nil)
	e := New(store, base...)

	turn1, err := e.Tokenize("their domain is widgetcorp-fixture.com")
	if err != nil {
		t.Fatal(err)
	}

	blockDet := NewBlockDetector([]*regexp.Regexp{regexp.MustCompile(`(?i)xyzexamplecorp`)})
	e2 := New(store, append(append([]Detector{}, base...), blockDet)...)

	// "XyzExampleCorp" sits directly adjacent to the old token with no gap --
	// a different, never-before-seen real value, must still be caught.
	turn2Input := turn1 + "XyzExampleCorp"
	turn2, err := e2.Tokenize(turn2Input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(turn2, "XyzExampleCorp") {
		t.Errorf("adjacent-but-not-overlapping real value leaked: %q", turn2)
	}
}
