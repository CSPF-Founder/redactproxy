package redact

import (
	"bytes"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/debuglog"
	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

func newTestEngine(t *testing.T) (*Engine, *tokenstore.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatalf("tokenstore.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return New(store, DefaultDetectors()...), store
}

// TestTokenize_DebugLog_ReplacementUsesFullVisibleTextNotBareToken
// confirms the debug log's "replacement" event logs the full wire-
// visible text, not the bare stored token key alone (e.g.
// "tok6a44f00e1999f85d"): a domain's real, preserved suffix is appended
// outside that key ("tok6a44f00e1999f85d.co"), and the wire text always
// has the suffix attached, so logging only the bare key would make it
// unsearchable against a Full-tier body dump.
func TestTokenize_DebugLog_ReplacementUsesFullVisibleTextNotBareToken(t *testing.T) {
	e, store := newTestEngine(t)
	var buf bytes.Buffer
	e.SetDebugLogger(debuglog.New(debuglog.Replacements, &buf))

	out, err := e.Tokenize("contact widgetcorp-fixture.co about renewal")
	if err != nil {
		t.Fatal(err)
	}

	tok, ok := store.LookupToken("widgetcorp-fixture.co")
	if !ok {
		t.Fatal("expected the domain to have been tokenized")
	}
	fullVisible := tok + ".co"
	if !strings.Contains(out, fullVisible) {
		t.Fatalf("expected %q in the tokenized output, got %q", fullVisible, out)
	}

	// Isolate the "replacement" event line specifically -- its "token"
	// field is the wire-visible form. ("new_value" also carries the
	// wire-visible form, but in a separate "wire_value" field alongside
	// the still-bare "token" -- see
	// TestTokenize_DebugLog_NewValueAlsoCarriesWireVisibleForm.)
	replLine := grepLine(t, buf.String(), `"event":"replacement"`)
	if !strings.Contains(replLine, `"token":"`+fullVisible+`"`) {
		t.Fatalf("expected the replacement event's token field to be the FULL visible wire text %q, got: %s", fullVisible, replLine)
	}
	if strings.Contains(replLine, `"token":"`+tok+`"`) {
		t.Fatalf("replacement event still has the bare stored key %q instead of the full visible text: %s", tok, replLine)
	}
}

// TestTokenize_DebugLog_NewValueAlsoCarriesWireVisibleForm covers
// "new_value" events the same way TestTokenize_DebugLog_
// ReplacementUsesFullVisibleTextNotBareToken covers "replacement"
// events: the bare stored key alone ("tok6a44f00e1999f85d") isn't what
// appears on the wire for a domain ("tok6a44f00e1999f85d.co"), so a
// "new_value" line needs to be grepable against a Full-tier body dump
// too. Unlike "replacement", "new_value"'s "token" field still
// deliberately stays
// the bare canonical key (the token store's stable identity for this
// value) -- the wire-visible form is added as a separate "wire_value"
// field alongside it, so both are available without losing either.
func TestTokenize_DebugLog_NewValueAlsoCarriesWireVisibleForm(t *testing.T) {
	e, store := newTestEngine(t)
	var buf bytes.Buffer
	e.SetDebugLogger(debuglog.New(debuglog.NewValues, &buf))

	_, err := e.Tokenize("contact widgetcorp-fixture.co about renewal")
	if err != nil {
		t.Fatal(err)
	}

	tok, ok := store.LookupToken("widgetcorp-fixture.co")
	if !ok {
		t.Fatal("expected the domain to have been tokenized")
	}
	fullVisible := tok + ".co"

	newValLine := grepLine(t, buf.String(), `"event":"new_value"`)
	if !strings.Contains(newValLine, `"token":"`+tok+`"`) {
		t.Fatalf("expected new_value's token field to stay the bare stored key %q, got: %s", tok, newValLine)
	}
	if !strings.Contains(newValLine, `"wire_value":"`+fullVisible+`"`) {
		t.Fatalf("expected new_value's wire_value field to be the FULL visible wire text %q, got: %s", fullVisible, newValLine)
	}
}

// grepLine returns the first line of s containing substr, failing the
// test if none matches.
func grepLine(t *testing.T, s, substr string) string {
	t.Helper()
	for line := range strings.SplitSeq(s, "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}
	t.Fatalf("no line containing %q in: %s", substr, s)
	return ""
}

// TestDetokenize_DebugLog_ReplacementUsesFullVisibleTextNotBareToken is
// the same check in the reverse direction.
func TestDetokenize_DebugLog_ReplacementUsesFullVisibleTextNotBareToken(t *testing.T) {
	e, store := newTestEngine(t)
	tok, err := store.GetOrCreateToken("widgetcorp-fixture.co", tokenstore.EntityDomain)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	e.SetDebugLogger(debuglog.New(debuglog.Replacements, &buf))

	fullVisible := tok + ".co"
	e.Detokenize("contact " + fullVisible + " about renewal")

	logged := buf.String()
	if !strings.Contains(logged, `"token":"`+fullVisible+`"`) {
		t.Fatalf("expected the debug log's token field to be the FULL visible wire text %q, got: %s", fullVisible, logged)
	}
	if strings.Contains(logged, `"token":"`+tok+`"`) {
		t.Fatalf("debug log still has the bare stored key %q instead of the full visible text: %s", tok, logged)
	}
}

func TestTokenize_URLPreservesSchemeAndPath(t *testing.T) {
	e, _ := newTestEngine(t)

	in := "curl -I -L https://widgetcorp-fixture.com/admin?x=1"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}

	if !strings.HasPrefix(out, "curl -I -L https://") {
		t.Fatalf("scheme/prefix not preserved: %q", out)
	}
	if !strings.HasSuffix(out, "/admin?x=1") {
		t.Fatalf("path/query not preserved: %q", out)
	}
	if strings.Contains(out, "widgetcorp-fixture.com") {
		t.Fatalf("real domain leaked into output: %q", out)
	}
}

func TestTokenize_SubstringCollision_TestComVsLatestCom(t *testing.T) {
	e, _ := newTestEngine(t)

	// "test.com" must not spuriously match inside "latest.com" or vice
	// versa: both are distinct real domains and must get distinct
	// tokens, and neither token substitution should corrupt the other's
	// text.
	in := "targets: test.com and latest.com"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}

	if strings.Contains(out, "test.com") || strings.Contains(out, "latest.com") {
		t.Fatalf("real domains leaked: %q", out)
	}

	// Round-trip: detokenizing should restore both distinct originals.
	back := e.Detokenize(out)
	if back != in {
		t.Fatalf("round-trip mismatch:\n  in:  %q\n  out: %q\n  back: %q", in, out, back)
	}
}

// TestTokenize_EmailSharesOrgTokenWithDomain reflects a deliberate design
// change: an email's domain part is NOT tokenized as its own independent
// entity; it shares the SAME org-token that a bare mention of the
// registrable domain would get, so "admin@widgetcorp-fixture.com" and a
// separate mention of "widgetcorp-fixture.com" resolve to the same fake
// domain, letting Claude see they're the same organization. Only the
// email's local part ("admin") gets its own, separate token.
func TestTokenize_EmailSharesOrgTokenWithDomain(t *testing.T) {
	e, store := newTestEngine(t)

	in := "contact security@widgetcorp-fixture.com, also see widgetcorp-fixture.com directly"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}

	if strings.Contains(out, "widgetcorp-fixture.com") || strings.Contains(out, "security@") {
		t.Fatalf("real email/domain leaked: %q", out)
	}

	orgTok, ok := store.LookupToken("widgetcorp-fixture.com")
	if !ok {
		t.Fatalf("expected the registrable domain to be tokenized")
	}
	if !strings.Contains(out, "@"+orgTok+".com") {
		t.Fatalf("expected the email's domain part to reuse the org token %q, got %q", orgTok, out)
	}
	if _, ok := store.LookupToken("security@widgetcorp-fixture.com"); !ok {
		t.Fatalf("expected the email's local part to be tokenized under the full address as its key")
	}
}

func TestTokenize_SkipsCommonFileExtensions(t *testing.T) {
	e, _ := newTestEngine(t)

	// .txt/.conf/.json aren't real TLDs, so the allowlist rejects them
	// structurally. Not tested here: a handful of two-letter ccTLDs
	// (.md Moldova, .io British Indian Ocean Territory, .co Colombia,
	// .tv Tuvalu, .me Montenegro, .sh Saint Helena, .to Tonga, .ai
	// Anguilla) collide with common extensions/abbreviations by pure
	// coincidence of being both a real country code AND a familiar
	// short word. "notes.md" is genuinely ambiguous between "a Markdown
	// file" and "a domain under Moldova's TLD" from text shape alone.
	// No regex-only approach resolves this; it would need context (a
	// preceding "saved to" vs "visit") to disambiguate.
	in := "wrote output to report_1.5.txt, see settings.conf and results.json"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}
	if out != in {
		t.Fatalf("expected filenames to pass through untouched, got %q", out)
	}
}

func TestTokenize_Idempotent(t *testing.T) {
	e, _ := newTestEngine(t)

	in := "Client target: widgetcorp-fixture.com, contact security@widgetcorp-fixture.com"
	once, err := e.Tokenize(in)
	if err != nil {
		t.Fatalf("Tokenize (1st): %v", err)
	}
	twice, err := e.Tokenize(once)
	if err != nil {
		t.Fatalf("Tokenize (2nd, on already-tokenized text): %v", err)
	}
	if once != twice {
		t.Fatalf("tokenizing already-tokenized text changed it:\n  once:  %q\n  twice: %q", once, twice)
	}
}

func TestRoundTrip_MultipleEntityTypes(t *testing.T) {
	e, _ := newTestEngine(t)

	in := "host 172.20.30.40 (admin@corp-target-fixture.com, +1 555-867-5309) resolves corp-target-fixture.com"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}
	for _, real := range []string{"172.20.30.40", "admin@corp-target-fixture.com", "555-867-5309", "corp-target-fixture.com"} {
		if strings.Contains(out, real) {
			t.Errorf("real value %q leaked into tokenized output: %q", real, out)
		}
	}

	back := e.Detokenize(out)
	if back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

func TestDetokenize_UnknownTokenPassesThroughUnchanged(t *testing.T) {
	e, _ := newTestEngine(t)

	// A token-shaped string this store never minted (e.g. from a
	// different engagement's store) must pass through unchanged rather
	// than erroring or being dropped.
	in := "curl https://tokdeadbeefdeadbeef.com/x"
	out := e.Detokenize(in)
	if out != in {
		t.Fatalf("expected unrecognized token to pass through unchanged, got %q", out)
	}
}

func TestDetokenize_ConsistentAcrossTwoTokenizeCalls(t *testing.T) {
	e, _ := newTestEngine(t)

	// The same real value mentioned in two separate Tokenize calls (e.g.
	// two different turns/messages) must map to the same token both
	// times, so Claude can correlate them across a conversation.
	first, err := e.Tokenize("recon on widgetcorp-fixture.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.Tokenize("re-checking widgetcorp-fixture.com again")
	if err != nil {
		t.Fatal(err)
	}

	extractToken := func(s string) string {
		m := regexp.MustCompile(`tok[0-9a-f]{16}`).FindString(s)
		if m == "" {
			t.Fatalf("no domain token found in %q", s)
		}
		return m
	}
	tok1 := extractToken(first)
	tok2 := extractToken(second)
	if tok1 != tok2 {
		t.Fatalf("same real value got different tokens across calls: %q vs %q", tok1, tok2)
	}
}

// failingDetector simulates a future detector (e.g. LLM-backed) that can
// error, to verify Tokenize fails closed rather than silently treating
// the error as "no detections."
type failingDetector struct{}

func (failingDetector) Detect(text string) ([]Detection, error) {
	return nil, errors.New("simulated detector failure")
}

func TestTokenize_FailsClosedOnDetectorError(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	e := New(store, append(DefaultDetectors(), failingDetector{})...)

	_, err = e.Tokenize("some text with example.com in it")
	if err == nil {
		t.Fatal("expected Tokenize to fail closed when a detector errors, got nil error")
	}
}

func TestTokenize_NoFalsePositiveOnPlainProse(t *testing.T) {
	e, _ := newTestEngine(t)

	in := "The scan completed successfully with no critical findings."
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("plain prose with no PII was modified: %q", out)
	}
}
