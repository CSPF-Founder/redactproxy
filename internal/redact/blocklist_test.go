package redact

import (
	"regexp"
	"strings"
	"testing"
)

func TestBlockDetector_LiteralStringRoundTrip(t *testing.T) {
	e, _ := newCorpusEngine(t)
	e.SetDetectors(append(DefaultDetectors(), NewBlockDetector([]*regexp.Regexp{
		regexp.MustCompile(`(?i)XyzExampleCorp`),
	})))

	in := "the client, XyzExampleCorp, uses widgetcorp-fixture.com"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "XyzExampleCorp") {
		t.Fatalf("block-listed string leaked: %q", out)
	}
	if strings.Contains(out, "widgetcorp-fixture.com") {
		t.Fatalf("real domain leaked: %q", out)
	}
	back := e.Detokenize(out)
	if back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

// TestBlockDetector_SubstringMatchLeavesFragment documents the
// deliberate substring-match behavior for literal block entries: it's
// intentionally NOT anchored to whole words, since the safe failure
// direction for a block list is over-matching, not under-matching, so
// "XyzExampleCorp" matches WITHIN "XyzExampleCorporation" too, redacting only the
// matched substring and leaving the rest as literal trailing text. An
// operator who wants the whole word caught should add it as its own
// entry (exactly what the wizard's per-line prompts encourage).
func TestBlockDetector_SubstringMatchLeavesFragment(t *testing.T) {
	e, _ := newCorpusEngine(t)
	e.SetDetectors(append(DefaultDetectors(), NewBlockDetector([]*regexp.Regexp{
		regexp.MustCompile(`(?i)XyzExampleCorp`),
	})))

	out, err := e.Tokenize("client is XyzExampleCorporation")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "XyzExampleCorp") {
		t.Fatalf("expected the XyzExampleCorp substring redacted even within a longer word, got %q", out)
	}
	if !strings.HasSuffix(out, "oration") {
		t.Fatalf("expected the unmatched 'oration' suffix preserved literally, got %q", out)
	}
}

// TestBlockDetector_RegexPattern confirms a user-supplied regex (not
// just a literal string) works, e.g. an internal ticket/codename ID
// scheme an operator wants redacted wholesale.
func TestBlockDetector_RegexPattern(t *testing.T) {
	e, _ := newCorpusEngine(t)
	e.SetDetectors(append(DefaultDetectors(), NewBlockDetector([]*regexp.Regexp{
		regexp.MustCompile(`PROJ-\d{4}`),
	})))

	in := "see ticket PROJ-1234 and PROJ-5678 for details"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "PROJ-1234") || strings.Contains(out, "PROJ-5678") {
		t.Fatalf("regex-matched block entries leaked: %q", out)
	}
	back := e.Detokenize(out)
	if back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestBlockDetector_SurvivesIncompleteBuiltinDomainMatch guards against
// a domain string with an accidentally doubled TLD (e.g. an LLM
// restating a domain in its own write-up and duplicating the suffix by
// mistake, "svc-b.widgetcorp.net.net") fooling the built-in domain
// detector's public-suffix splitting (see splitDomain in
// domainsplit.go) into tokenizing the wrong label, leaving the real
// organization name ("widgetcorp") as literal subdomain-prefix text,
// never redacted at all, by the domain detector OR the block rule
// that should have caught it once the domain detector's earlier-starting
// (but incomplete) match swallowed the whole span in overlap
// resolution.
//
// Fixed at the source (splitDomain now walks past a doubled suffix to
// find the real organization label) rather than by giving block-list
// detections blanket priority over overlapping built-in ones: that
// alternative also closes this leak, but at the cost of silently
// downgrading every domain that happens to overlap a block rule to the
// block detector's fully-opaque token format on every occurrence,
// discarding the subdomain/TLD structure Claude's own reasoning
// benefits from, not just on the rare buggy input. See
// TestSplitDomain_DoubledTLDSuffix for the fix itself; this test
// confirms the end-to-end result through the full detector set,
// including that the redaction still uses the structured domain-token
// format, not the block detector's opaque one.
func TestBlockDetector_SurvivesIncompleteBuiltinDomainMatch(t *testing.T) {
	e, _ := newCorpusEngine(t)
	e.SetDetectors(append(DefaultDetectors(), NewBlockDetector([]*regexp.Regexp{
		regexp.MustCompile(`(?i)widgetcorp`),
	})))

	in := "asset: svc-b.widgetcorp.net.net (Akamai 2nd edge)"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "widgetcorp") {
		t.Fatalf("LEAK: org name survived a doubled-TLD domain match: %q", out)
	}
	if !strings.HasPrefix(out, "asset: svc-b.tok") || !strings.HasSuffix(out, ".net.net (Akamai 2nd edge)") {
		t.Fatalf("expected the structured domain-token format (subdomain prefix and TLD suffix preserved), not the opaque block format, got %q", out)
	}
}

// TestBlockDetector_TokenGluedDirectlyToMoreLetters_StillDetokenizes is
// a regression test for a real leak found live: a model, needing to
// reference a related identifier it hadn't seen tokenized before,
// reused an already-known block token and appended more letters
// directly onto it with no separator (e.g. combining a known token for
// "widgetcorp" with a literal suffix to mean "widgetcorpsubsidiary.
// example"). The detokenize pattern for custom-block tokens was
// anchored \b on both ends; a hex digit immediately followed by a
// letter is a word-to-word transition, which \b never matches, so the
// whole pattern silently failed to match and the raw token leaked
// through un-replaced into what actually got executed. Fixed by
// dropping the trailing \b (kept the leading one) across every
// detokenize pattern that has a fixed-length variable part; see the
// doc comment above domainTokenRe in engine.go for the full reasoning.
func TestBlockDetector_TokenGluedDirectlyToMoreLetters_StillDetokenizes(t *testing.T) {
	e, _ := newCorpusEngine(t)
	e.SetDetectors(append(DefaultDetectors(), NewBlockDetector([]*regexp.Regexp{
		regexp.MustCompile(`(?i)widgetcorp`),
	})))

	tokenized, err := e.Tokenize("client: widgetcorp")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimPrefix(tokenized, "client: ")

	// Model glues more letters directly onto the end of the token, no
	// separator -- exactly what was observed live.
	compound := token + "subsidiary.example"
	out := e.Detokenize("run curl on " + compound)

	if strings.Contains(out, token) {
		t.Fatalf("LEAK: raw block token survived detokenize when glued to trailing letters: %q", out)
	}
	if !strings.Contains(out, "widgetcorpsubsidiary.example") {
		t.Fatalf("expected the token to detokenize even with trailing letters glued on, got %q", out)
	}
}

func TestBlockDetector_Idempotent(t *testing.T) {
	e, _ := newCorpusEngine(t)
	e.SetDetectors(append(DefaultDetectors(), NewBlockDetector([]*regexp.Regexp{
		regexp.MustCompile(`(?i)XyzExampleCorp`),
	})))

	once, err := e.Tokenize("client is XyzExampleCorp")
	if err != nil {
		t.Fatal(err)
	}
	twice, err := e.Tokenize(once)
	if err != nil {
		t.Fatal(err)
	}
	if once != twice {
		t.Fatalf("tokenizing already-tokenized text changed it:\n  once:  %q\n  twice: %q", once, twice)
	}
}
