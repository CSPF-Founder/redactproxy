package redact

import (
	"strings"
	"testing"
)

// TestTokenize_IDNDomainNotTruncated guards against a real German domain
// containing "ü" getting its match truncated to "nchen-realtest.de" (an
// ASCII-only character class can't include "ü", so matching would
// restart one character later), with that truncated string stored as
// the token's real value -- silently wrong, not just under-redacted:
// detokenize would restore the wrong domain entirely.
func TestTokenize_IDNDomainNotTruncated(t *testing.T) {
	e, _ := newTestEngine(t)
	in := "contact us at münchen-realtest.de today"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out == in {
		t.Fatal("domain was not redacted at all")
	}
	for _, leak := range []string{"münchen-realtest.de", "nchen-realtest.de"} {
		if strings.Contains(out, leak) {
			t.Fatalf("real (or truncated-real) domain leaked in output: %q", out)
		}
	}
	back := e.Detokenize(out)
	if back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestTokenize_ZeroWidthCharMidLabelNotTruncated is the same bug via an
// invisible character (rather than a real Unicode letter) sitting
// between two halves of one continuous domain -- a human reading
// "xyzexample<ZWSP>hiddenchartest.com" perceives ONE word, so the token's
// stored real value must be the whole thing, not just the suffix after
// the invisible break.
func TestTokenize_ZeroWidthCharMidLabelNotTruncated(t *testing.T) {
	e, _ := newTestEngine(t)
	in := "visit xyzexample\u200bhiddenchartest.com now"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "xyzexample") {
		t.Fatalf("prefix before the invisible char leaked unredacted: %q", out)
	}
	back := e.Detokenize(out)
	if back != in {
		t.Fatalf("round-trip mismatch (invisible char lost from stored value):\n  in:   %q\n  back: %q", in, back)
	}
}

// TestTokenize_ZeroWidthCharAtDotBoundaryStillDetected covers an
// invisible character sitting exactly between a label and the TLD dot,
// which breaks the regex's own literal "." expectation -- NEITHER half
// matches at all, a complete miss rather than a partial one.
func TestTokenize_ZeroWidthCharAtDotBoundaryStillDetected(t *testing.T) {
	e, _ := newTestEngine(t)
	in := "see hiddenchartest\u200b.com now"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "hiddenchartest") {
		t.Fatalf("domain leaked entirely unredacted: %q", out)
	}
	back := e.Detokenize(out)
	if back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestTokenize_RTLOverrideWrapDoesNotCorruptSuffix guards against
// extending a match through an invisible character touching its edge:
// for a domain WRAPPED in a RIGHT-TO-LEFT OVERRIDE / POP DIRECTIONAL
// FORMATTING pair, folding the trailing mark into the stored real value
// would mean that value no longer literally ends in ".com", so the
// domain's own structure-preserving format() (which re-appends ".com" as
// literal text around the opaque token) would produce a doubled suffix
// on detokenize (".com<U+202C>.com"). The wrapping marks must stay
// outside the token as literal text -- the same role quotes or backticks
// already play here -- not get folded into what's stored.
func TestTokenize_RTLOverrideWrapDoesNotCorruptSuffix(t *testing.T) {
	e, _ := newTestEngine(t)
	in := "here is the value: \u202ewidgetcorp-fixture.com\u202c -- please use it"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "widgetcorp-fixture.com") {
		t.Fatalf("real domain survived intact in output: %q", out)
	}
	back := e.Detokenize(out)
	if back != in {
		t.Fatalf("round-trip mismatch (doubled suffix regression):\n  in:   %q\n  back: %q", in, back)
	}
}

// TestTokenize_BareDomainAndEmailShareOneToken confirms a real IDN
// domain referenced both as a bare hostname (in a URL) and as an email's
// domain part mint and reuse the SAME token -- the dedup guarantee
// (same real value always maps to the same placeholder) must hold for
// IDN domains exactly as it already does for ASCII ones.
func TestTokenize_BareDomainAndEmailShareOneToken(t *testing.T) {
	e, _ := newTestEngine(t)
	in := "visit https://münchenmün.com and email useraa@münchenmün.com for details"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "münchenmün.com") {
		t.Fatalf("real domain leaked in output: %q", out)
	}

	firstTok := extractDomainToken(t, out)
	occurrences := strings.Count(out, firstTok)
	if occurrences != 2 {
		t.Fatalf("expected the SAME domain token to appear twice (bare URL + email domain), got %d occurrences in: %q", occurrences, out)
	}

	back := e.Detokenize(out)
	if back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// --- negative controls: confirm the widened matching does NOT swallow
// unrelated non-Latin-script prose sitting next to an ASCII domain with
// no space boundary -- these scripts don't use inter-word spacing the
// way Latin-script text does, so matching any Unicode letter (rather
// than Latin specifically) would swallow entire sentences into what
// should be a short domain match. ---

func TestTokenize_CJKProseAdjacentToDomainNotSwallowed(t *testing.T) {
	e, _ := newTestEngine(t)
	in := "这是一个重要的网站cjkfixture-test.com请访问谢谢"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "这是一个重要的网站") || !strings.Contains(out, "请访问谢谢") {
		t.Fatalf("surrounding CJK prose was altered/swallowed: %q", out)
	}
	if strings.Contains(out, "cjkfixture-test.com") {
		t.Fatalf("the actual domain was not redacted: %q", out)
	}
}

func TestTokenize_PureCJKProseNeverFalsePositives(t *testing.T) {
	e, _ := newTestEngine(t)
	in := "这是一段完全没有任何网址的中文句子测试一下"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("ordinary CJK prose with no domain was altered: got %q, want unchanged %q", out, in)
	}
}

func TestTokenize_ArabicAndCyrillicProseAdjacentToDomainNotSwallowed(t *testing.T) {
	e, _ := newTestEngine(t)
	for _, in := range []string{
		"التفاصيلcyrfixture-test.comشكرا",
		"посетитеcyrfixture-test.comсайт",
	} {
		out, err := e.Tokenize(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "cyrfixture-test.com") {
			t.Errorf("domain not redacted in %q: got %q", in, out)
		}
		// The surrounding non-Latin text must survive verbatim -- only
		// the "cyrfixture-test.com" span should ever change.
		if !strings.Contains(out, "التفاصيل") && !strings.Contains(out, "посетите") {
			t.Errorf("surrounding non-Latin prose was altered: %q -> %q", in, out)
		}
	}
}

// extractDomainToken pulls the first "tok<16 hex>" domain token out of s.
func extractDomainToken(t *testing.T, s string) string {
	t.Helper()
	idx := strings.Index(s, "tok")
	if idx == -1 {
		t.Fatalf("no domain token found in: %q", s)
	}
	end := idx + 3
	for end < len(s) && end < idx+3+16 && isHexByte(s[end]) {
		end++
	}
	return s[idx:end]
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}
