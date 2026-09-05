package redact

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// countingDetector wraps a real Detector and counts how many times
// Detect is actually invoked, the direct way to prove a cache hit
// skips detection entirely, rather than inferring it indirectly from
// timing (which is exactly the kind of thing that's flaky under a
// shared CI machine's noise).
type countingDetector struct {
	inner Detector
	calls *atomic.Int64
}

func (c countingDetector) Detect(text string) ([]Detection, error) {
	c.calls.Add(1)
	return c.inner.Detect(text)
}

func cacheTestEngine(t *testing.T) (*Engine, *atomic.Int64) {
	t.Helper()
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	var calls atomic.Int64
	var wrapped []Detector
	for _, d := range DefaultDetectors() {
		wrapped = append(wrapped, countingDetector{inner: d, calls: &calls})
	}
	return New(store, wrapped...), &calls
}

func TestTokenizeCache_HitSkipsDetectionEntirely(t *testing.T) {
	e, calls := cacheTestEngine(t)
	text := "contact admin@widgetcorp-fixture.com about the AWS key " + awsKeyIDPrefix + "ABCD1234EFGH5678"

	out1, err := e.Tokenize(text)
	if err != nil {
		t.Fatal(err)
	}
	firstCallCount := calls.Load()
	if firstCallCount == 0 {
		t.Fatal("expected detectors to run on the first (cold) call")
	}

	out2, err := e.Tokenize(text)
	if err != nil {
		t.Fatal(err)
	}
	secondCallDelta := calls.Load() - firstCallCount
	if secondCallDelta != 0 {
		t.Errorf("expected zero detector calls on a cache hit for identical text, got %d more calls", secondCallDelta)
	}
	if out2 != out1 {
		t.Errorf("cached output differs from the original: %q vs %q", out1, out2)
	}
}

// TestTokenizeCache_EvictsOldestPastCapacity covers the bound that makes
// this cache safe to leave running for the length of a real engagement:
// a session with many large, mostly-distinct tool outputs must not grow
// it without limit. An LRU that stopped evicting would otherwise look
// exactly like one that worked.
func TestTokenizeCache_EvictsOldestPastCapacity(t *testing.T) {
	c := newTokenizeCache()
	const overshoot = 50
	for i := range tokenizeCacheCapacity + overshoot {
		c.put(fmt.Sprintf("distinct text %d", i), "out", 0)
	}
	if got := c.len(); got != tokenizeCacheCapacity {
		t.Fatalf("cache grew to %d entries; it must stay capped at %d", got, tokenizeCacheCapacity)
	}

	// The oldest entries are the ones that went, and the newest stayed:
	// eviction has to be least-recently-used, not arbitrary, or the
	// entries that actually repeat (the system prompt and CLAUDE.md note,
	// resent on literally every request) would be the ones thrown away.
	if _, ok := c.get("distinct text 0", 0); ok {
		t.Error("expected the oldest entry to have been evicted")
	}
	newest := fmt.Sprintf("distinct text %d", tokenizeCacheCapacity+overshoot-1)
	if _, ok := c.get(newest, 0); !ok {
		t.Error("expected the most recently added entry to still be resident")
	}
}

// TestTokenizeCache_RecentUseDefersEviction confirms the "least recently
// USED" half of the policy: a read counts as use, so a long-lived entry
// that keeps being hit survives a full capacity's worth of churn around
// it. That's the property the cache exists for, since the repeated text
// in a session is read far more often than it's written.
func TestTokenizeCache_RecentUseDefersEviction(t *testing.T) {
	c := newTokenizeCache()
	const keepMe = "the system prompt, resent every turn"
	c.put(keepMe, "out", 0)

	for i := range tokenizeCacheCapacity - 1 {
		c.put(fmt.Sprintf("churn %d", i), "out", 0)
		if _, ok := c.get(keepMe, 0); !ok {
			t.Fatalf("the repeatedly-read entry was evicted after %d insertions", i+1)
		}
	}
	// One more insertion overflows capacity; the entry read on every
	// iteration above must not be the one that goes.
	c.put("churn final", "out", 0)
	if _, ok := c.get(keepMe, 0); !ok {
		t.Fatal("a repeatedly-read entry was evicted ahead of colder ones; eviction is not LRU")
	}
}

func TestTokenizeCache_DifferentTextIsAlwaysAMiss(t *testing.T) {
	e, calls := cacheTestEngine(t)
	if _, err := e.Tokenize("contact admin@widgetcorp-fixture.com"); err != nil {
		t.Fatal(err)
	}
	afterFirst := calls.Load()
	if _, err := e.Tokenize("contact admin@othercorp-fixture.com"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() == afterFirst {
		t.Error("expected different text to still run detection, got zero additional detector calls")
	}
}

// TestTokenizeCache_InvalidatedOnSetDetectors is the correctness test
// for the exact risk a naive cache would introduce: a category gets
// disabled between two calls, and the SAME text, previously redacted,
// must now come back through unredacted, not silently reuse the stale
// pre-disable answer.
func TestTokenizeCache_InvalidatedOnSetDetectors(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	e := New(store, DefaultDetectors()...)
	text := "contact admin@widgetcorp-fixture.com"

	out1, err := e.Tokenize(text)
	if err != nil {
		t.Fatal(err)
	}
	if out1 == text {
		t.Fatal("expected the email to be tokenized on the first call")
	}

	// Disable everything (empty detector set), same as a live rule
	// reload that turns off every category.
	e.SetDetectors(nil)

	out2, err := e.Tokenize(text)
	if err != nil {
		t.Fatal(err)
	}
	if out2 != text {
		t.Errorf("expected the cache to be invalidated after SetDetectors, so the SAME text now passes through untouched (no active detectors); got a stale cached redacted answer instead: %q", out2)
	}
}

// TestTokenizeCache_InvalidatedOnSetAllowPatterns is the same
// correctness test as above, for the other mutation point.
func TestTokenizeCache_InvalidatedOnSetAllowPatterns(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	e := New(store, DefaultDetectors()...)
	text := "clone github.com/our-team/templates"

	out1, err := e.Tokenize(text)
	if err != nil {
		t.Fatal(err)
	}
	if out1 != text {
		t.Fatalf("expected github.com to be allowlisted by default and pass through untouched, got: %q", out1)
	}

	// Clear the allowlist entirely; github.com should now be a normal
	// domain subject to tokenization.
	e.SetAllowPatterns(nil)

	out2, err := e.Tokenize(text)
	if err != nil {
		t.Fatal(err)
	}
	if out2 == text {
		t.Error("expected the cache to be invalidated after SetAllowPatterns, so github.com is now tokenized like any other domain; got a stale cached untouched answer instead")
	}
}

// TestTokenizeCache_PreserveIfUnknownNeverCached is the correctness test
// for the one store-state-dependent case in the tokenize path: a
// path-segment-shaped domain mention's correct output depends on
// whether that registrable domain has been independently established as
// real elsewhere, which can change between two calls with IDENTICAL
// text. Confirms this exact scenario still resolves correctly on a
// second call rather than serving a stale cached answer from before the
// domain became known.
func TestTokenizeCache_PreserveIfUnknownNeverCached(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	e := New(store, DefaultDetectors()...)

	pathText := "redirect target: /xyz/pathseg-fixture.com"

	out1, err := e.Tokenize(pathText)
	if err != nil {
		t.Fatal(err)
	}
	if out1 != pathText {
		t.Fatalf("expected the path-segment domain to be left untouched (not yet an established real value), got: %q", out1)
	}

	// Now establish pathseg-fixture.com as a real value via an ordinary
	// (non-path) mention elsewhere.
	if _, err := e.Tokenize("host pathseg-fixture.com"); err != nil {
		t.Fatal(err)
	}

	// The EXACT same pathText as before; must now be tokenized, since
	// pathseg-fixture.com is a known real value. A stale cache would
	// incorrectly return the untouched answer from before.
	out2, err := e.Tokenize(pathText)
	if err != nil {
		t.Fatal(err)
	}
	if out2 == pathText {
		t.Error("expected the path-segment domain to now be tokenized (registrable domain became known in between), got a stale untouched answer; PreserveIfUnknown text must never be cached")
	}
}

// TestTokenizeCache_StaleGenerationEntryTreatedAsMiss is the direct,
// deterministic test for the mechanism that closes the real race
// SetDetectors/SetAllowPatterns has around their Store-then-clear
// sequence (see tokenizeCache.get's doc comment): those are two
// separate, non-atomic steps, so a concurrent Tokenize call's cache
// lookup can land in the narrow window where the new detector set is
// already active but clear() hasn't run yet, and get back a stale
// pre-reload answer for text it already had cached. Reproducing that
// exact interleaving via goroutine timing would be flaky; this instead
// plants a stale-generation entry directly (exactly what such a call
// would have written) and confirms a lookup under the CURRENT
// generation correctly treats it as a miss rather than serving it.
func TestTokenizeCache_StaleGenerationEntryTreatedAsMiss(t *testing.T) {
	c := newTokenizeCache()
	c.put("some text", "old-answer-computed-under-gen-1", 1)

	if _, ok := c.get("some text", 1); !ok {
		t.Fatal("expected a hit when looking up under the SAME generation it was stored with")
	}
	if _, ok := c.get("some text", 2); ok {
		t.Fatal("expected a miss when looking up under a NEWER generation than the entry was stored with; this is the exact stale-cache-survives-a-reload scenario the generation tag exists to prevent")
	}

	// A fresh put() under the new generation must then be servable.
	c.put("some text", "new-answer-computed-under-gen-2", 2)
	if got, ok := c.get("some text", 2); !ok || got != "new-answer-computed-under-gen-2" {
		t.Fatalf("expected the gen-2 entry to be a hit under gen 2, got value=%q ok=%v", got, ok)
	}
}

// TestEngine_ConcurrentReloadNeverServesStaleGenerationAnswer is the
// same regression at the Engine level: a category enabled specifically
// to close a redaction gap must take effect for text ALREADY seen
// before the reload, not just new text, the exact scenario a
// clear()-only cache invalidation has a live window to get wrong.
func TestEngine_ConcurrentReloadNeverServesStaleGenerationAnswer(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	e := New(store) // no detectors active -- the "category is disabled" starting state
	text := "contact admin@widgetcorp-fixture.com"

	out1, err := e.Tokenize(text)
	if err != nil {
		t.Fatal(err)
	}
	if out1 != text {
		t.Fatalf("expected no redaction with zero active detectors, got: %q", out1)
	}

	// Simulate exactly what a concurrent Tokenize call could have
	// written during SetDetectors' Store-then-clear window: an entry
	// for this text, tagged with the CURRENT (about to be stale)
	// generation, holding the pre-reload (unredacted) answer.
	genBeforeReload := e.gen.Load()
	e.cache.put(text, text, genBeforeReload)

	// Now the operator enables email detection.
	e.SetDetectors(DefaultDetectors())

	out2, err := e.Tokenize(text)
	if err != nil {
		t.Fatal(err)
	}
	if out2 == text {
		t.Fatal("expected the newly-enabled detector to redact this text; got the stale pre-reload cached answer instead, exactly the race this test guards against")
	}
}

func TestTokenizeCache_ConcurrentAccessSafe(t *testing.T) {
	e, _ := cacheTestEngine(t)
	texts := []string{
		"contact admin@widgetcorp-fixture.com",
		"host 104.248.115.96",
		"AWS key " + awsKeyIDPrefix + "ABCD1234EFGH5678",
		"plain text with no PII at all",
	}

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			for _, text := range texts {
				if _, err := e.Tokenize(text); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}

// TestTokenizeCache_RepeatedTextRoundTripsCorrectly confirms caching
// doesn't break the actual redaction contract for the common case: the
// same message resent across many turns must still detokenize back to
// exactly the original text every time, cache hit or not.
func TestTokenizeCache_RepeatedTextRoundTripsCorrectly(t *testing.T) {
	e, _ := cacheTestEngine(t)
	text := buildBenchText(3)

	for i := range 5 {
		out, err := e.Tokenize(text)
		if err != nil {
			t.Fatal(err)
		}
		back := e.Detokenize(out)
		if back != text {
			t.Fatalf("call %d: round-trip mismatch after caching:\n  want: %q\n  got:  %q", i, text, back)
		}
		if strings.Contains(out, "widgetcorp-fixture.com") {
			t.Fatalf("call %d: real value leaked in cached output: %q", i, out)
		}
	}
}

// TestCombinedTokenPatternRe_CaseInsensitivityDoesNotLeak is the
// regression test for the subtlest part of merging tokenPatterns into
// one alternation (see combinedTokenPatternRe's doc comment): the
// Razorpay pattern's bare "(?i)" flag must stay scoped to ONLY its own
// alternative, not leak into every pattern listed after it in the
// combined regex. Checked directly at the regex level (not through
// Detokenize+store); a leaked case-insensitivity flag wouldn't be
// visible through a round-trip test at all, since an over-matched
// candidate with no corresponding store entry just gets left unchanged
// either way, masking the bug rather than exposing it.
func TestCombinedTokenPatternRe_CaseInsensitivityDoesNotLeak(t *testing.T) {
	// Razorpay itself must still match case-insensitively, and that's the
	// one pattern that's actually supposed to.
	razorpayUpper := "RZP_LIVE_FAKEabcdef1234"
	if !combinedTokenPatternRe.MatchString(razorpayUpper) {
		t.Errorf("expected Razorpay's own case-insensitive match to still work, got no match for %q", razorpayUpper)
	}

	// A pattern listed AFTER razorpay in tokenPatterns (custom_block,
	// lowercase-only by construction) must NOT match an uppercased
	// variant of its prefix; if it does, the (?i) flag leaked past
	// razorpay's own alternative into this one.
	customBlockUpper := "TOK-BLOCKED-" + strings.Repeat("AB12CD34", 4)
	if combinedTokenPatternRe.MatchString(customBlockUpper) {
		t.Errorf("case-insensitivity leaked past the Razorpay alternative: uppercased custom-block-shaped text %q matched, but this pattern must be case-sensitive", customBlockUpper)
	}

	// Same check for a pattern listed BEFORE razorpay (AWS key, which
	// requires an UPPERCASE hex suffix specifically, so a lowercased
	// variant must NOT match it).
	awsKeyLower := strings.ToLower(tokenstore.TokenAWSKeyPrefix) + "abcdef1234567890"
	if combinedTokenPatternRe.MatchString(awsKeyLower) {
		t.Errorf("expected the AWS key pattern to stay case-sensitive (requires uppercase hex), got a match for lowercased %q", awsKeyLower)
	}
}

// TestTokenize_NoCrossDetectorContaminationWhenMixed is the direct
// verification for a real architectural question: does one detector's
// own token ever get mistaken by a DIFFERENT detector as new real data
// worth re-tokenizing? Each detector only recognizes its OWN token
// shape (see e.g. awsKeyDetector's "strings.HasPrefix(val,
// tokenstore.TokenAWSKeyPrefix)"); nothing checks "is this ANY kind of
// token" before running. TestAllDetectors_FirstPrinciplesInvariants
// already proves idempotency per entity type in isolation; this test
// mixes many different token types together in one realistic block (the
// actual shape a real conversation has: several different secrets and
// PII types in the same message) and confirms full-text idempotency
// holds across the WHOLE mix, not just one type at a time.
func TestTokenize_NoCrossDetectorContaminationWhenMixed(t *testing.T) {
	e, _ := cacheTestEngine(t)

	text := "contact admin@widgetcorp-fixture.com about the AWS key " + awsKeyIDPrefix + "ABCD1234EFGH5678, " +
		"SSO tenant widgetcorp-fixture.okta.com, password hash 8846f7eaee8fb117ad06bdd830b7586c, " +
		"machine account WORKSTATION01$:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::, " +
		"stripe key " + stripeLivePrefix + "51H8xyzABCDEFGHIJKLMNOPQ, github token " + githubPATPrefix + "16C7e42F292c6912E7710c838347Ae178B4a, " +
		"mongodb://dbadmin:S3cr3tP@ss@10.0.0.5:27017/prod"

	out1, err := e.Tokenize(text)
	if err != nil {
		t.Fatal(err)
	}
	if out1 == text {
		t.Fatal("expected extensive tokenization across this mixed corpus, got it unchanged")
	}

	// Re-tokenize the ALREADY fully-tokenized output; every detector
	// runs again over text containing tokens from every OTHER entity
	// type simultaneously. If any detector cross-contaminated (mistook
	// another's token for new real data of its own type), this second
	// pass would mutate the text further.
	out2, err := e.Tokenize(out1)
	if err != nil {
		t.Fatal(err)
	}
	if out2 != out1 {
		t.Errorf("cross-detector contamination: re-tokenizing mixed already-tokenized text changed it further:\n  pass1: %q\n  pass2: %q", out1, out2)
	}

	back := e.Detokenize(out1)
	if back != text {
		t.Errorf("round-trip mismatch on mixed corpus:\n  want: %q\n  got:  %q", text, back)
	}
}
