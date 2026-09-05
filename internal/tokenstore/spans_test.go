package tokenstore

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestSafeFlushPoint_EmptyTrieFlushesEverything(t *testing.T) {
	s := openTemp(t)
	buf := []byte("just some ordinary text, nothing registered at all")
	if got := s.SafeFlushPoint(buf); got != len(buf) {
		t.Fatalf("expected full flush with no registered spans, got cut point %d of %d", got, len(buf))
	}
}

func TestSafeFlushPoint_HoldsBackGrowingPartialMatch(t *testing.T) {
	s := openTemp(t)
	if err := s.RegisterSpan("tokABCDEF1234567890.com"); err != nil {
		t.Fatal(err)
	}
	buf := []byte("visit tokABCDEF12345")
	got := s.SafeFlushPoint(buf)
	want := len("visit ")
	if got != want {
		t.Fatalf("expected cut point %d (before the growing span), got %d: %q", want, got, buf[got:])
	}
}

func TestSafeFlushPoint_FlushesCompleteMatchWithNoLongerSpan(t *testing.T) {
	s := openTemp(t)
	if err := s.RegisterSpan("AKIAFAKEFACF313CDF66"); err != nil {
		t.Fatal(err)
	}
	// Nothing else registered shares this prefix, so once the full span
	// has arrived there's nothing left it could still be growing into.
	buf := []byte("the key is AKIAFAKEFACF313CDF66 today")
	if got := s.SafeFlushPoint(buf); got != len(buf) {
		t.Fatalf("expected full flush of a complete, unambiguous span, got cut point %d of %d: %q", got, len(buf), buf[got:])
	}
}

func TestSafeFlushPoint_AmbiguousSharedPrefixHeldBackUntilResolved(t *testing.T) {
	s := openTemp(t)
	// Two registered spans sharing a common prefix: "tok-bearer-AAAA" is
	// itself a complete, valid span, but "tok-bearer-AAAABBBB" is a
	// DIFFERENT, longer registered span that also starts with it. Until
	// more bytes arrive (or fail to), the shorter one can't be safely
	// flushed on its own.
	if err := s.RegisterSpan("tok-bearer-AAAA"); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterSpan("tok-bearer-AAAABBBB"); err != nil {
		t.Fatal(err)
	}
	buf := []byte("see tok-bearer-AAAA")
	got := s.SafeFlushPoint(buf)
	want := len("see ")
	if got != want {
		t.Fatalf("expected the ambiguous complete-but-extensible match held back to %d, got %d: %q", want, got, buf[got:])
	}
	// Once it diverges from the longer span, it's unambiguous again.
	buf2 := []byte("see tok-bearer-AAAAzzzz")
	if got := s.SafeFlushPoint(buf2); got != len(buf2) {
		t.Fatalf("expected full flush once the match diverged from the longer span, got cut point %d of %d: %q", got, len(buf2), buf2[got:])
	}
}

func TestSafeFlushPoint_UnrelatedTextNeverHeldBack(t *testing.T) {
	s := openTemp(t)
	if err := s.RegisterSpan("tokABCDEF1234567890.com"); err != nil {
		t.Fatal(err)
	}
	buf := []byte("we went together to the store")
	if got := s.SafeFlushPoint(buf); got != len(buf) {
		t.Fatalf("expected no false hold-back on unrelated prose, got cut point %d of %d: %q", got, len(buf), buf[got:])
	}
}

func TestRegisterSpan_SurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.RegisterSpan("tokABCDEF1234567890.com"); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulates a proxy restart mid-engagement: a fresh Store instance
	// over the same file must still protect a span registered by an
	// earlier process lifetime, or a token minted before the restart
	// would silently lose streaming-safety coverage.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	buf := []byte("visit tokABCDEF12345")
	got := s2.SafeFlushPoint(buf)
	want := len("visit ")
	if got != want {
		t.Fatalf("expected the reloaded span to still be protected, cut point %d, got %d: %q", want, got, buf[got:])
	}
}

func TestRegisterSpan_RepeatedRegistrationIsNoop(t *testing.T) {
	s := openTemp(t)
	if err := s.RegisterSpan("tokABCDEF1234567890.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterSpan("tokABCDEF1234567890.com"); err != nil {
		t.Fatal(err)
	}
	if n := countPersistedSpans(t, s); n != 1 {
		t.Fatalf("expected exactly one span registered after a repeat call, got %d", n)
	}
}

// countPersistedSpans reports how many spans s has persisted. Checked
// against the bucket rather than any in-memory field: the trie is a set,
// so a redundant insert is invisible in it by construction, and what
// this test is actually pinning is that a repeat registration doesn't
// accumulate a second entry anywhere.
func countPersistedSpans(t *testing.T, s *Store) int {
	t.Helper()
	n := 0
	if err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSpans).ForEach(func(_, _ []byte) error {
			n++
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSafeFlushPoint_NoDegenerationUnderManyTinyDeltas proves that
// checking on every single-byte delta never releases a still-growing
// span one fragment at a time: as long as a genuine partial match is in
// progress, the returned cut point must stay pinned to the same
// starting index regardless of how little new data has arrived since
// the last check.
func TestSafeFlushPoint_NoDegenerationUnderManyTinyDeltas(t *testing.T) {
	s := openTemp(t)
	span := "tokABCDEF1234567890.com"
	if err := s.RegisterSpan(span); err != nil {
		t.Fatal(err)
	}

	prefix := "some leading prose before the span arrives "
	full := prefix + span
	lastSpanByte := len(prefix) + len(span) - 1 // the byte that COMPLETES the span
	var buf []byte
	for i := 0; i < len(full); i++ {
		buf = append(buf, full[i])
		got := s.SafeFlushPoint(buf)
		switch {
		case i < len(prefix):
			continue // still just prose, nothing to pin yet
		case i < lastSpanByte:
			// Partially arrived, so it must stay held back to before the span,
			// regardless of how many single-byte deltas it took to get
			// here.
			if got > len(prefix) {
				t.Fatalf("byte %d: expected the growing span to stay held back to <= %d, got %d, a fragment of %q was released early",
					i, len(prefix), got, span)
			}
		default:
			// The byte that completes the span (i == lastSpanByte) makes
			// it whole with nothing else registered that extends past
			// it, so it's safe to flush immediately, not one byte later.
			if got != len(buf) {
				t.Fatalf("byte %d: expected full flush once the complete span had arrived, got cut point %d of %d: %q", i, got, len(buf), buf[got:])
			}
		}
	}
}

func TestMintAndRegisterSpan_SingleLookupBrandNew(t *testing.T) {
	s := openTemp(t)
	buildSpan := func(toks []string) string { return toks[0] + ".example" }

	tokens, err := s.MintAndRegisterSpan([]string{"newdomain.example"}, []EntityType{EntityDomain}, buildSpan)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 || !strings.HasPrefix(tokens[0], TokenDomainPrefix) {
		t.Fatalf("expected one domain-prefixed token, got %v", tokens)
	}

	// Both the token and the composite span must actually be persisted.
	if got, ok := s.LookupToken("newdomain.example"); !ok || got != tokens[0] {
		t.Fatalf("expected token to be persisted, LookupToken = (%q, %v)", got, ok)
	}
	span := buildSpan(tokens)
	buf := []byte("visit " + span[:len(span)-2])
	if got := s.SafeFlushPoint(buf); got == len(buf) {
		t.Fatalf("expected the registered span to be protected by SafeFlushPoint, but it flushed everything")
	}
}

func TestMintAndRegisterSpan_AllAlreadyKnownIsNoop(t *testing.T) {
	s := openTemp(t)
	buildSpan := func(toks []string) string { return toks[0] + ".example" }
	first, err := s.MintAndRegisterSpan([]string{"newdomain.example"}, []EntityType{EntityDomain}, buildSpan)
	if err != nil {
		t.Fatal(err)
	}

	// Second call with the same real value: buildSpan must be called
	// (to check whether the span itself is already known) but nothing
	// should be re-minted, and the returned token must be identical.
	second, err := s.MintAndRegisterSpan([]string{"newdomain.example"}, []EntityType{EntityDomain}, buildSpan)
	if err != nil {
		t.Fatal(err)
	}
	if first[0] != second[0] {
		t.Fatalf("expected the same token on repeat call, got %q then %q", first[0], second[0])
	}
}

func TestMintAndRegisterSpan_MixedKnownAndNewLookups(t *testing.T) {
	// Mirrors the email case: one lookup (the domain) already minted via
	// a prior bare-domain mention, the other (the local part) brand new
	// in this call; both must resolve correctly and the composite span
	// must combine them.
	s := openTemp(t)
	domainTok, err := s.GetOrCreateToken("widgetcorp-fixture.com", EntityDomain)
	if err != nil {
		t.Fatal(err)
	}

	buildSpan := func(toks []string) string { return toks[0] + "@" + toks[1] }
	tokens, err := s.MintAndRegisterSpan(
		[]string{"admin@widgetcorp-fixture.com", "widgetcorp-fixture.com"},
		[]EntityType{EntityEmailLocal, EntityDomain},
		buildSpan,
	)
	if err != nil {
		t.Fatal(err)
	}
	if tokens[1] != domainTok {
		t.Fatalf("expected the already-known domain token to be reused, got %q want %q", tokens[1], domainTok)
	}
	if !strings.HasPrefix(tokens[0], TokenEmailLocalPrefix) {
		t.Fatalf("expected a freshly minted email-local token, got %q", tokens[0])
	}
	if got, ok := s.LookupToken("admin@widgetcorp-fixture.com"); !ok || got != tokens[0] {
		t.Fatalf("expected the new email-local token to be persisted, LookupToken = (%q, %v)", got, ok)
	}
}

func TestMintAndRegisterSpan_TokenAlreadyKnownButSpanIsNew(t *testing.T) {
	// The network-token case: the SAME token can legitimately produce a
	// genuinely NEW composite span on a later call (a different host
	// octet within an already-known /24); this must still register.
	s := openTemp(t)
	netTok, err := s.GetOrCreateToken("10.0.0", EntityIPNetwork)
	if err != nil {
		t.Fatal(err)
	}

	buildSpanFor := func(host string) func([]string) string {
		return func(toks []string) string { return toks[0] + "." + host }
	}
	tokens, err := s.MintAndRegisterSpan([]string{"10.0.0"}, []EntityType{EntityIPNetwork}, buildSpanFor("77"))
	if err != nil {
		t.Fatal(err)
	}
	if tokens[0] != netTok {
		t.Fatalf("expected the already-known network token to be reused, got %q want %q", tokens[0], netTok)
	}

	span := netTok + ".77"
	buf := []byte("host " + span[:len(span)-1])
	if got := s.SafeFlushPoint(buf); got == len(buf) {
		t.Fatalf("expected the new composite span %q to be registered and protected, but it flushed everything", span)
	}
}

func TestMintAndRegisterSpan_FailureRollsBackEverything(t *testing.T) {
	// Exhaust the IP-network token pool (256 slots -- see nextIPNetwork)
	// first, then attempt a MULTI-lookup mint where the SECOND lookup is
	// the one that fails, proving the FIRST lookup's mint doesn't get
	// persisted as an orphan when the overall call fails, unlike what two
	// separate GetOrCreateToken calls would do. Phone tokens used to be
	// the convenient small pool for triggering this on purpose, but
	// nanpFakeAreaCodes widened that pool enough that exhausting it here
	// would be impractically slow; the IP-network pool is still small and
	// unchanged, so it takes over this role.
	s := openTemp(t)
	for i := 0; i < 256; i++ {
		if _, err := s.GetOrCreateToken(fmt.Sprintf("10.0.%d", i), EntityIPNetwork); err != nil {
			t.Fatalf("mint #%d: %v", i, err)
		}
	}

	buildSpan := func(toks []string) string { return toks[0] + "|" + toks[1] }
	_, err := s.MintAndRegisterSpan(
		[]string{"newdomain-for-rollback-test.example", "10.1.0"},
		[]EntityType{EntityDomain, EntityIPNetwork},
		buildSpan,
	)
	if err == nil {
		t.Fatal("expected an error from the exhausted IP-network pool, got nil")
	}

	// The domain lookup (first in the list, would have succeeded on its
	// own) must NOT have been persisted; the whole transaction rolled
	// back together.
	if _, ok := s.LookupToken("newdomain-for-rollback-test.example"); ok {
		t.Fatal("expected the domain lookup to be rolled back along with the failed IP-network mint, but it was persisted")
	}
}

func TestMintAndRegisterSpan_ConcurrentCallsForSameNewValueMintOnce(t *testing.T) {
	s := openTemp(t)
	buildSpan := func(toks []string) string { return toks[0] + ".example" }

	const n = 20
	results := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			tokens, err := s.MintAndRegisterSpan([]string{"racedomain.example"}, []EntityType{EntityDomain}, buildSpan)
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = tokens[0]
		}(i)
	}
	wg.Wait()

	for i := 1; i < n; i++ {
		if results[i] != results[0] {
			t.Fatalf("expected every concurrent call to resolve to the same token, got %q and %q", results[0], results[i])
		}
	}
}

// TestMintAndRegisterSpan_ManyDifferentConcurrentValuesNoDeadlock guards
// the lock-ordering invariant documented on MintAndRegisterSpan: its
// slow-path transaction must never acquire spansMu while holding
// bbolt's internal write lock, since RegisterSpan (the fast path below,
// and its own public method) acquires spansMu then starts its own bbolt
// transaction, the opposite order. Two different lock orderings across
// the same two locks from two call paths deadlock as soon as one
// goroutine is inside each at once. This does NOT require identical
// input: racing many callers on the SAME value (see the test above)
// never triggers it, since only one goroutine at a time actually
// reaches the slow path; it needs a MIX of concurrent slow-path (new
// tokens) and fast-path (RegisterSpan-only, for an already-known token
// paired with a new composite) calls in flight together, which this
// test constructs directly rather than relying on timing to produce it.
func TestMintAndRegisterSpan_ManyDifferentConcurrentValuesNoDeadlock(t *testing.T) {
	s := openTemp(t)

	// Pre-seed one network token so some callers can hit the "token
	// known, span new" fast path (RegisterSpan only) while OTHER
	// concurrent callers are still minting brand-new tokens (slow path),
	// the specific interleaving that deadlocked.
	sharedNet, err := s.GetOrCreateToken("10.0.0", EntityIPNetwork)
	if err != nil {
		t.Fatal(err)
	}

	const n = 60
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(i int) {
				defer wg.Done()
				if i%3 == 0 {
					// Fast path: token already known, span (host octet)
					// is new every time.
					buildSpan := func(toks []string) string { return fmt.Sprintf("%s.%d", toks[0], i) }
					if _, err := s.MintAndRegisterSpan([]string{"10.0.0"}, []EntityType{EntityIPNetwork}, buildSpan); err != nil {
						t.Error(err)
					}
					return
				}
				// Slow path: a brand-new domain every time.
				real := fmt.Sprintf("newdomain-%d.example", i)
				buildSpan := func(toks []string) string { return toks[0] + ".example" }
				if _, err := s.MintAndRegisterSpan([]string{real}, []EntityType{EntityDomain}, buildSpan); err != nil {
					t.Error(err)
				}
			}(i)
		}
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("deadlocked: MintAndRegisterSpan calls did not complete within 10s")
	}

	if _, ok := s.LookupToken("10.0.0"); !ok || s.real2token["10.0.0"] != sharedNet {
		t.Fatal("expected the pre-seeded network token to be unaffected")
	}
}
