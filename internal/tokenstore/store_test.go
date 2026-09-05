package tokenstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestGetOrCreateToken_Idempotent(t *testing.T) {
	s := openTemp(t)

	tok1, err := s.GetOrCreateToken("example.com", EntityDomain)
	if err != nil {
		t.Fatalf("GetOrCreateToken: %v", err)
	}
	if !strings.HasPrefix(tok1, TokenDomainPrefix) {
		t.Fatalf("token %q does not have prefix %q", tok1, TokenDomainPrefix)
	}

	tok2, err := s.GetOrCreateToken("example.com", EntityDomain)
	if err != nil {
		t.Fatalf("GetOrCreateToken (2nd call): %v", err)
	}
	if tok1 != tok2 {
		t.Fatalf("expected same token on repeat call, got %q then %q", tok1, tok2)
	}

	real, ok := s.LookupReal(tok1)
	if !ok || real != "example.com" {
		t.Fatalf("LookupReal(%q) = (%q, %v), want (example.com, true)", tok1, real, ok)
	}
}

func TestGetOrCreateToken_DistinctValuesDistinctTokens(t *testing.T) {
	s := openTemp(t)

	a, err := s.GetOrCreateToken("example.com", EntityDomain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.GetOrCreateToken("evil.example.com", EntityDomain)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("distinct real values got the same token %q", a)
	}
}

func TestEntityTypeFormats(t *testing.T) {
	s := openTemp(t)

	tests := []struct {
		real   string
		et     EntityType
		verify func(tok string) error
	}{
		{"example.com", EntityDomain, func(tok string) error {
			if !strings.HasPrefix(tok, TokenDomainPrefix) {
				return fmt.Errorf("missing domain prefix: %q", tok)
			}
			return nil
		}},
		{"192.0.2", EntityIPNetwork, func(tok string) error {
			if !strings.HasPrefix(tok, TokenIPNetworkPrefix) {
				return fmt.Errorf("missing IP network prefix: %q", tok)
			}
			return nil
		}},
		{"20010db8000000000000000000000000", EntityIPv6Network, func(tok string) error {
			if !strings.HasPrefix(tok, TokenIPv6NetworkPrefix) {
				return fmt.Errorf("missing IPv6 network prefix: %q", tok)
			}
			return nil
		}},
		{"j.smith", EntityEmailLocal, func(tok string) error {
			if !strings.HasPrefix(tok, TokenEmailLocalPrefix) {
				return fmt.Errorf("missing email local prefix: %q", tok)
			}
			return nil
		}},
		{"555-123-4567", EntityPhone, func(tok string) error {
			// Not HasPrefix: the token is now "<fake area code>-" +
			// TokenPhonePrefix + two digits, not literally starting with
			// TokenPhonePrefix itself; see nanpFakeAreaCodes' doc comment.
			if !strings.Contains(tok, TokenPhonePrefix) {
				return fmt.Errorf("missing phone prefix: %q", tok)
			}
			return nil
		}},
	}

	for _, tt := range tests {
		tok, err := s.GetOrCreateToken(tt.real, tt.et)
		if err != nil {
			t.Fatalf("GetOrCreateToken(%q, %q): %v", tt.real, tt.et, err)
		}
		if err := tt.verify(tok); err != nil {
			t.Errorf("%s: %v", tt.et, err)
		}
	}
}

func TestIPNetworkCounterIncrements(t *testing.T) {
	s := openTemp(t)

	// Keys here are network prefixes (what redact's IPv4 detector passes
	// in, the real address's first three octets), not whole addresses;
	// tokenstore itself is agnostic to what the key represents.
	tok1, err := s.GetOrCreateToken("10.0.0", EntityIPNetwork)
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := s.GetOrCreateToken("10.0.1", EntityIPNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if tok1 == tok2 {
		t.Fatalf("expected distinct network tokens, got %q twice", tok1)
	}
	if tok1 != "198.18.0" {
		t.Fatalf("first network token = %q, want 198.18.0", tok1)
	}
	if tok2 != "198.18.1" {
		t.Fatalf("second network token = %q, want 198.18.1", tok2)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tokens.db")

	s1, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s1.GetOrCreateToken("client-target.example", EntityDomain)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	tok2, err := s2.GetOrCreateToken("client-target.example", EntityDomain)
	if err != nil {
		t.Fatal(err)
	}
	if tok != tok2 {
		t.Fatalf("token changed across reopen: %q vs %q", tok, tok2)
	}

	real, ok := s2.LookupReal(tok)
	if !ok || real != "client-target.example" {
		t.Fatalf("LookupReal after reopen = (%q, %v)", real, ok)
	}
}

// TestConcurrentGetOrCreate_SameValue verifies that many goroutines racing
// to tokenize the SAME real value all converge on exactly one minted token.
// This is the scenario that a naive read-then-write (without the
// double-checked lock in GetOrCreateToken) would get wrong.
func TestConcurrentGetOrCreate_SameValue(t *testing.T) {
	s := openTemp(t)

	const n = 50
	tokens := make([]string, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			tokens[i], errs[i] = s.GetOrCreateToken("race.example.com", EntityDomain)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	first := tokens[0]
	for i, tok := range tokens {
		if tok != first {
			t.Fatalf("goroutine %d got token %q, want %q (all should match)", i, tok, first)
		}
	}
}

// TestConcurrentGetOrCreate_DistinctValues verifies no lost updates /
// silent overwrites when many goroutines mint DIFFERENT values in
// parallel: every value should end up with its own distinct token and all
// should be persisted and lookup-able afterward.
func TestConcurrentGetOrCreate_DistinctValues(t *testing.T) {
	s := openTemp(t)

	const n = 50
	tokens := make([]string, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			real := fmt.Sprintf("host-%d.example.com", i)
			tokens[i], errs[i] = s.GetOrCreateToken(real, EntityDomain)
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
		if seen[tokens[i]] {
			t.Fatalf("duplicate token %q minted for distinct real values", tokens[i])
		}
		seen[tokens[i]] = true
	}

	for i := 0; i < n; i++ {
		real := fmt.Sprintf("host-%d.example.com", i)
		got, ok := s.LookupReal(tokens[i])
		if !ok || got != real {
			t.Errorf("LookupReal(%q) = (%q, %v), want (%q, true)", tokens[i], got, ok, real)
		}
	}
}

// TestPhoneTokenPool_SurvivesFarBeyondOldHundredLimit pins the fix for
// the old design's exhaustion problem: NANP phone tokens used to be
// minted from a single fixed area code's 100-slot 555-01XX block, so a
// 101st distinct real number in one engagement would fail-closed and
// block that request. Tokens are now drawn from nanpFakeAreaCodes'
// spread of area codes combined with that same reserved block, so 500
// distinct real numbers -- five times the old hard limit -- must all
// mint cleanly with no collisions.
func TestPhoneTokenPool_SurvivesFarBeyondOldHundredLimit(t *testing.T) {
	s := openTemp(t)

	seen := make(map[string]bool)
	for i := 0; i < 500; i++ {
		real := fmt.Sprintf("212-555-%04d", 1000+i) // outside the reserved 0100-0199 range itself
		tok, err := s.GetOrCreateToken(real, EntityPhone)
		if err != nil {
			t.Fatalf("mint #%d (%s): %v", i, real, err)
		}
		if seen[tok] {
			t.Fatalf("mint #%d: token %q reused for a different real value", i, tok)
		}
		seen[tok] = true
	}
}

func TestLookupToken_UnknownReturnsFalse(t *testing.T) {
	s := openTemp(t)
	if _, ok := s.LookupToken("never-seen.example.com"); ok {
		t.Fatal("expected LookupToken to report false for an unseen value")
	}
	if _, ok := s.LookupReal("never-seen.tok.internal"); ok {
		t.Fatal("expected LookupReal to report false for an unminted token")
	}
}

func TestList_ReturnsEveryMintedEntryWithMetadata(t *testing.T) {
	s := openTemp(t)

	tokA, err := s.GetOrCreateToken("widgetcorp-fixture.com", EntityDomain)
	if err != nil {
		t.Fatal(err)
	}
	tokB, err := s.GetOrCreateToken("172.20.30", EntityIPNetwork)
	if err != nil {
		t.Fatal(err)
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), entries)
	}

	byReal := map[string]Entry{}
	for _, e := range entries {
		byReal[e.Real] = e
	}
	a, ok := byReal["widgetcorp-fixture.com"]
	if !ok {
		t.Fatalf("missing entry for widgetcorp-fixture.com: %+v", entries)
	}
	if a.Token != tokA || a.EntityType != EntityDomain || a.FirstSeen.IsZero() {
		t.Errorf("unexpected entry for widgetcorp-fixture.com: %+v", a)
	}
	b, ok := byReal["172.20.30"]
	if !ok {
		t.Fatalf("missing entry for 172.20.30: %+v", entries)
	}
	if b.Token != tokB || b.EntityType != EntityIPNetwork || b.FirstSeen.IsZero() {
		t.Errorf("unexpected entry for 172.20.30: %+v", b)
	}
}

func TestList_EmptyStoreReturnsNoEntries(t *testing.T) {
	s := openTemp(t)
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries in a fresh store, got %+v", entries)
	}
}

func TestDelete_RemovesMappingFromBothDirectionsAndList(t *testing.T) {
	s := openTemp(t)

	tok, err := s.GetOrCreateToken("widgetcorp-fixture.com", EntityDomain)
	if err != nil {
		t.Fatal(err)
	}

	removed, err := s.Delete("widgetcorp-fixture.com")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !removed {
		t.Fatal("expected Delete to report true for an existing mapping")
	}

	if _, ok := s.LookupToken("widgetcorp-fixture.com"); ok {
		t.Error("expected LookupToken to no longer find the deleted real value")
	}
	if _, ok := s.LookupReal(tok); ok {
		t.Error("expected LookupReal to no longer resolve the deleted token")
	}
	entries, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected List to be empty after deleting the only entry, got %+v", entries)
	}
}

func TestDelete_UnknownValueReportsFalseNotError(t *testing.T) {
	s := openTemp(t)
	removed, err := s.Delete("never-seen.example.com")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if removed {
		t.Fatal("expected Delete to report false for a value that was never minted")
	}
}

// TestDelete_ThenGetOrCreateMintsAFreshToken pins the documented
// behavior: deleting a mapping does not "free" the old token for reuse
// on the same real value; the next mint gets a brand-new token, since
// a stale token resolving again after being deleted (e.g. re-shown in a
// report already delivered under the old mapping) would be confusing.
func TestDelete_ThenGetOrCreateMintsAFreshToken(t *testing.T) {
	s := openTemp(t)

	first, err := s.GetOrCreateToken("widgetcorp-fixture.com", EntityDomain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Delete("widgetcorp-fixture.com"); err != nil {
		t.Fatal(err)
	}
	second, err := s.GetOrCreateToken("widgetcorp-fixture.com", EntityDomain)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("expected a fresh token after delete+remint, got the same token %q both times", first)
	}
}

// TestIsLockTimeout_TrueForGenuineLockContention uses a short custom
// bolt.Open timeout (not tokenstore.Open's real 5s) so the test stays
// fast while still exercising the genuine bolt.ErrTimeout IsLockTimeout
// must recognize -- bbolt allows only one writer to hold a given path
// open at once.
func TestIsLockTimeout_TrueForGenuineLockContention(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.db")
	holder, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer holder.Close()

	_, err = bolt.Open(path, 0o600, &bolt.Options{Timeout: 50 * time.Millisecond})
	if err == nil {
		t.Fatal("expected a lock-contention error while holder still has the db open, got nil")
	}
	if !IsLockTimeout(err) {
		t.Errorf("IsLockTimeout(%v) = false, want true", err)
	}
}

// TestIsLockTimeout_FalseForOtherErrors pins the other half of
// IsLockTimeout's contract: an Open failure with a completely different
// cause (here, a directory sitting where the db file should be) must
// not be misdiagnosed as "another process has this locked" -- that was
// a real, misleading error message found via testing before this
// function existed to distinguish the two cases.
func TestIsLockTimeout_FalseForOtherErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.db")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := Open(path)
	if err == nil {
		t.Fatal("expected an error opening a directory as a db file, got nil")
	}
	if IsLockTimeout(err) {
		t.Errorf("IsLockTimeout(%v) = true, want false", err)
	}
}
