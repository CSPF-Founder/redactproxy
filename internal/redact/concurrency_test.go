package redact

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// TestTokenize_ConcurrentRequestsSameEngine simulates what the real
// proxy actually does (many HTTP requests in flight at once, all
// calling Tokenize on the SAME *Engine/*Store concurrently), layered on
// top of collectDetections' own internal per-detector goroutines added
// for the performance fix in engine.go. This is a second, independent
// concurrency dimension from that internal parallelism (many external
// callers, each triggering many internal goroutines), and needed its
// own dedicated stress test rather than assuming the internal fix is
// automatically safe under external concurrent load too.
//
// Mixes distinct-per-goroutine real values (exercises concurrent
// GetOrCreateToken minting; bbolt's single-writer semantics need to
// serialize correctly under contention) with one real value SHARED
// across every goroutine (exercises concurrent GetOrCreateToken lookups
// racing against a mint; every goroutine must observe the exact same
// token for it, not a handful of different ones from a race in the
// store's read-then-write path).
func TestTokenize_ConcurrentRequestsSameEngine(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	e := New(store, DefaultDetectors()...)

	const goroutines = 50
	const sharedDomain = "shared-fixture.com"

	results := make([]string, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			text := fmt.Sprintf("request %d: contact admin@unique-fixture-%d.com about %s, key AKIAABCD%04dEFGH5678", i, i, sharedDomain, i)
			out, err := e.Tokenize(text)
			results[i] = out
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: Tokenize error: %v", i, err)
		}
	}

	// Every goroutine's output must contain the SAME token for the
	// shared domain: if concurrent GetOrCreateToken calls raced and
	// each goroutine minted its own token before seeing another's, this
	// would show multiple different tokens for one real value, a
	// correctness bug worse than a crash (silent inconsistent
	// redaction, not a loud failure). Find the token standing in for
	// sharedDomain via the store directly, then confirm every
	// goroutine's output used that exact same one.
	sharedToken, ok := store.LookupToken(sharedDomain)
	if !ok {
		t.Fatal("shared domain was never tokenized at all")
	}
	for i, out := range results {
		count := 0
		for j := 0; j+len(sharedToken) <= len(out); j++ {
			if out[j:j+len(sharedToken)] == sharedToken {
				count++
			}
		}
		if count == 0 {
			t.Errorf("goroutine %d output missing the shared token %q entirely: %q", i, sharedToken, out)
		}
	}

	// Every unique-per-goroutine AWS key must have round-tripped
	// correctly, independent of all the concurrent activity around it.
	for i, out := range results {
		back := e.Detokenize(out)
		want := fmt.Sprintf("request %d: contact admin@unique-fixture-%d.com about %s, key AKIAABCD%04dEFGH5678", i, i, sharedDomain, i)
		if back != want {
			t.Errorf("goroutine %d round-trip mismatch:\n  want: %q\n  got:  %q", i, want, back)
		}
	}
}
