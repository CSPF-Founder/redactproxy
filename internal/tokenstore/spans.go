package tokenstore

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// spanTrie is a thread-safe set of exact "wire spans": the literal text
// Tokenize actually substituted into an outbound request (a credential's
// whole token, or a structure-preserving token plus whatever real text
// it kept attached, like a domain token plus its real TLD suffix, or an
// IPv4 network token plus its real host octet).
//
// This exists so SafeFlushPoint can answer "could the tail of this
// streaming buffer be the start of a real credential still arriving?"
// exactly, from the actual set of values that could possibly come back,
// rather than approximating from token shape or a fixed byte margin.
// Every span a response could ever echo was necessarily written here
// first, synchronously, as part of Tokenize substituting it into the
// outbound request (Claude never sees a real value it wasn't first
// handed a token for), so this set is complete by construction for
// anything the model could legitimately reproduce.
type spanTrie struct {
	mu     sync.RWMutex
	root   *spanNode
	maxLen int
}

type spanNode struct {
	children map[byte]*spanNode
	isEnd    bool // true exactly at the node completing a registered span
}

func newSpanTrie() *spanTrie {
	return &spanTrie{root: &spanNode{children: map[byte]*spanNode{}}}
}

// insert adds span to the set and reports whether it was NEW (i.e. not
// already present). Safe to call with a span already present; it's a
// no-op walk down the existing path (isEnd already true), reporting
// false.
//
// The "was it already there?" answer comes from the insert itself,
// under the same lock, rather than from a separate membership set
// checked beforehand: a caller that consults one structure and then
// mutates another can observe "already known" in the window between the
// two, and for RegisterSpan that means reporting success for a span
// that isn't queryable by safeFlushPoint/findFullSpans yet.
func (t *spanTrie) insert(span string) (added bool) {
	if span == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.root
	for i := 0; i < len(span); i++ {
		b := span[i]
		child, ok := n.children[b]
		if !ok {
			child = &spanNode{children: map[byte]*spanNode{}}
			n.children[b] = child
		}
		n = child
	}
	if n.isEnd {
		return false
	}
	n.isEnd = true
	if len(span) > t.maxLen {
		t.maxLen = len(span)
	}
	return true
}

// contains reports whether span is already registered.
func (t *spanTrie) contains(span string) bool {
	if span == "" {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := t.root
	for i := 0; i < len(span); i++ {
		child, ok := n.children[span[i]]
		if !ok {
			return false
		}
		n = child
	}
	return n.isEnd
}

// safeFlushPoint returns the largest N <= len(buf) such that buf[:N] is
// guaranteed to contain no partial prefix of any registered span still
// arriving.
//
// For every candidate start position i in the trailing maxLen-byte
// window (nothing earlier can matter, since no registered span is longer),
// it walks the trie through buf[i:]. Three outcomes:
//   - the walk falls off the trie before reaching the end of buf: buf[i:]
//     isn't the start of any known span at all, not a risk.
//   - the walk survives to the end of buf AND that trie node still has
//     children (some registered span is strictly longer than what's
//     arrived so far): buf[i:] could still be growing, so hold back to i.
//   - the walk survives to the end of buf with NO further children: every
//     span sharing this exact prefix already terminates at or before
//     this length, so nothing more can arrive for it, so not held back.
//
// The leftmost i satisfying the "still growing" case wins, since that's
// the earliest point anything risky could have started. If no such i
// exists anywhere in the window, the whole buffer is safe to flush.
//
// Safe to call on every delta rather than batching: as long as a genuine
// partial match is in progress, this keeps returning the SAME starting
// index i regardless of how little new data has arrived since the last
// call, so the entire partial span stays one contiguous held-back block
// until it's genuinely resolved one way or the other, with no risk of
// slicing a still-arriving token across many small releases. See
// TestSafeFlushPoint_NoDegenerationUnderManyTinyDeltas.
func (t *spanTrie) safeFlushPoint(buf []byte) int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	n := len(buf)
	if t.maxLen == 0 {
		return n
	}
	start := max(n-t.maxLen, 0)
	for i := start; i < n; i++ {
		node := t.root
		matched := true
		for j := i; j < n; j++ {
			child, ok := node.children[buf[j]]
			if !ok {
				matched = false
				break
			}
			node = child
		}
		if !matched {
			continue
		}
		if len(node.children) == 0 {
			// buf[i:] exactly, completely matches a registered span with
			// nothing else in the trie extending past it here: fully
			// resolved, no reason to hold back for this candidate.
			continue
		}
		return i
	}
	return n
}

// Span is a byte range [Start, End) within some text.
type Span struct {
	Start, End int
}

// findFullSpans finds every position in text where a COMPLETE
// registered span occurs, not a still-arriving prefix (safeFlushPoint's
// question), a fully-present, already-known wire span. Used to protect
// an already-minted token (of ANY entity type: a domain token, an AWS
// token, ...) from a DIFFERENT detector matching a substring inside it
// on a later Tokenize call, once that token is sitting in resent
// conversation history and gets re-scanned. See
// Engine.filterAlreadyTokenized's doc comment for the full reasoning.
//
// Unbounded in the number of registered spans (trie lookup cost is
// O(path length), not O(spans)) but, unlike safeFlushPoint, scans every
// starting position across the WHOLE text rather than a maxLen-bounded
// trailing window; a registered span can legitimately appear anywhere
// in a large block of resent history, not just near the end of an
// in-progress streaming buffer. Each starting position bails immediately
// on the first non-matching byte (the common case for the overwhelming
// majority of positions, since every registered span begins with one of
// a small, fixed set of prefix bytes: "t" for "tok...", "A" for
// "AKIAFAKE...", "g" for "ghp_FAKE...", etc.), so the practical cost
// tracks close to text length rather than text length × maxLen.
func (t *spanTrie) findFullSpans(text string) []Span {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.maxLen == 0 {
		return nil
	}
	var out []Span
	for i := 0; i < len(text); i++ {
		node := t.root
		for j := i; j < len(text); j++ {
			child, ok := node.children[text[j]]
			if !ok {
				break
			}
			node = child
			if node.isEnd {
				out = append(out, Span{Start: i, End: j + 1})
			}
		}
	}
	return out
}

// RegisterSpan records span as a wire span that could legitimately come
// back in a streamed response; see spanTrie's doc comment. Persisted
// (best-effort, like GetOrCreateToken) so a proxy restart mid-engagement
// doesn't lose coverage for spans minted in an earlier process lifetime;
// skips the write entirely for a span already known, the common case
// once a value's been seen once.
//
// The "already known" check reads the SAME structure the insert writes
// (the trie), not a separate membership set alongside it. With two
// structures, a caller that had updated the set but not yet the trie
// left a window where this returned nil, i.e. "registered, safe to put
// on the wire", for a span safeFlushPoint/findFullSpans couldn't see
// yet. Two concurrent callers can now both reach the write for one span,
// but bbolt's Put is idempotent, so the worst case is one redundant
// write rather than a gap in streaming-safety coverage.
func (s *Store) RegisterSpan(span string) error {
	if span == "" {
		return nil
	}
	if s.spanTrie.contains(span) {
		return nil // already registered, in this process or a previous one
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSpans).Put([]byte(span), []byte{1})
	}); err != nil {
		return err
	}
	s.spanTrie.insert(span)
	return nil
}

// SafeFlushPoint is the streaming-safety query used by
// redact.Engine.SafeFlushPoint; see spanTrie.safeFlushPoint.
func (s *Store) SafeFlushPoint(buf []byte) int {
	return s.spanTrie.safeFlushPoint(buf)
}

// AlreadyTokenizedSpans is the query used by
// redact.Engine.filterAlreadyTokenized; see spanTrie.findFullSpans.
func (s *Store) AlreadyTokenizedSpans(text string) []Span {
	return s.spanTrie.findFullSpans(text)
}

// MintAndRegisterSpan resolves the token for each (real, entityType)
// pair in reals/types, minting and persisting any not already known,
// exactly like GetOrCreateToken, then computes the composite wire span
// via buildSpan(tokens) (called with the resolved tokens in the same
// order as reals/types) and registers it too.
//
// When anything actually needs writing (a new token, a new span, or
// both), it all happens in ONE bbolt transaction rather than one
// transaction per new token plus a separate one for the span, roughly
// halving the fsync cost of minting a brand-new value. This also makes
// the token and its span consistent by construction: if the process
// died mid-write, a partial commit can't leave a token persisted with
// no streaming-safety coverage for it, since both are in the same
// transaction.
//
// The already-fully-known common case (every real value AND the
// resulting span already registered, the overwhelming majority of
// calls once an engagement has been running a while) costs exactly
// what a LookupToken call per real value would: no transaction, no
// write lock.
//
// Lock ordering is deliberate and load-bearing: the bbolt write
// transaction below never touches the span trie's lock (directly or via
// RegisterSpan) while it's open. RegisterSpan's own ordering is the
// trie's lock, then its own bbolt transaction; if this method's
// transaction also reached for the trie lock while holding bbolt's
// internal write lock, that would be two different lock orderings across
// the same two locks from two call paths: a deadlock under concurrent
// callers resolving different real values at once, not just added
// contention. The transaction below never consults the trie to decide
// whether to skip its write; it always writes the span (bbolt's Put is
// idempotent, so a redundant write in the rare already-known case is
// harmless), and the trie insert happens strictly after both s.mu and
// the transaction have been released. See
// TestMintAndRegisterSpan_ManyDifferentConcurrentValuesNoDeadlock.
//
// mu is held only across the transaction and the real2token/token2real
// mirror update, exactly as long as GetOrCreateToken alone would hold
// it, and released before the trie insert below, which uses its own
// separate lock, so a concurrent LookupToken/GetOrCreateToken call from
// another goroutine only ever waits for one write, not two.
func (s *Store) MintAndRegisterSpan(reals []string, types []EntityType, buildSpan func(tokens []string) string) ([]string, error) {
	tokens := make([]string, len(reals))

	allKnown := true
	for i, real := range reals {
		tok, ok := s.LookupToken(real)
		if !ok {
			allKnown = false
			break
		}
		tokens[i] = tok
	}
	if allKnown {
		if err := s.RegisterSpan(buildSpan(tokens)); err != nil {
			return nil, err
		}
		return tokens, nil
	}

	s.mu.Lock()
	var span string
	err := s.db.Update(func(tx *bolt.Tx) error {
		for i, real := range reals {
			if tok, ok := s.real2token[real]; ok {
				tokens[i] = tok
				continue
			}
			tok, genErr := nextToken(tx, types[i], s.token2real)
			if genErr != nil {
				return fmt.Errorf("mint token for %s: %w", types[i], genErr)
			}
			meta := entityMeta{EntityType: types[i], FirstSeen: time.Now().UTC()}
			metaBytes, jerr := json.Marshal(meta)
			if jerr != nil {
				return jerr
			}
			if err := tx.Bucket(bucketRealToToken).Put([]byte(real), []byte(tok)); err != nil {
				return err
			}
			if err := tx.Bucket(bucketTokenToReal).Put([]byte(tok), []byte(real)); err != nil {
				return err
			}
			if err := tx.Bucket(bucketMeta).Put([]byte(real), metaBytes); err != nil {
				return err
			}
			tokens[i] = tok
		}

		// Does not consult the span trie here; see the doc comment above
		// on lock ordering. Always writes the span; a redundant write in
		// the rare already-known case (a multi-lookup detection minting
		// some new lookups while reusing an already-known one) is
		// harmless since bbolt's Put is idempotent.
		span = buildSpan(tokens)
		return tx.Bucket(bucketSpans).Put([]byte(span), []byte{1})
	})
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("mint and register: %w", err)
	}
	for i, real := range reals {
		s.real2token[real] = tokens[i]
		s.token2real[tokens[i]] = real
	}
	s.mu.Unlock()

	// The trie insert happens strictly after BOTH s.mu and bbolt's write
	// transaction have been released, never nested inside either, for the
	// same lock-ordering reason as above.
	s.spanTrie.insert(span)

	return tokens, nil
}
