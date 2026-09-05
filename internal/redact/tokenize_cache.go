package redact

import (
	"container/list"
	"crypto/sha256"
	"sync"
)

// tokenizeCacheCapacity bounds memory in a long-running engagement:
// without a cap, a session with many large, mostly-distinct tool
// outputs over hours would grow this cache without limit. Sized well
// above what a typical conversation's distinct message/tool-result count
// looks like in practice, so the entries that actually matter (the
// system prompt, CLAUDE.md note, and early conversation turns, each
// resent unchanged on every subsequent call) stay resident for the life
// of a normal session rather than getting evicted by churn.
const tokenizeCacheCapacity = 4096

// tokenizeCacheKey is a content hash, not the raw text itself,
// deliberately, so a cache entry never pins a large input string's
// backing array in memory for longer than the call that produced it
// needs it. SHA-256 over correctness-only usage (never used as a
// security boundary), chosen for zero extra dependency (stdlib) and
// negligible cost relative to running ~40 regex detectors over the same
// bytes.
type tokenizeCacheKey [sha256.Size]byte

// tokenizeCache is a bounded LRU from (hash of input text) to its
// Tokenize() output, each entry additionally tagged with the engine
// generation it was computed under. See Engine.Tokenize's doc comment
// for why this is safe: Tokenize is a pure function of (text, detector
// set, allow-patterns), as TestTokenize_DeterministicAcrossManyRuns confirms,
// so the SAME text under the SAME rule configuration always produces
// the SAME output, making content-addressed caching sound as long as a
// lookup only ever accepts an entry computed under the CURRENT
// configuration.
//
// The generation tag, not a bare clear() call, is what actually
// guarantees that: Engine.SetDetectors/SetAllowPatterns swap an
// atomic.Pointer and bump Engine.gen as two separate operations, not
// one atomic step, so a clear()-only scheme has a real window where a
// concurrent Tokenize call's cache lookup can still hit a pre-swap
// entry after the pointer swap has already logically taken effect,
// serving a result computed under a just-disabled category as if it
// were still current, right at the moment an operator enabled that
// category specifically to close a gap. Comparing generations closes
// the window regardless of Store/clear ordering; see get/put's own doc
// comments for why tagging (not timing) is the actual correctness
// mechanism; clear() is still called too, but now purely for
// cache-memory hygiene, not correctness.
//
// Real payoff: Claude Code resends the full conversation history on
// every request (a stateless chat API has no other way to give the
// model prior context), so by turn N of a session, roughly (N-1)/N of
// the total text being scanned is byte-identical to a previous call;
// the system prompt and CLAUDE.md note alone repeat on literally every
// single request. Without this cache, all ~40 detectors re-scan every
// one of those unchanged bytes on every turn, for the entire life of
// the session, for content already known to produce a specific,
// unchanging result.
type tokenizeCache struct {
	mu    sync.Mutex
	ll    *list.List // front = most recently used
	items map[tokenizeCacheKey]*list.Element
}

type tokenizeCacheEntry struct {
	key   tokenizeCacheKey
	value string
	gen   uint64
}

func newTokenizeCache() *tokenizeCache {
	return &tokenizeCache{
		ll:    list.New(),
		items: make(map[tokenizeCacheKey]*list.Element, tokenizeCacheCapacity),
	}
}

// get returns a hit only if the cached entry's generation matches gen;
// see Engine's gen field doc comment for why a bare text->value cache
// without this check has a real race with a live SetDetectors/
// SetAllowPatterns reload, and why comparing generations (not just
// calling clear() at reload time) is what actually closes it.
func (c *tokenizeCache) get(text string, gen uint64) (string, bool) {
	key := sha256.Sum256([]byte(text))
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return "", false
	}
	entry := el.Value.(*tokenizeCacheEntry)
	if entry.gen != gen {
		return "", false // stale generation -- treat as a miss, not an error
	}
	c.ll.MoveToFront(el)
	return entry.value, true
}

func (c *tokenizeCache) put(text, value string, gen uint64) {
	key := sha256.Sum256([]byte(text))
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		entry := el.Value.(*tokenizeCacheEntry)
		entry.value, entry.gen = value, gen
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&tokenizeCacheEntry{key: key, value: value, gen: gen})
	c.items[key] = el
	if c.ll.Len() > tokenizeCacheCapacity {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.items, oldest.Value.(*tokenizeCacheEntry).key)
		}
	}
}

// clear drops every cached entry, called whenever the active detector
// set or allow-pattern list changes, since an entry computed under the
// old configuration may no longer be correct for text that hasn't
// changed a single byte.
func (c *tokenizeCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = make(map[tokenizeCacheKey]*list.Element, tokenizeCacheCapacity)
}

func (c *tokenizeCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
