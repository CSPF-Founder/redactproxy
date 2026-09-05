package tokenstore

import (
	"bytes"
	"sort"
	"strings"
	"testing"
)

// spanTrie backs SafeFlushPoint and AlreadyTokenizedSpans -- the
// streaming-safety and already-tokenized-detection logic Engine leans
// on to never split a still-arriving credential token across two
// separately-flushed chunks (see spanTrie's own doc comment) and to
// never let a different detector re-match a substring inside an
// already-minted token on a later Tokenize call.
//
// Both safeFlushPoint and findFullSpans have a doc comment precisely
// specifying what they must return; that specification is simple enough
// to reimplement directly against the plain list of registered span
// strings (no trie, just substring/prefix checks) as an independent,
// obviously-correct reference -- the same "fast implementation checked
// against a slow-but-clearly-correct one" pattern
// TestApply_FastPathVerifiedAgainstSlowPath and
// FuzzApplyFastSlowPathAgreement already use for jsonwalk.apply.

// bruteForceSafeFlushPoint reimplements spanTrie.safeFlushPoint's own
// doc-comment specification directly against spans, with no trie: the
// leftmost position i in buf such that buf[i:] is a genuine, strict,
// non-empty prefix of some registered span (i.e. that span could still
// be arriving) is where the buffer must be held back; if no such i
// exists, the whole buffer is safe.
func bruteForceSafeFlushPoint(spans []string, buf []byte) int {
	for i := 0; i < len(buf); i++ {
		tail := string(buf[i:])
		for _, s := range spans {
			if len(s) > len(tail) && strings.HasPrefix(s, tail) {
				return i
			}
		}
	}
	return len(buf)
}

// bruteForceFindFullSpans reimplements spanTrie.findFullSpans directly:
// every position where some registered span occurs as a complete,
// already-present substring of text.
func bruteForceFindFullSpans(spans []string, text string) []Span {
	var out []Span
	for _, s := range spans {
		if s == "" {
			continue
		}
		start := 0
		for {
			idx := strings.Index(text[start:], s)
			if idx == -1 {
				break
			}
			pos := start + idx
			out = append(out, Span{Start: pos, End: pos + len(s)})
			start = pos + 1 // overlapping occurrences matter too
		}
	}
	sortSpans(out)
	return out
}

func sortSpans(spans []Span) {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		return spans[i].End < spans[j].End
	})
}

// FuzzSpanTrie fuzzes spanTrie's insert/safeFlushPoint/findFullSpans
// against the brute-force reference above. The fuzzer input is a single
// []byte, deliberately -- go-fuzz only supports a fixed set of scalar
// corpus types, not a slice of strings -- so it's decoded here into a
// realistic (spans, queryBuffer) pair: NUL-delimited parts, every part
// but the last is a span to register, the last is the buffer to query
// safeFlushPoint/findFullSpans against. NUL was picked as the delimiter
// specifically because it can never appear inside any real span this
// proxy ever registers (every one is built from token prefixes, hex,
// and echoed real text, none of which contain a NUL byte) or inside
// realistic response text either, so this decoding doesn't quietly
// exclude any input shape that could occur for real.
//
// Span count and length are capped defensively (not a correctness
// concern, purely to keep the O(spans × len(buf)) brute-force reference
// fast enough for the fuzzer's iteration rate) -- an input exceeding
// either cap is skipped, not treated as a failure.
func FuzzSpanTrie(f *testing.F) {
	for _, seed := range spanFuzzSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		parts := bytes.Split(data, []byte{0})
		if len(parts) < 2 {
			return
		}
		rawSpans, rawBuf := parts[:len(parts)-1], parts[len(parts)-1]
		if len(rawSpans) > 40 || len(rawBuf) > 4096 {
			return
		}

		seen := map[string]bool{}
		var spans []string
		trie := newSpanTrie()
		for _, sp := range rawSpans {
			if len(sp) == 0 || len(sp) > 300 {
				continue
			}
			s := string(sp)
			if seen[s] {
				continue
			}
			seen[s] = true
			spans = append(spans, s)
			trie.insert(s)
		}

		gotFlush := trie.safeFlushPoint(rawBuf)
		wantFlush := bruteForceSafeFlushPoint(spans, rawBuf)
		if gotFlush != wantFlush {
			t.Fatalf("safeFlushPoint disagrees with reference:\n  spans: %q\n  buf:   %q\n  got:   %d\n  want:  %d", spans, rawBuf, gotFlush, wantFlush)
		}
		if gotFlush < 0 || gotFlush > len(rawBuf) {
			t.Fatalf("safeFlushPoint returned out-of-range index %d for a %d-byte buffer", gotFlush, len(rawBuf))
		}

		gotSpans := trie.findFullSpans(string(rawBuf))
		sortSpans(gotSpans)
		wantSpans := bruteForceFindFullSpans(spans, string(rawBuf))
		if !equalSpans(gotSpans, wantSpans) {
			t.Fatalf("findFullSpans disagrees with reference:\n  spans: %q\n  text:  %q\n  got:   %v\n  want:  %v", spans, rawBuf, gotSpans, wantSpans)
		}
	})
}

func equalSpans(a, b []Span) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// spanFuzzSeeds encodes (spans..., queryBuffer) tuples NUL-delimited
// (see FuzzSpanTrie's doc comment) covering: no registered spans, a
// buffer that IS a complete registered span with nothing else in the
// trie extending past it, a buffer that's a still-growing strict prefix
// of a longer span, two spans sharing a long common prefix with the
// buffer sitting exactly at the point they diverge (the "ambiguous
// shared prefix" case each hand-written test already names), a
// completely unrelated buffer, a registered span appearing mid-text
// rather than at the very end (only findFullSpans, not safeFlushPoint,
// should ever see this), overlapping occurrences of the same span,
// duplicate span registration, and spans/buffers containing raw
// non-UTF-8 bytes (a stored real value is never guaranteed to be valid
// UTF-8 -- see Engine.Tokenize's own utf8.ValidString guard).
var spanFuzzSeeds = [][]byte{
	{},
	[]byte{0},
	joinSeed("tok1a2b3c4d5e6f7890.com", "tok1a2b3c4d5e6f7890.com"),
	joinSeed("tok1a2b3c4d5e6f7890.com", "tok1a2b3c4"),
	joinSeed("tok1a2b3c4d5e6f7890.com", "tok1a2b3c4d5e6f7890.co.uk", "tok1a2b3c4d5e6f7890.co"),
	joinSeed("tok1a2b3c4d5e6f7890.com", "completely unrelated text with no relation at all"),
	joinSeed("AKIAFAKEEXAMPLE12345", "prefix text AKIAFAKEEXAMPLE12345 and more AKIAFAKEEXAMPLE12345 twice"),
	joinSeed("tok1a2b3c4d5e6f7890.com", "tok1a2b3c4d5e6f7890.com", "tok1a2b3c4d5e6f7890.com"), // duplicate registration
	joinSeed("aaa", "aaaa"), // overlapping self-similar occurrences
	joinSeed(string([]byte{0xff, 0xfe, 0xfd}), string([]byte{0xff, 0xfe})),
	joinSeed("198.18.1.2", "network prefix 198.18.1"),
	joinSeed("fd00:c0de:ffff:ffff::1234", "fd00:c0de:ffff:ffff:"),
	joinSeed(""), // empty span, should be a no-op
}

func joinSeed(parts ...string) []byte {
	return []byte(strings.Join(parts, "\x00"))
}
