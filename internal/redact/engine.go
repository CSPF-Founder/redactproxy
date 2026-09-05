package redact

import (
	"cmp"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/CSPF-Founder/redactproxy/internal/debuglog"
	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// Engine performs bidirectional substitution over text using a set of
// pluggable Detectors (for the tokenize/real->token direction) and a
// fixed set of token-namespace patterns (for the detokenize/token->real
// direction, which needs no pluggability, since the token formats are this
// tool's own implementation detail, not user-configurable PII shapes).
//
// The active detector set and allow-list are held behind atomic.Pointer,
// not a plain field, so SetDetectors/SetAllowPatterns can be called
// concurrently with in-flight Tokenize calls: a live rule reload (no
// process restart) swaps them for calls that start afterward, without
// touching a call already in progress or requiring a lock on the hot
// path.
type Engine struct {
	store         *tokenstore.Store
	detectors     atomic.Pointer[[]Detector]
	allowPatterns atomic.Pointer[[]*regexp.Regexp]
	debug         atomic.Pointer[debuglog.Logger]
	cache         *tokenizeCache
	// gen tags which SetDetectors/SetAllowPatterns generation the active
	// config is on; see tokenize_cache.go's doc comment for why the
	// cache compares this per-lookup instead of relying on clear() alone
	// to invalidate stale entries around a live reload. Bumped by
	// SetDetectors/SetAllowPatterns; read once per Tokenize call.
	gen atomic.Uint64
}

// New builds an Engine over store using the given detectors. Pass
// DefaultDetectors() for the standard regex set.
//
// Allow-patterns default to BuiltinAllowPatterns(nil), the curated
// well-known-platform/security-testing-service exclusions active with
// nothing disabled, rather than empty, so a bare New(store,
// DefaultDetectors()...) keeps the same default protective behavior
// DefaultDetectors() implies without a caller also having to know to
// wire in BuiltinAllowPatterns separately. cmd/redactproxy's
// effectiveAllowPatterns still calls SetAllowPatterns explicitly once
// rules.json is loaded, since only then is the real Disabled set known,
// so this default is what's active in between (and for anything
// constructing an Engine directly, e.g. tests, without going through
// that wiring at all).
func New(store *tokenstore.Store, detectors ...Detector) *Engine {
	e := &Engine{store: store, cache: newTokenizeCache()}
	e.detectors.Store(&detectors)
	defaults := BuiltinAllowPatterns(nil)
	e.allowPatterns.Store(&defaults)
	return e
}

// SetDebugLogger sets (or replaces) the optional debug sink; see
// package debuglog. A nil logger (the default) disables debug logging
// entirely, at effectively zero cost per call (Enabled short-circuits on
// a nil *Logger).
func (e *Engine) SetDebugLogger(l *debuglog.Logger) {
	e.debug.Store(l)
}

// SetDetectors atomically replaces the active detector set. Safe to call
// while Tokenize calls are in flight: each call reads the detector set
// once at the start, so this only affects calls that start afterward.
//
// Also bumps the cache generation and clears the tokenize cache (see
// tokenize_cache.go): a cached (text -> output) entry was computed under
// the PREVIOUS detector set, and text that hasn't changed a single byte
// can still need a different result once a category is enabled/disabled.
// Serving a stale cached answer here would silently ignore a live
// rule-reload for any text already seen before the change, exactly the
// kind of under-redaction risk this tool exists to prevent. The
// generation bump is what actually guarantees this (see
// tokenizeCache.get's doc comment for why clear() alone has a race);
// clear() is kept alongside it purely to free the now-permanently-stale
// entries' memory promptly rather than waiting for LRU eviction to get
// around to them.
func (e *Engine) SetDetectors(detectors []Detector) {
	cp := append([]Detector(nil), detectors...)
	e.detectors.Store(&cp)
	e.gen.Add(1)
	e.cache.clear()
}

// SetAllowPatterns atomically replaces the allow-list: any Detection
// with at least one Lookup whose Real value matches one of these
// patterns is dropped entirely before substitution (see Tokenize's
// filterAllowed step), left as literal text even though a detector
// matched it. Whole-detection, not per-lookup: allow-listing a domain
// also leaves an email at that domain untouched, local part included,
// rather than trying to partially redact a Detection whose Format
// function expects every one of its Lookups to have resolved to a real
// token.
//
// Also bumps the cache generation and clears the tokenize cache, for the
// identical reason SetDetectors does; see its doc comment.
func (e *Engine) SetAllowPatterns(patterns []*regexp.Regexp) {
	cp := append([]*regexp.Regexp(nil), patterns...)
	e.allowPatterns.Store(&cp)
	e.gen.Add(1)
	e.cache.clear()
}

// Tokenize replaces every detected real value in text with its token,
// minting new tokens for values seen for the first time. It fails closed:
// if any detector errors, or if the token store fails to mint/persist a
// token for any detected value, Tokenize returns an error and the
// (possibly partially built) string is discarded, and callers must never
// forward text after a Tokenize error, since that could mean real PII
// reaching the model un-redacted.
//
// Checks the tokenize cache first (see tokenize_cache.go): Claude Code
// resends the full conversation history on every API call, so the same
// message/tool-result text (the system prompt and CLAUDE.md note above
// all, which repeat on literally every single request) gets rescanned
// by every detector on every turn without this. A cache hit skips
// collectDetections/filterAllowed/resolveOverlaps and the mint loop
// below entirely, including their debug-log calls: re-logging the exact
// same NewValue/Replacement events every time identical text is resent
// would be noise, not signal, so a cache hit is deliberately silent;
// the first call already logged the real detail.
func (e *Engine) Tokenize(text string) (string, error) {
	// Read once, use for both the lookup below and the store at the end;
	// see Engine.gen's doc comment. Capturing it up front (rather than
	// re-reading at put time) means a concurrent SetDetectors/
	// SetAllowPatterns mid-call can only ever make this call's own
	// result look stale to LATER lookups (a wasted cache slot, safe),
	// never cause it to be miscategorized as valid for a generation it
	// wasn't actually computed under (unsafe).
	gen := e.gen.Load()
	if cached, ok := e.cache.get(text, gen); ok {
		return cached, nil
	}

	// A detector's regex slices a byte span straight out of text without
	// checking it's valid UTF-8, so an invalid byte sequence caught up in
	// a match would be stored verbatim as a token's real value and later
	// corrupt whatever otherwise-valid-UTF-8 output it gets substituted
	// back into on Detokenize. jsonwalk.Tokenize already blocks this at
	// the JSON-body level (gjson's own validity check doesn't reject
	// invalid UTF-8 inside a string value, so that guard is separate);
	// this repeats the check here so any other caller of this lower-level
	// API gets the same protection. Checked only after the cache lookup
	// above (not before it): utf8.ValidString is O(len(text)), and a
	// cache hit means this exact text already passed this same check the
	// first time it was seen and cached, so paying for it again on every
	// repeat of the same text (Claude Code resends full conversation
	// history on every turn) would be pure waste.
	if !utf8.ValidString(text) {
		return "", fmt.Errorf("text contains invalid UTF-8")
	}

	dets, err := e.collectDetections(text)
	if err != nil {
		return "", err
	}
	dets = e.filterAllowed(dets)
	dets = e.filterAlreadyTokenized(dets, text)
	dets = resolveOverlaps(dets)

	result, cacheable, err := e.applyDetections(text, dets)
	if err != nil {
		return "", err
	}

	// Unconditional final pass: re-scan the block patterns against the
	// already-substituted output; see blockListSafetyPass's doc comment
	// for why this needs to exist as a SEPARATE pass rather than relying
	// on resolveOverlaps above to have already handled it.
	result, err = e.blockListSafetyPass(result)
	if err != nil {
		return "", err
	}

	if cacheable {
		e.cache.put(text, result, gen)
	}
	return result, nil
}

// applyDetections substitutes every detection in dets (already
// allow-filtered and overlap-resolved by the caller) into text, minting
// whatever tokens are new. Returns the substituted text and whether the
// result is safe to cache; see Tokenize's doc comment on
// PreserveIfUnknown for why that's sometimes false. Factored out of
// Tokenize so blockListSafetyPass's final pass can reuse the exact same
// mint/format/debug-log path rather than a second, subtly-divergent copy
// of it.
func (e *Engine) applyDetections(text string, dets []Detection) (result string, cacheable bool, err error) {
	cacheable = true

	// PreserveIfUnknown's own contract is "established ... in this call
	// or a prior one" (see its doc comment), but dets is processed
	// strictly in left-to-right text order below to build the output:
	// a path-segment mention earlier in the text than the non-path-
	// segment mention that establishes the same value would otherwise
	// only ever see the "prior one" half of that contract, since its
	// own store lookup runs before the later detection in this same
	// batch has minted anything. Pre-scanning every non-PreserveIfUnknown
	// detection's real values up front (no store writes, just what
	// THIS batch is already going to establish regardless of order)
	// closes that gap without changing the left-to-right output order.
	//
	// Only built when dets actually contains a PreserveIfUnknown entry;
	// a bare-path-segment-shaped domain is a rare match shape, so most
	// calls would otherwise pay for a map allocation and a full scan of
	// every lookup in the batch for a check they never need.
	var establishedThisCall map[string]bool
	for _, d := range dets {
		if d.PreserveIfUnknown {
			establishedThisCall = make(map[string]bool)
			break
		}
	}
	if establishedThisCall != nil {
		for _, d := range dets {
			if d.PreserveIfUnknown {
				continue
			}
			for _, lk := range d.Lookups {
				establishedThisCall[lk.Real] = true
			}
		}
	}

	var sb strings.Builder
	last := 0
	for _, d := range dets {
		if d.PreserveIfUnknown {
			cacheable = false
			_, inStore := e.store.LookupToken(d.Lookups[0].Real)
			if !inStore && !establishedThisCall[d.Lookups[0].Real] {
				// Not already an established real value elsewhere (this
				// call or a prior one), so treat it as a coincidentally
				// domain-shaped path segment, not a real second domain.
				// Leave it as literal text: don't write a replacement,
				// don't advance last, don't mint a token for it.
				continue
			}
		}
		dbg := e.debug.Load()
		wantNewValueLog := dbg.Enabled(debuglog.NewValues) // nil-safe; see Logger.Enabled
		newlyMinted := make([]bool, len(d.Lookups))
		if wantNewValueLog {
			for i, lk := range d.Lookups {
				_, alreadyKnown := e.store.LookupToken(lk.Real)
				newlyMinted[i] = !alreadyKnown
			}
		}

		reals := make([]string, len(d.Lookups))
		types := make([]tokenstore.EntityType, len(d.Lookups))
		for i, lk := range d.Lookups {
			reals[i] = lk.Real
			types[i] = lk.Type
		}
		buildSpan := func(toks []string) string {
			if d.Format != nil {
				return d.Format(toks)
			}
			return toks[0]
		}
		// Mints whatever tokens are new AND registers the resulting
		// wire-visible span (not just the bare stored token; see the
		// comment on dbg.NewValue below for why those differ) in ONE
		// call, before any of it is written into the outbound request,
		// i.e. before Claude ever sees it. See
		// tokenstore.Store.MintAndRegisterSpan's doc comment for why this
		// is one bbolt transaction rather than one per lookup plus a
		// separate one for the span, and tokenstore.spanTrie's doc
		// comment for why registering it here makes the set complete by
		// construction for SafeFlushPoint's purposes. A failure here
		// fails the whole call rather than silently tokenizing without
		// it: an unregistered span is a real gap in streaming-safety
		// coverage, not something to paper over.
		tokens, mintErr := e.store.MintAndRegisterSpan(reals, types, buildSpan)
		if mintErr != nil {
			return "", false, fmt.Errorf("tokenize %q: %w", text[d.Start:d.End], mintErr)
		}
		replacement := buildSpan(tokens)
		// NewValue is logged AFTER Format runs (not inside the mint loop
		// above) specifically so it can carry the actual wire-visible
		// substitution alongside the bare stored key: a domain's key
		// alone ("tok6a44f00e1999f85d") is missing the preserved real
		// suffix ("tok6a44f00e1999f85d.co") that's what's actually
		// visible on the wire, and is what you'd grep a Full-tier body
		// dump for to find this mint event.
		for i, lk := range d.Lookups {
			if newlyMinted[i] {
				dbg.NewValue(string(lk.Type), lk.Real, tokens[i], replacement)
			}
		}
		// Logged once per detection (not per lookup), using the actual
		// matched span and the actual visible substituted text; see
		// above for why bare stored keys aren't logged directly.
		// entity_type uses the first lookup's type: exact for
		// single-lookup detections (domain, IP, credential, ...);
		// for the rare multi-lookup case (email: local part + domain)
		// it's the primary/whole-value type, a reasonable label since
		// the logged text itself already carries the full picture.
		dbg.Replacement("tokenize", string(d.Lookups[0].Type), text[d.Start:d.End], replacement)
		sb.WriteString(text[last:d.Start])
		sb.WriteString(replacement)
		last = d.End
	}
	sb.WriteString(text[last:])
	return sb.String(), cacheable, nil
}

// blockListSafetyPass is an unconditional final backstop: after every
// other detector has run and resolveOverlaps has picked winners among
// overlapping matches, re-scan JUST the block-list patterns against the
// already-substituted output text (not the original input) and redact
// any surviving literal match.
//
// Why this needs to exist as its own pass rather than being handled by
// resolveOverlaps: a block-list detection can lose the overlap race
// against an earlier-starting built-in detection whose OWN substitution
// doesn't actually cover the full span it claims. For example, the domain
// detector only ever tokenizes the single label immediately before the
// recognized public suffix, but its Detection.Start/End spans the WHOLE
// matched hostname. For a multi-level hostname where a block-listed
// value (a customer's own name, say) sits in a label further left than
// that (e.g. an Akamai CNAME target shaped like
// "www.<customer>.<edge-hash>.edgekey.net"), the domain detection's
// wider span suppresses the block detection for "<customer>" even though
// the domain detection's own Format never touches that part of the
// string, leaving the real name in the output untouched.
//
// Giving block-list detections blanket priority over any overlapping
// built-in one would also close this gap, but at the cost of
// downgrading EVERY domain that happens to overlap a block rule to the
// block detector's fully-opaque token format on every occurrence, not
// just the buggy one, losing the subdomain/TLD structure Claude's
// reasoning benefits from. This pass avoids that entirely: it only ever
// looks at what's LEFT in the output
// after every other detector already had its correct chance. For every
// correctly-handled occurrence, the block pattern no longer matches at
// all (the literal text is already gone), so this is a no-op; it only
// fires on genuine survivors. See
// TestEngine_BlockListSafetyPass_CatchesOrgNameInPreservedSubdomainLabel.
func (e *Engine) blockListSafetyPass(text string) (string, error) {
	var patterns []*regexp.Regexp
	for _, d := range *e.detectors.Load() {
		if bd, ok := d.(blockDetector); ok {
			patterns = append(patterns, bd.patterns...)
		}
	}
	if len(patterns) == 0 {
		return text, nil // no block list configured -- nothing to backstop, skip the scan entirely
	}

	dets, err := (blockDetector{patterns: patterns}).Detect(text)
	if err != nil {
		return "", err
	}
	// filterAllowed and filterAlreadyTokenized both apply here too,
	// exactly as they do for the main pass in Tokenize -- allow always
	// wins over block (see
	// TestBuiltinAllowlist_BlockAddDoesNotOverridePerValue), and this
	// pass is JUST as capable of matching a fragment inside an
	// already-minted token (of any entity type, including one freshly
	// minted earlier in this SAME Tokenize call's main pass, already
	// registered by the time this runs) as the main pass's block
	// detections were -- see filterAlreadyTokenized's doc comment. That
	// precedence/protection can't be allowed to quietly differ between
	// the two passes.
	dets = e.filterAllowed(dets)
	dets = e.filterAlreadyTokenized(dets, text)
	if len(dets) == 0 {
		return text, nil
	}
	dets = resolveOverlaps(dets) // in case two block patterns overlap each other
	result, _, err := e.applyDetections(text, dets)
	return result, err
}

// collectDetections runs every active detector concurrently, one
// goroutine each, then merges their results. This is the main cost
// driver for Tokenize on any non-trivial input: every detector does its
// own full regex pass over the whole text regardless of whether it's
// likely to find anything (see the package doc comment: a loose
// candidate regex plus precise validation, not a single combined
// grammar), so scanning cost scales with detector count, not just text
// size, so running all ~37 detectors' regex passes concurrently rather
// than sequentially avoids paying that cost serially on every single
// Tokenize call (see BenchmarkTokenize_* in engine_bench_test.go). Safe
// to parallelize because every Detector implementation is a pure
// function of its `text` argument alone (see the Detector
// interface doc comment): no shared mutable state, no detector reads
// another's output, so nothing here needs synchronization beyond
// collecting each goroutine's own result into its own slice slot.
//
// resolveOverlaps (Tokenize's next step) sorts everything it receives by
// position anyway, so the ORDER detections are merged in here was never
// significant for correctness; goroutine completion order affecting
// merge order changes nothing a caller could observe.
func (e *Engine) collectDetections(text string) ([]Detection, error) {
	detectors := *e.detectors.Load()
	results := make([][]Detection, len(detectors))
	errs := make([]error, len(detectors))

	var wg sync.WaitGroup
	wg.Add(len(detectors))
	for i, d := range detectors {
		go func(i int, d Detector) {
			defer wg.Done()
			results[i], errs[i] = d.Detect(text)
		}(i, d)
	}
	wg.Wait()

	var total int
	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("detector failed: %w", err)
		}
		total += len(results[i])
	}

	all := make([]Detection, 0, total)
	for _, found := range results {
		all = append(all, found...)
	}
	return all, nil
}

// filterAllowed drops every Detection with at least one Lookup whose
// Real value matches an allow-list pattern (see SetAllowPatterns).
func (e *Engine) filterAllowed(dets []Detection) []Detection {
	patterns := *e.allowPatterns.Load()
	if len(patterns) == 0 {
		return dets
	}
	out := dets[:0]
	for _, d := range dets {
		allowed := false
		for _, lk := range d.Lookups {
			for _, re := range patterns {
				if re.MatchString(lk.Real) {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}
		if !allowed {
			out = append(out, d)
		}
	}
	return out
}

// filterAlreadyTokenized drops any detection whose span overlaps a
// span this store has ALREADY registered as a real, minted wire token,
// of any entity type, not just the detector that produced this
// detection's own.
//
// Every built-in detector already refuses to re-match its OWN token
// shape (e.g. domainDetector's isOwnDomainToken), but that only
// protects a detector against its own output; nothing otherwise stops
// one detector from matching a substring INSIDE a DIFFERENT entity's
// already-minted token, once that token is sitting in resent
// conversation history and gets re-scanned on a later Tokenize call.
// This is a normal occurrence, not a rare one: history is resent every
// turn, and tokenize_cache is generation-keyed, so adding a new
// rules.json block entry mid-engagement invalidates the cache and
// forces a full re-scan of everything already tokenized so far. A
// short block-listed word that happens to be valid hex (ordinary
// English words like "cafe"/"face"/"beef" all are) can land inside
// another domain token's random hex and splice a new opaque token into
// the middle of the old one, corrupting it. The same class of
// collision reaches built-in detectors too, not just the block
// detector: tok-blocked-<32hex> tokens are exactly MD5 length, so a
// hash-related keyword (e.g. "NTLM hash") appearing near an
// already-blocked term can let hashDetector re-claim the block token's
// own hex body as if it were a real password hash.
//
// Scoped to every detector rather than just the block detector, since
// the hash case above shows a built-in detector is exposed to this
// too, and there's no principled shape/keyword-based way to declare only
// operator-authored patterns at risk. Checked against tokenstore's
// spanTrie (the exact set of wire spans this engine has actually
// minted, not a shape/pattern guess), so this can only ever remove a
// detection that's provably already one of this tool's own tokens; it
// can never suppress a detection for genuinely new, real content that
// merely resembles a token shape.
func (e *Engine) filterAlreadyTokenized(dets []Detection, text string) []Detection {
	spans := e.store.AlreadyTokenizedSpans(text)
	if len(spans) == 0 {
		return dets
	}
	out := dets[:0]
	for _, d := range dets {
		overlaps := false
		for _, s := range spans {
			if d.Start < s.End && s.Start < d.End {
				overlaps = true
				break
			}
		}
		if !overlaps {
			out = append(out, d)
		}
	}
	return out
}

// resolveOverlaps sorts detections by start position (longest match first
// among ties) and greedily keeps only non-overlapping ones: later,
// shorter, or later-starting matches that overlap an already-accepted
// span are dropped. This naturally gives priority to more specific
// matches (e.g. a full email address) over a broader one that happens to
// start at the same or a later position (e.g. just the domain within
// that email) without needing explicit per-detector priority.
//
// A block-list detection losing to an earlier-starting built-in one here
// is safe specifically because splitDomain (domainsplit.go) guarantees
// the built-in domain detector's own substitution always replaces
// whatever it identifies as the organization label in full; see
// TestSplitDomain_DoubledTLDSuffix for the concrete case (a doubled TLD)
// that would defeat that guarantee if not fixed at the source rather
// than papered over here. Giving block-list detections blanket priority
// here instead would also close the same gap, but at the cost of
// silently downgrading every domain that happens to also match a block
// rule to the block detector's fully-opaque token format, discarding the
// subdomain/TLD structure Claude's reasoning benefits from, on every
// single occurrence, not just the rare buggy one. Fixing the actual
// mis-splitting at its source keeps that structure intact.
// Two detectors can also produce byte-identical spans, not just
// overlapping ones: a real GitHub PAT written as "api_key: ghp_..." is
// claimed by githubTokenDetector and bearerDetector alike, over exactly
// the same start and length. Both redact it, so nothing leaks either
// way, but they give it different entity types and so different
// placeholder shapes, and the sort has to break that tie somehow. The
// sort is STABLE so the answer is a property of the code rather than of
// pivot choices inside the sort: collectDetections merges each
// detector's results in detector-list order (results[i] is indexed by
// detector index, so goroutine completion order doesn't affect it), and
// stability preserves that, letting the earlier entry in
// DefaultCategorizedDetectors win.
func resolveOverlaps(dets []Detection) []Detection {
	slices.SortStableFunc(dets, func(a, b Detection) int {
		if c := cmp.Compare(a.Start, b.Start); c != 0 {
			return c
		}
		return cmp.Compare(b.End-b.Start, a.End-a.Start) // longest match first
	})

	accepted := make([]Detection, 0, len(dets))
	lastEnd := -1
	for _, d := range dets {
		if d.Start >= lastEnd {
			accepted = append(accepted, d)
			lastEnd = d.End
		}
	}
	return accepted
}

// Every detokenize pattern below (domainTokenRe, emailLocalTokenRe,
// tokenPatterns, intlPhoneTokenRe) that anchors on a leading boundary at
// all uses the same underscore-safe boundary as domainLabelUnicodeRe in unicode_domain.go
// (never a bare \b) and no trailing one. Both asymmetries were found
// from real leaks:
//
//   - Leading: RE2's \b treats "_" as a word character, so a token glued
//     onto a preceding identifier via underscore (e.g. a locally-created
//     filename like "hdr_tok<hex>.com", a genuinely common pattern) never
//     got a \b to fire on, and detokenization silently skipped it
//     entirely: the raw token, not the real value, reached the
//     operator's own terminal. See wrapDetokenizeBoundary's doc comment
//     for the fix, the same capture-group workaround domainLabelUnicodeRe uses (RE2
//     has no lookbehind).
//   - Trailing: a model reusing an already-known token to construct a new
//     compound identifier (e.g. taking a known "tok-blocked-<hash>" for
//     "widgetcorp" and writing "tok-blocked-<hash>subsidiary.example" to
//     mean "widgetcorpsubsidiary.example", with no separator) glues more
//     word characters directly onto the token's end. A trailing \b there
//     means the WHOLE match silently fails and the raw token leaks
//     straight through un-replaced. Safe to drop entirely (not just
//     replace) specifically because every one of these patterns' variable
//     part is a FIXED, EXACT count ({16} hex, {32} hex, {4} digits, ...),
//     and that exact count is already an unambiguous stopping point on its
//     own, so \b was never load-bearing for correctness there, only for a
//     false safety margin that broke real cases. False-positive risk from
//     dropping it is negligible: matching a fixed-length run of this many
//     hex/digit characters that ISN'T actually one of this tool's own
//     minted tokens by coincidence is astronomically unlikely.
//
// domainTokenRe matches just the org-token itself, "tok" + 16 hex chars,
// with none of its trailing preserved-suffix labels captured. Unlike
// the other token patterns below, the domain token needs custom
// detokenize logic (see detokenizeDomainTokens), because the number of
// trailing labels to consume (".com" is one, ".co.uk" is two) depends on
// the real value being restored, not on anything visible in the token
// text itself.
var domainTokenRe = regexp.MustCompile(`(?:^|[^0-9A-Za-z])(` + regexp.QuoteMeta(tokenstore.TokenDomainPrefix) + `[0-9a-f]{16})`)

// emailLocalTokenRe also needs custom handling, not the generic
// tokenPatterns loop: its stored "real" value is the FULL lowercased
// email address, not just the local part (see redact.emailDetector;
// keying by the whole address is what stops two different mailboxes at
// different organizations from colliding), so a naive substitution of
// the looked-up value in place of just the local-part span would paste
// the whole "local@domain" where only "local" belongs, duplicating the
// domain that the domain-token pass already restored beside it.
var emailLocalTokenRe = regexp.MustCompile(`(?:^|[^0-9A-Za-z])(` + regexp.QuoteMeta(tokenstore.TokenEmailLocalPrefix) + `[0-9a-f]{12})`)

// tokenPatterns match this tool's own generated token formats that are
// fully self-contained: a straight regex match is the whole token, so
// plain ReplaceAllStringFunc is enough. Domain, email-local, IPv4, IPv6,
// and international-phone tokens are NOT here: those carry a preserved-
// structure piece of variable length or position (see the dedicated
// detokenizeXxx methods below) that a single fixed-shape pattern can't
// express.
var tokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b\d{3}-` + regexp.QuoteMeta(tokenstore.TokenPhonePrefix) + `\d{2}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenJWTPrefix) + `[0-9a-f]{8}\.[0-9a-f]{32}\.[0-9a-f]{32}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenBearerPrefix) + `[0-9a-f]{32}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenAWSKeyPrefix) + `[0-9A-F]{12}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenAWSSecretKeyPrefix) + `[0-9a-f]{32}`),
	regexp.MustCompile(regexp.QuoteMeta(tokenstore.TokenPEMKeyBeginMarker) + `[0-9a-f]{48}` + regexp.QuoteMeta(tokenstore.TokenPEMKeyEndMarker)),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenMACPrefix) + `[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenAadhaarPrefix) + `\d{4} \d{4}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenPANPrefix) + `\d{4}[A-Z]`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenGitHubPrefix) + `[0-9a-f]{32}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenGitLabPrefix) + `[0-9a-f]{16}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenSlackTokenPrefix) + `[0-9a-f]{8}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenSlackWebhookMarker) + `[0-9a-f]{32}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenStripePrefix) + `[0-9a-f]{16}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenGoogleAPIKeyPrefix) + `[0-9a-f]{28}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenNPMPrefix) + `[0-9a-f]{32}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenConnStringMarker) + `[0-9a-f]{24}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenTwilioSIDPrefix) + `[0-9a-f]{30}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenSendGridPrefix) + `[0-9a-f]{20}\.[0-9a-f]{40}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenDigitalOceanPrefix) + `[0-9a-f]{60}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenCloudflarePrefix) + `[0-9a-f]{44}`),
	regexp.MustCompile(regexp.QuoteMeta(tokenstore.TokenAzureStorageKeyPrefix) + `[0-9a-f]{60}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenArtifactoryPrefix) + `[0-9a-f]{60}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenDockerHubPrefix) + `[0-9a-f]{28}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenCircleCIPrefix) + `[0-9a-f]{18}_[0-9a-f]{40}`),
	regexp.MustCompile(regexp.QuoteMeta(tokenstore.TokenTerraformPrefix) + `[0-9a-f]{60}`),
	regexp.MustCompile(regexp.QuoteMeta(tokenstore.TokenSnykPrefix) + `[0-9a-f]{12}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenBitbucketPrefix) + `[0-9a-f]{40}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenVaultPrefix) + `[0-9a-f]{100}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenOpenAIPrefix) + `[0-9a-f]{20}` + regexp.QuoteMeta(tokenstore.TokenOpenAIMarker) + `[0-9a-f]{20}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenAnthropicPrefix) + `[0-9a-f]{88}AA`),
	regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(tokenstore.TokenRazorpayPrefix) + `[0-9a-f]{10}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenItsdangerousPrefix) + `[0-9a-f]{32}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenCustomBlockPrefix) + `[0-9a-f]{32}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenPasswordHashPrefix) + `[0-9a-f]{48}`),
	regexp.MustCompile(`\b` + regexp.QuoteMeta(tokenstore.TokenADMachineAccountPrefix) + `[0-9a-f]{12}\$`),
	regexp.MustCompile(regexp.QuoteMeta(tokenstore.TokenGPPCPasswordPrefix) + `[0-9a-f]{48}`),
}

// wrapDetokenizeBoundary rewrites one tokenPatterns entry's source into
// a self-contained alternative for combinedTokenPatternRe: a leading \b
// (if present) is replaced with the same underscore-safe boundary
// domainLabelUnicodeRe uses in unicode_domain.go (RE2 treats "_" as a word character, so a
// bare \b never fires between an underscore and this token's first
// character; see this file's doc comment above domainTokenRe), and
// EVERY pattern gets its own capture group around its actual content,
// whether or not it needed a boundary rewrite. That uniformity is what
// lets replaceFirstNonEmptyGroup below identify, for any match anywhere
// in the combined alternation, exactly which captured span is the real
// token text: group 0 (the whole match) may also include a consumed
// boundary character ahead of it, which must NOT be treated as part of
// the token.
//
// The capture group also still gives every sub-pattern its own group
// boundary for the (?i) case-insensitive-flag-scoping reason the
// previous non-capturing-group version existed for (RE2 scopes an
// inline flag to its enclosing group; without one, Razorpay's leading
// "(?i)" would silently apply to every pattern listed after it too).
func wrapDetokenizeBoundary(pattern string) string {
	if rest, ok := strings.CutPrefix(pattern, `\b`); ok {
		return `(?:^|[^0-9A-Za-z])(` + rest + `)`
	}
	return `(` + pattern + `)`
}

// combinedTokenPatternRe merges every tokenPatterns entry into ONE
// compiled alternation so Detokenize does a single full-text scan
// instead of one pass per credential format; every sub-pattern's
// callback is identical (just store.LookupReal, nothing
// pattern-specific), so there's no need for separate passes at all.
var combinedTokenPatternRe = regexp.MustCompile(func() string {
	parts := make([]string, len(tokenPatterns))
	for i, re := range tokenPatterns {
		parts[i] = wrapDetokenizeBoundary(re.String())
	}
	return strings.Join(parts, "|")
}())

// replaceFirstNonEmptyGroup finds every match of re in text and replaces
// EACH with repl(capturedText), where capturedText comes from the first
// capture group that actually matched (exactly one fires per match, by
// construction; see wrapDetokenizeBoundary). Everything outside that
// group, including a consumed boundary character ahead of it, which
// group 0 (the whole match) spans but the token's own group doesn't,
// is copied through unchanged. Needed instead of the stdlib's
// ReplaceAllStringFunc (which always hands the callback the WHOLE
// match) because these patterns can consume a boundary character ahead
// of the real token as part of matching "a non-alnum character counts
// as a boundary, not just \b's narrower definition."
func replaceFirstNonEmptyGroup(re *regexp.Regexp, text string, repl func(string) string) string {
	matches := re.FindAllStringSubmatchIndex(text, -1)
	if matches == nil {
		return text
	}
	var sb strings.Builder
	last := 0
	for _, m := range matches {
		if m[0] < last {
			continue // overlapped a previous match; skip
		}
		groupStart, groupEnd := -1, -1
		for g := 1; 2*g+1 < len(m); g++ {
			if m[2*g] != -1 {
				groupStart, groupEnd = m[2*g], m[2*g+1]
				break
			}
		}
		if groupStart == -1 {
			continue // shouldn't happen -- every alternative wraps its content in exactly one group
		}
		sb.WriteString(text[last:groupStart])
		sb.WriteString(repl(text[groupStart:groupEnd]))
		last = groupEnd
	}
	sb.WriteString(text[last:])
	return sb.String()
}

// intlPhoneTokenRe matches a preserved-country-code international phone
// token: "+<real country code>-" + the opaque subscriber token. Like the
// domain case, the variable preserved piece (here, a PREFIX rather than a
// suffix) sits outside the actual stored token, so this can't be a single
// self-contained tokenPatterns entry: the subscriber token
// ("555-<4 digits>") is looked up on its own, and the real country code
// in the visible text is just carried through as literal text around it.
var intlPhoneTokenRe = regexp.MustCompile(`\+\d{1,3}-` + regexp.QuoteMeta(tokenstore.TokenIntlPhonePrefix) + `\d{4}`)

// ipNetworkTokenRe matches an IPv4 network-token immediately followed by
// its real, preserved host octet: "198.18.<net>.<host>" as a whole. The
// host octet's exact width (1-3 digits) is always present in the match
// itself, unlike the domain case, so no separate lookup-then-lookahead
// step is needed here.
var ipNetworkTokenRe = regexp.MustCompile(regexp.QuoteMeta(tokenstore.TokenIPNetworkPrefix) + `(\d{1,3})\.(\d{1,3})\b`)

// ipv6TokenCandidateRe finds anything starting with the fixed IPv6 token
// prefix and greedily consumes the rest of a plausible address. Unlike
// the IPv4 case, this can't require a rigid group count: the visible
// text is in Go's canonical "::"-compressed form (see ipv6Detector's
// Format), and compression can merge zero groups straddling the
// network/host boundary, so the number of VISIBLE groups after the fixed
// prefix isn't fixed either. The fixed prefix itself is never compressed
// away ("fd00" and "c0de" are both non-zero), so it's a safe anchor;
// everything after it gets parsed properly by netip (see
// detokenizeIPv6Tokens) instead of pattern-matched.
var ipv6TokenCandidateRe = regexp.MustCompile(regexp.QuoteMeta(tokenstore.TokenIPv6NetworkPrefix) + `[0-9a-fA-F:]*`)

// Detokenize replaces every recognized token in text with its real value.
// It fails open by design: a token that isn't found in the store (should
// never happen in practice, since every token was minted by this same
// store) is left as literal text rather than erroring. That's the safe
// direction to fail: worst case is a broken command Claude Code runs
// against a fake hostname, which is visibly wrong to the operator, not a
// silent PII leak.
func (e *Engine) Detokenize(text string) string {
	dbg := e.debug.Load()
	text = e.detokenizeDomainTokens(text, dbg)
	text = e.detokenizeEmailLocalTokens(text, dbg)
	text = e.detokenizeIPv4Tokens(text, dbg)
	text = e.detokenizeIPv6Tokens(text, dbg)
	text = e.detokenizeIntlPhoneTokens(text, dbg)
	text = replaceFirstNonEmptyGroup(combinedTokenPatternRe, text, func(tok string) string {
		real, ok := e.store.LookupReal(tok)
		if !ok {
			return tok
		}
		dbg.Replacement("detokenize", "credential", real, tok)
		return real
	})
	return text
}

// SafeFlushPoint returns the largest N <= len(buf) such that buf[:N] can
// be safely detokenized and emitted right now during streaming, without
// risking cutting a credential that hasn't finished arriving yet. See
// tokenstore.spanTrie's doc comment for the underlying mechanism and why
// it's exact rather than an approximation: every span this could ever
// need to hold back was registered by this same Engine's Tokenize call
// before the request that could produce this response was ever sent, so
// there's nothing here Claude could echo that isn't already a known,
// exact, complete string.
func (e *Engine) SafeFlushPoint(buf []byte) int {
	return e.store.SafeFlushPoint(buf)
}

// detokenizeEmailLocalTokens restores "user-<hex>" to the real local
// part alone. The stored value behind the token is the full lowercased
// email address (see emailLocalTokenRe for why), so this extracts just
// the piece before "@" rather than substituting the whole thing, which
// would duplicate the domain the domain-token pass already restores next
// to it.
func (e *Engine) detokenizeEmailLocalTokens(text string, dbg *debuglog.Logger) string {
	return replaceFirstNonEmptyGroup(emailLocalTokenRe, text, func(tok string) string {
		real, ok := e.store.LookupReal(tok)
		if !ok {
			return tok
		}
		dbg.Replacement("detokenize", "email_local", real, tok)
		if at := strings.LastIndexByte(real, '@'); at != -1 {
			return real[:at]
		}
		return real
	})
}

// detokenizeIPv4Tokens restores "198.18.<net>.<host>" to the real
// "<a>.<b>.<c>.<host>": the network portion is looked up, the host
// octet is carried straight through from the match, unchanged.
func (e *Engine) detokenizeIPv4Tokens(text string, dbg *debuglog.Logger) string {
	return ipNetworkTokenRe.ReplaceAllStringFunc(text, func(m string) string {
		sub := ipNetworkTokenRe.FindStringSubmatch(m)
		netToken := tokenstore.TokenIPNetworkPrefix + sub[1]
		if realNet, ok := e.store.LookupReal(netToken); ok {
			real := realNet + "." + sub[2]
			dbg.Replacement("detokenize", "ip_network", real, m)
			return real
		}
		return m
	})
}

// detokenizeIPv6Tokens restores a /64 network-token plus its preserved
// interface ID to the real address. It parses the candidate through
// netip FIRST (letting Go's real IPv6 parser correctly expand whatever
// "::" compression the visible text uses) rather than trying to
// pattern-match a specific group count, which breaks the moment
// compression merges a zero group straddling the network/host boundary
// (e.g. "fd00:c0de:0:1::1234" has only 5 visible groups where the
// uncompressed form has 6, so a rigid regex wouldn't match it).
// Once parsed, the network-token's 4 bytes sit at a fixed byte offset
// regardless of how the text was written, so the exact lookup key the
// generator originally minted can be reconstructed byte-for-byte.
func (e *Engine) detokenizeIPv6Tokens(text string, dbg *debuglog.Logger) string {
	return ipv6TokenCandidateRe.ReplaceAllStringFunc(text, func(m string) string {
		addr, err := netip.ParseAddr(m)
		if err != nil {
			return m // over-matched a trailing character or similar; not a fully valid address
		}
		b := addr.As16()
		netToken := fmt.Sprintf("%s%02x%02x:%02x%02x", tokenstore.TokenIPv6NetworkPrefix, b[4], b[5], b[6], b[7])
		realNetHex, ok := e.store.LookupReal(netToken)
		if !ok {
			return m
		}
		full := hexToIPv6Groups(realNetHex) + ":" + formatIPv6Groups(b[8:])
		result := full
		if realAddr, err := netip.ParseAddr(full); err == nil {
			result = realAddr.String()
		}
		dbg.Replacement("detokenize", "ipv6_network", result, m)
		return result
	})
}

// detokenizeIntlPhoneTokens restores "+<cc>-555-<nnnn>" to the real E.164
// number. Only the "555-<nnnn>" portion was ever minted/stored as a
// token (the "+<cc>-" prefix is the real country code, echoed literally
// at tokenize time (see intlPhoneDetector's Format), so that's the
// substring looked up, not the whole match.
//
// A "555-01XX" suffix is skipped here rather than looked up: that's
// TokenPhonePrefix's own reserved NANP subrange (see nextPhone/
// nextIntlPhone in tokenstore/generator.go, which keeps intl-phone's
// random draw out of it), so any "+<cc>-555-01XX" match here is a NANP
// phone token that happens to sit right after an unrelated literal
// "+<cc>-" in the source text (routine for a NANP number written with
// an explicit country code; phoneRe's leading boundary doesn't capture
// it, so it passes through as plain text on both sides), not a genuine
// international token. Leaving it for the plain tokenPatterns pass right
// below restores just the "555-01XX" portion via its own dedicated
// regex, keeping the literal prefix intact instead of swallowing it.
func (e *Engine) detokenizeIntlPhoneTokens(text string, dbg *debuglog.Logger) string {
	return intlPhoneTokenRe.ReplaceAllStringFunc(text, func(m string) string {
		i := strings.Index(m, tokenstore.TokenIntlPhonePrefix)
		if i == -1 {
			return m
		}
		key := m[i:]
		if strings.HasPrefix(key, tokenstore.TokenPhonePrefix) {
			return m
		}
		if real, ok := e.store.LookupReal(key); ok {
			dbg.Replacement("detokenize", "intl_phone", real, key)
			return real
		}
		return m
	})
}

// hexToIPv6Groups renders a 16-character hex string (the stored /64
// network key) as four colon-separated 4-hex-digit groups.
func hexToIPv6Groups(h string) string {
	groups := make([]string, 0, 4)
	for i := 0; i < len(h); i += 4 {
		groups = append(groups, h[i:min(i+4, len(h))])
	}
	return strings.Join(groups, ":")
}

// detokenizeDomainTokens finds every org-token and restores it to the
// real registrable domain. Reconstructing subdomain labels and suffix
// is unnecessary because they were never modified in the first place
// (they sit outside the matched span, both at tokenize time and here).
// What DOES need care is the trailing echoed suffix that WAS added at
// tokenize time (e.g. "tok1a2b3c4d5e6f70.co.uk", where the ".co.uk" is a
// literal echo of the real suffix, written so the text reads naturally).
// That echo must be consumed as part of the match and replaced together
// with the token, or it would be left dangling next to the restored real
// domain. The number of labels to consume isn't visible in the token
// text; it depends on the real suffix, which is why this can't be a
// single self-contained regex like the other token patterns and instead
// looks the real value up first, then checks how much of the text
// immediately following the token matches that value's own suffix.
func (e *Engine) detokenizeDomainTokens(text string, dbg *debuglog.Logger) string {
	matches := domainTokenRe.FindAllStringSubmatchIndex(text, -1)
	if matches == nil {
		return text
	}

	var sb strings.Builder
	last := 0
	for _, m := range matches {
		// m[2],m[3] is capture group 1 -- the token itself, excluding
		// whatever boundary character group 0 (the whole match) may have
		// consumed ahead of it. See domainTokenRe's doc comment.
		start, tokEnd := m[2], m[3]
		if start < last {
			continue // overlapped a previous (extended) match; skip
		}
		tok := text[start:tokEnd]
		end := tokEnd
		replacement := tok // fail open: unrecognized token stays literal

		if real, ok := e.store.LookupReal(tok); ok {
			replacement = real
			suffix := ""
			if parts, ok := splitTenantSubdomainSaaS(real); ok {
				suffix = parts.suffix
			} else if parts, ok := splitDomain(real); ok {
				// splitDomain, not a bare publicsuffix.PublicSuffix(real)
				// call: real is already the final, tokenize-time-resolved
				// registrable domain, which for a doubled-suffix input
				// (e.g. the original FQDN was "svc-b.widgetcorp.net.net")
				// is itself "widgetcorp.net.net" -- a string publicsuffix
				// alone parses as suffix "net" (it has no notion that the
				// two "net"s are a duplication, only splitDomain's own
				// walk-back loop does). Using that shorter suffix here
				// would only consume ONE of the two echoed ".net"
				// segments actually sitting in the wire text, leaving the
				// second dangling as literal text next to the restored
				// real value. splitDomain's walk-back is idempotent on an
				// already-registrable domain -- splitDomain("widgetcorp.net.net")
				// independently re-derives suffix "net.net", matching
				// tokenize time exactly -- so calling it again here on
				// real recovers the same suffix that was actually echoed
				// onto the wire, without needing to have stored it
				// separately.
				suffix = parts.suffix
			}
			if suffix != "" {
				echoed := "." + suffix
				if strings.HasPrefix(text[end:], echoed) {
					end += len(echoed)
				}
			}
			// Logged with the FULL wire-visible span (token + echoed
			// suffix, e.g. "tok6a44f00e1999f85d.co"), not the bare
			// stored key alone; that's what actually appeared on the
			// wire and is what you'd grep a Full-tier body dump for.
			dbg.Replacement("detokenize", "domain", real, text[start:end])
		}

		sb.WriteString(text[last:start])
		sb.WriteString(replacement)
		last = end
	}
	sb.WriteString(text[last:])
	return sb.String()
}
