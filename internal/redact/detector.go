// Package redact implements PII detection and bidirectional substitution
// (real value <-> token) over arbitrary text, backed by a tokenstore.Store.
//
// Detection is deliberately regex-only (RE2 via Go's stdlib regexp, which
// cannot backtrack: safe to run against untrusted scan output or page
// content with no ReDoS risk). This trades recall for predictability and
// zero false-positive risk on report prose: names, codenames, and other
// unpatterned PII are out of scope for v1. The Detector interface exists
// so a future LLM-backed or additional rule-based detector can be added
// later without touching the substitution engine.
//
// The detection strategy here (a loose regex to find candidates, then a
// precise check (TLD allowlist, a real IP parser, a reserved-range check)
// to accept or reject each one) separates "does this look like the
// shape" from "is this actually valid", which matters because RE2 has no
// lookaround: anywhere a lookahead/lookbehind assertion would normally
// narrow the candidate regex itself, the equivalent here is a post-match
// Go check instead.
package redact

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// lookup is one (real value, entity type) pair that needs a token. Most
// Detections need exactly one; an email needs two (a local-part token
// and a shared org-domain token) combined by Format into one piece of
// replacement text.
type lookup struct {
	Real string
	Type tokenstore.EntityType
}

// Detection is a single real-value match found in text, in byte offsets
// into that exact text, plus the token lookup(s) needed to redact it and
// (optionally) how to combine their results into the final replacement.
type Detection struct {
	Start, End int
	Lookups    []lookup
	// Format combines the resolved tokens (same order as Lookups) into
	// the final replacement text. nil means "exactly one lookup, use its
	// token directly", the common case for IPs, phone numbers, and a
	// domain with no subdomain structure to reconstruct.
	Format func(tokens []string) string
	// PreserveIfUnknown marks a detection whose match is more likely a
	// coincidentally domain-shaped word than a real second domain
	// reference: e.g. "login.com" as a bare URL PATH segment
	// ("/xyz/login.com"), as opposed to a host ("https://login.com") or a
	// query-parameter value ("?to=login.com/phish", a plausible redirect
	// target). Tokenizing it unconditionally would destroy a semantic cue
	// Claude may need (this is a login page) for no privacy benefit in
	// the common case where it isn't really a second domain at all. When
	// true, the engine only tokenizes this match if its registrable
	// domain is ALREADY a known real value in the store (established via
	// some other, non-path-segment mention, in this call or a prior one);
	// otherwise it's left as literal text. See domainDetector.Detect
	// for how the position is classified.
	PreserveIfUnknown bool
}

// simpleDetection builds a Detection with exactly one lookup and no
// reconstruction: the token itself is the whole replacement.
func simpleDetection(start, end int, real string, typ tokenstore.EntityType) Detection {
	return Detection{Start: start, End: end, Lookups: []lookup{{Real: real, Type: typ}}}
}

// wholeMatchDetector covers the shape most vendor-credential detectors
// share exactly: one regex, whole match is the secret, fully opaque
// (EntityXxx with no Format), skip anything that's already one of this
// tool's own tokens. Everything genuinely detector-specific about those
// (why the pattern is shaped the way it is, what it deliberately doesn't
// match) lives on the regex's own doc comment, which is where a reader
// looking to change detection behavior goes; the loop underneath was
// identical copy-paste in every case.
//
// tokenMarker is the exact constant tokenstore mints for this entity,
// NOT the bare string "FAKE" the hand-written copies each checked for.
// That mattered: "FAKE" appears inside most, but not all, of the minted
// prefixes, and it's a plain 4-character substring, so a REAL credential
// that happens to contain it anywhere (routine for a 40-to-300-character
// random secret, and these detectors match uppercase alphanumerics) was
// silently treated as already-tokenized and passed through the proxy
// unredacted. Checking the full minted marker instead makes a
// coincidental match effectively impossible, and ties each detector to
// the constant it's actually guarding against rather than a shared magic
// string.
type wholeMatchDetector struct {
	re          *regexp.Regexp
	entity      tokenstore.EntityType
	tokenMarker string
}

func (d wholeMatchDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, loc := range d.re.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		if strings.Contains(val, d.tokenMarker) {
			continue // already a token
		}
		out = append(out, simpleDetection(loc[0], loc[1], val, d.entity))
	}
	return out, nil
}

// capturedMatchDetector is wholeMatchDetector for the patterns whose
// secret is capture group 1 rather than the whole match, i.e. the
// keyword-anchored ones, where the anchoring keyword and whatever sits
// between it and the value must stay as untouched literal context.
type capturedMatchDetector struct {
	re          *regexp.Regexp
	entity      tokenstore.EntityType
	tokenMarker string
}

func (d capturedMatchDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, m := range d.re.FindAllStringSubmatchIndex(text, -1) {
		start, end := m[2], m[3]
		val := text[start:end]
		if strings.Contains(val, d.tokenMarker) {
			continue // already a token
		}
		out = append(out, simpleDetection(start, end, val, d.entity))
	}
	return out, nil
}

// Detector finds real-value PII in text for the tokenize (real -> token)
// direction. Implementations must never match text that already looks
// like one of this tool's own tokens (see the per-detector exclusion
// checks below); otherwise tokenizing already-tokenized text would mint
// garbage entries and break idempotency.
//
// Detect returns an error for detectors that can genuinely fail (e.g. a
// future LLM-backed detector hitting a timeout or rate limit); the
// regex detectors below never do. A detector error propagates out of
// Engine.Tokenize and fails the whole call closed: a detector that
// couldn't check its share of the text must never be treated as "found
// nothing," since that would silently let real PII through undetected.
type Detector interface {
	Detect(text string) ([]Detection, error)
}

// DefaultDetectors returns the standard regex-based detector set, order
// preserved from DefaultCategorizedDetectors (the source of truth; see
// categories.go). Order does not encode priority; the engine resolves
// overlaps by match position and length, not by detector order.
func DefaultDetectors() []Detector {
	cats := DefaultCategorizedDetectors()
	out := make([]Detector, len(cats))
	for i, c := range cats {
		out[i] = c.Detector
	}
	return out
}

// --- email -------------------------------------------------------------

var ownEmailLocalTokenRe = regexp.MustCompile(`^` + regexp.QuoteMeta(tokenstore.TokenEmailLocalPrefix) + `[0-9a-f]{12}$`)

type emailDetector struct{}

// An email is redacted as (local-part token) + "@" + (structure-
// preserving domain reconstruction; see domainReplacement). The local
// part is kept fully opaque even though subdomain labels aren't: a
// subdomain label is infrastructure/role metadata ("admin", "ns1"), but
// an email local part is very often a real person's name, and preserving
// it would buy nothing.
func (emailDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, cand := range findEmailCandidates(text) {
		// Validate against Clean (invisible/format characters stripped):
		// the domain-part split below, and domainReplacement's own
		// public-suffix lookup, do their own dot-splitting and suffix
		// matching that an embedded invisible character breaks the same
		// way an ASCII-only regex truncates on one -- see
		// domainCandidate's doc comment.
		lowerClean := strings.ToLower(cand.Clean)

		at := strings.LastIndexByte(lowerClean, '@')
		if at == -1 {
			continue // regex guarantees an "@", but never trust a match blindly
		}
		localPart, domainPart := lowerClean[:at], lowerClean[at+1:]

		if ownEmailLocalTokenRe.MatchString(localPart) || isOwnDomainToken(domainPart) {
			continue // already a token
		}
		if strings.HasPrefix(cand.Clean[:at], "ATBB") {
			// Not actually an email: a Bitbucket app password in git-URL
			// form ("user:ATBBxxxx@bitbucket.org") happens to be
			// syntactically indistinguishable from local@domain, but its
			// "local part" is a case-SENSITIVE credential. Lowercasing it
			// (as this detector does for every real email local part)
			// would corrupt the password on restore; bitbucketDetector
			// claims it instead, case preserved exactly.
			continue
		}
		if isReservedDomain(domainPart) {
			continue // e.g. user@example.com: reserved, never a real target
		}

		domainRepl, _, ok := domainReplacement(domainPart)
		if !ok {
			continue
		}

		// Map back to the ORIGINAL text for both the redaction span and
		// what actually gets stored as each token's real value, so an
		// invisible/format character that was part of the real address
		// (rather than an artifact this detector is looking past) is
		// never silently dropped from what a later detokenize restores;
		// see domainCandidate's doc comment.
		start := cand.ToOrig(0)
		end := cand.ToOrig(len(cand.Clean))
		lowerOrigWhole := strings.ToLower(text[start:end])

		// Label-counted, not a bare len(domainRepl.registrable) byte
		// subtraction: domainRepl.registrable came from domainPart
		// (lowercased), and strings.ToLower does not preserve UTF-8
		// byte length for every rune, so its length cannot be trusted
		// as an offset into cand.Clean's own (unlowered) byte space;
		// see lastNLabels' doc comment. "at" itself IS safe to index
		// cand.Clean with directly: the local part's own character
		// class is ASCII-only (see emailUnicodeRe), so lowercasing it
		// can never shift "@"'s byte position between cand.Clean and
		// lowerClean.
		origDomainPart := cand.Clean[at+1:]
		labelCount := strings.Count(domainRepl.registrable, ".") + 1
		registrableOrigCase := lastNLabels(origDomainPart, labelCount)
		regStart := len(cand.Clean) - len(registrableOrigCase)
		origRegistrable := strings.ToLower(text[cand.ToOrig(regStart):cand.ToOrig(len(cand.Clean))])

		out = append(out, Detection{
			Start: start, End: end,
			Lookups: []lookup{
				// Keyed by the full address, not just the local part, so
				// two different mailboxes that happen to share a local
				// part at different organizations never collide.
				{Real: lowerOrigWhole, Type: tokenstore.EntityEmailLocal},
				{Real: origRegistrable, Type: tokenstore.EntityDomain},
			},
			Format: func(tokens []string) string {
				return tokens[0] + "@" + domainRepl.format(tokens[1])
			},
		})
	}
	return out, nil
}

// --- domain / hostname (bare or embedded in a URL) ----------------------
//
// Deliberately matches ONLY the hostname span, not a whole URL: for
// "curl -I https://example.com/admin?x=1" this matches just
// "example.com". Because substitution only rewrites the matched span
// (see Engine.Tokenize), the scheme, path, and query are left byte-for-
// byte untouched automatically; no separate URL-parsing detector needed.

var ownDomainTokenLabelRe = regexp.MustCompile(`^` + regexp.QuoteMeta(tokenstore.TokenDomainPrefix) + `[0-9a-f]{16}$`)

// isOwnDomainToken reports whether ANY label of a dot-separated domain
// is exactly this tool's own org-token shape, not just a prefix/suffix
// check, because a token can now appear anywhere in the string (e.g.
// "ns1.tok1a2b3c4d5e6f70.co.uk", where the token is the middle label).
func isOwnDomainToken(lower string) bool {
	for label := range strings.SplitSeq(lower, ".") {
		if ownDomainTokenLabelRe.MatchString(label) {
			return true
		}
	}
	return false
}

// domainDetector's forceAsDomain, when non-nil, is the set of registrable
// domains (lowercased) that bypass looksLikeBareFilename's skip entirely;
// see DefaultCategorizedDetectorsWithForcedDomains's doc comment for
// why this exists and where it's populated from.
type domainDetector struct {
	forceAsDomain map[string]bool
}

// lastNLabels returns the trailing n dot-separated labels of s, with s's
// OWN casing preserved, found by counting '.' bytes rather than by
// subtracting byte lengths computed from a lowercased copy of s.
//
// That distinction matters: strings.ToLower does not preserve UTF-8
// byte length for every rune ("Ⱦ" is 2 bytes; its lowercase "ⱦ" is 3),
// so a length taken from a lowercased string is not safe to subtract
// from an offset measured in the original, unlowered string: the two
// "byte length" units silently stop meaning the same thing the moment
// such a rune is involved, which is exactly what produces a
// slice-bounds panic in domainDetector.Detect on input like "ab@Ⱦ.ba".
// Dots are ASCII and case-invariant, so counting them instead never has
// this problem, regardless of what casing changes elsewhere in the
// string.
func lastNLabels(s string, n int) string {
	idx := len(s)
	for range n {
		dot := strings.LastIndexByte(s[:idx], '.')
		if dot == -1 {
			return s
		}
		idx = dot
	}
	return s[idx+1:]
}

// domainLabelUnicodeRe is deliberately greedy across every dot-separated label
// ("bytes.length" wouldn't work otherwise), which means a real domain
// glued directly (no separator) to a non-TLD dotted suffix, e.g.
// "widgetcorp-fixture.com.hosts-crtsh.txt", a domain-derived output
// filename, a genuinely common pattern in pentest tooling, becomes ONE
// match spanning the whole thing. Validation then correctly rejects the
// whole span (".txt" isn't a real TLD), and since RE2 doesn't backtrack,
// the real domain prefix ("widgetcorp-fixture.com" alone, which WOULD
// validate on its own) needs its own chance explicitly: retry with
// progressively shorter prefixes (dropping the last dot-separated label
// each time) until one validates or nothing's left. The detection span
// then ends wherever the shortest valid prefix does, leaving the
// non-domain trailing text (".hosts-crtsh.txt") as literal.
func (d domainDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, cand := range findDomainCandidates(text) {
		// Validate against Clean (invisible/format characters stripped)
		// -- see domainCandidate's doc comment for why: domainReplacement
		// does its own dot-splitting/suffix lookup, which an embedded
		// invisible character breaks the same way an ASCII-only
		// regex truncates on one.
		//
		// Lowercased before it ever becomes a tokenstore key, so
		// "Example.COM" and "example.com" dedupe to one token instead of
		// minting two -- deliberate, same canonical-form tradeoff as
		// macDetector and intlPhoneDetector. Detokenize therefore restores
		// this domain's original case as lowercase, not necessarily
		// byte-identical to however it was written; harmless, since DNS
		// names are case-insensitive by spec (RFC 4343).
		lower := strings.ToLower(cand.Clean)

		if isOwnDomainToken(lower) {
			continue
		}

		// candidate stays in cand.Clean's OWN casing throughout --
		// shortened here by dot position (ASCII, case-invariant), never
		// by a length taken from a lowercased copy. See lastNLabels'
		// doc comment for why mixing the two is unsafe: strings.ToLower
		// does not preserve UTF-8 byte length for every rune, so a
		// length measured after lowercasing cannot be trusted as an
		// offset into the original string's own byte space. trial is
		// lowercased fresh each iteration purely for the validation
		// calls below, which need lowercase input but never hand back
		// anything this loop measures the length of.
		candidate := cand.Clean
		var repl domainReplacementPlan
		var parts domainParts
		var ok bool
		for {
			trial := strings.ToLower(candidate)
			if !isReservedDomain(trial) {
				if repl, parts, ok = domainReplacement(trial); ok {
					break
				}
			}
			idx := strings.LastIndexByte(candidate, '.')
			if idx == -1 {
				break // nothing shorter left to try
			}
			candidate = candidate[:idx]
		}

		if ok {
			// Map back to the ORIGINAL text for both the redaction span
			// and what's actually stored as the token's real value, so
			// an invisible/format character that was part of the real
			// domain (rather than an artifact this detector is looking
			// past) is never silently dropped from what a later
			// detokenize restores -- see domainCandidate's doc comment.
			matchStart := cand.ToOrig(0)
			end := cand.ToOrig(len(candidate)) // may be shorter than the whole candidate; see doc comment above
			labelCount := strings.Count(repl.registrable, ".") + 1
			registrableOrigCase := lastNLabels(candidate, labelCount)
			registrable := strings.ToLower(text[cand.ToOrig(len(candidate)-len(registrableOrigCase)):end])
			if !d.forceAsDomain[registrable] && looksLikeBareFilename(text, matchStart, end, parts) {
				continue
			}
			out = append(out, Detection{
				Start: matchStart, End: end,
				Lookups:           []lookup{{Real: registrable, Type: tokenstore.EntityDomain}},
				Format:            func(tokens []string) string { return repl.format(tokens[0]) },
				PreserveIfUnknown: isPathSegmentPosition(text, matchStart),
			})
			continue
		}

		// Fallback, checked only once the above has already failed to
		// validate anything: an operator-declared domain (rules.json
		// IsDomain) whose TLD isn't a recognized public suffix at all --
		// an internal AD forest name, a purely-internal naming scheme
		// like "fileserver.corp-ad". domainReplacement's public-suffix-
		// based splitting never validates these on its own, so this
		// never changes behavior for anything the normal path already
		// handles; it only adds coverage for what it can't.
		matchStart, matchEnd := cand.ToOrig(0), cand.ToOrig(len(cand.Clean))
		if registrable, forced := forcedDomainSuffix(lower, d.forceAsDomain); forced {
			prefix := lower[:len(lower)-len(registrable)]
			out = append(out, Detection{
				Start: matchStart, End: matchEnd,
				Lookups: []lookup{{Real: registrable, Type: tokenstore.EntityDomain}},
				Format: func(tokens []string) string {
					if !ownDomainTokenLabelRe.MatchString(tokens[0]) {
						// Same foreign-token safety net as
						// domainReplacementPlan.format -- see its doc
						// comment.
						return tokens[0]
					}
					return prefix + tokens[0]
				},
				PreserveIfUnknown: isPathSegmentPosition(text, matchStart),
			})
		}
	}
	return out, nil
}

// forcedDomainSuffix reports whether lower IS, or ends with a "."
// followed by, one of forceAsDomain's entries, the same subdomain-
// respecting boundary wellknown.go's compileAllowPatterns already uses
// ("(.*\.)?" + the domain, anchored), just as a direct string check
// instead of a compiled regex per entry, since forceAsDomain is
// typically tiny (an engagement's own handful of client domains).
func forcedDomainSuffix(lower string, forceAsDomain map[string]bool) (registrable string, ok bool) {
	for d := range forceAsDomain {
		if lower == d || strings.HasSuffix(lower, "."+d) {
			return d, true
		}
	}
	return "", false
}

// isPathSegmentPosition reports whether a match starting at start sits
// right after a bare "/" that is NOT the "://" of a URL scheme, i.e. it's
// somewhere in a URL's path, not its host. "https://example.com" and
// "ftp://example.com" both put the host directly after "://", which also
// ends in "/", so that specific case is excluded explicitly; a bare
// mention with nothing before it, or one preceded by whitespace/quote/
// "="/"?"/"&" (a query-parameter value; see PreserveIfUnknown's doc
// comment for why that's treated as more likely a real embedded target),
// is not a path position either.
func isPathSegmentPosition(text string, start int) bool {
	if start == 0 || text[start-1] != '/' {
		return false
	}
	return !strings.HasSuffix(text[:start], "://")
}

// domainReplacementPlan carries what's needed to reconstruct a
// structure-preserving domain from a resolved org-token: the
// registrable domain to use as the tokenstore key, and a format
// function that combines a token with the (possibly leak-checked-away)
// subdomain prefix and the real, preserved suffix.
type domainReplacementPlan struct {
	registrable string
	format      func(token string) string
}

// domainReplacement runs a lowercased FQDN through the public-suffix
// split and decides how to reconstruct it: preserving subdomain labels
// and the real suffix when safe, or collapsing to just the org-token
// plus real suffix when a subdomain label would leak a fragment of the
// org's own name (see subdomainLeaksOrgName). ok is false when fqdn has
// no recognized registrable domain at all, in which case the caller
// should leave the text untouched.
func domainReplacement(fqdn string) (domainReplacementPlan, domainParts, bool) {
	parts, ok := splitTenantSubdomainSaaS(fqdn)
	if !ok {
		parts, ok = splitDomain(fqdn)
	}
	if !ok {
		return domainReplacementPlan{}, domainParts{}, false
	}

	prefix := parts.subdomainPrefix
	if subdomainLeaksOrgName(prefix, parts.orgLabel) {
		prefix = ""
	}
	suffix := parts.suffix

	return domainReplacementPlan{
		registrable: parts.registrable,
		format: func(token string) string {
			if !ownDomainTokenLabelRe.MatchString(token) {
				// The store already had a token for this registrable
				// domain under a DIFFERENT entity type -- e.g. an
				// operator's block-list rule already claimed the same
				// bare string elsewhere in the text (GetOrCreateToken
				// is keyed by real value alone, not by entity type, so
				// it returns whatever token already exists regardless
				// of who's asking). Wrapping a foreign, already-opaque
				// token with this domain's own subdomain-prefix/
				// real-suffix template would corrupt it (e.g. gluing
				// an extra ".do" onto a block-list token). Use it as
				// the caller's caller already prepared it -- opaque,
				// as-is -- rather than wrapping it.
				return token
			}
			return prefix + token + "." + suffix
		},
	}, parts, true
}

// anchoredDomainRe is domainLabelUnicodeRe's own label grammar, anchored to the
// WHOLE string instead of hunting for a domain-shaped substring inside
// larger text. domainReplacement/splitDomain only ever split on dots and
// check suffix membership; they never validate that what's between the
// dots is even a syntactically legal hostname label, because every
// existing caller already filtered through domainLabelUnicodeRe's character class
// first. DomainRegistrablePart is called directly on arbitrary
// operator-supplied text (a rules.json value, a CLI argument), which
// hasn't been through that filter, so domainReplacement happily
// "succeeds" on "https://widgetcorp-fixture.do" and
// "admin@widgetcorp-fixture.do", treating "https://widgetcorp-fixture"/
// "admin@widgetcorp-fixture" as the org label, and reports each as its
// OWN bare registrable domain. That's not just cosmetically wrong: it
// would silently exclude a value like that from the ordinary block list
// (see rules.Compiled.ForcedDomains) while the "registrable" it computed
// never matches anything the real domain detector would ever extract
// (which correctly finds just "widgetcorp-fixture.do"), leaving the entry completely
// inert -- a real redaction gap, not just a wrong CLI message.
var anchoredDomainRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,24}$`)

// LooksLikeHostname reports whether value is syntactically a standalone
// hostname: dot-separated labels, nothing else (no scheme, no "@", no
// path), using the exact same grammar domainLabelUnicodeRe itself requires to ever
// match this text in real prose in the first place. Deliberately does
// NOT require the final label to be a recognized public suffix: an
// internal-only name (an Active Directory forest like "corp.internal",
// a purely-internal naming scheme) is never going to be on a public
// suffix list, but an operator who explicitly marks it IsDomain in
// rules.json is the actual authority on their own engagement's naming.
// See rules.Compiled.ForcedDomains and forcedDomainSuffix, the
// fallback path in domainDetector.Detect that this authorizes.
func LooksLikeHostname(value string) bool {
	return anchoredDomainRe.MatchString(strings.ToLower(value))
}

// DomainRegistrablePart reports the registrable (base) domain this tool's
// own domain detector would recognize within value, and whether value IS
// exactly that bare registrable domain (no subdomain, no "www." prefix).
// ok is false when value isn't a syntactically clean, standalone hostname
// at all -- a URL, an email address, an arbitrary string like a company
// name, or an RFC-reserved example domain (see isReservedDomain) all
// report ok == false, never a wrong answer.
//
// Exported for internal/rules and the CLI: a rules.json block entry an
// operator has explicitly marked as a domain (see rules.Entry.IsDomain)
// needs this to find its actual registrable part for forced domain-token
// treatment (DefaultCategorizedDetectorsWithForcedDomains), and to warn
// when what they marked isn't the bare form.
func DomainRegistrablePart(value string) (registrable string, isBare bool, ok bool) {
	lower := strings.ToLower(value)
	if !anchoredDomainRe.MatchString(lower) {
		return "", false, false
	}
	if isReservedDomain(lower) {
		return "", false, false
	}
	repl, _, ok := domainReplacement(lower)
	if !ok {
		return "", false, false
	}
	return repl.registrable, repl.registrable == lower, true
}

// filenameCollisionTLDs are real, delegated TLDs that also happen to be
// extremely common source-file/binary/doc-file extensions or
// object-attribute names: "<name>.<ext>" is shape-identical to a bare
// registrable domain under the corresponding ccTLD/gTLD. Unlike
// ".properties"/".name" (excluded outright; see tlds.go), every TLD in
// this set does see genuine real-world domain use, so instead of a
// blanket exclusion each one asks for one extra piece of positional
// evidence before being treated as a filename; see
// looksLikeBareFilename. A real domain still tokenizes correctly given
// any of the usual context (subdomain, "www.", a URL scheme, or a
// trailing "/", ":", "?").
//
//   - md, sh: Moldova/Saint Helena ccTLDs vs. Markdown files and shell
//     scripts ("CLAUDE.md", "catalina.sh"), which collide constantly with a
//     Claude Code session's own working files and a target's startup
//     scripts.
//   - style: a 2012+ new-gTLD vs. object/DOM/CSS attribute access
//     ("el.style.color") or a report-generation script's own source
//     (python-docx's "table.style").
//   - do: Dominican Republic's ccTLD vs. Apache Struts' action-mapping
//     URL extension ("Login.do", "Logout.do"), extremely common in
//     older enterprise Java web apps.
//   - so: Somalia's ccTLD vs. shared-object binaries ("libssl.so",
//     "libcrypto.so"), near-constant in binary exploitation / reverse
//     engineering findings.
//   - pl: Poland's ccTLD vs. Perl scripts ("exploit.pl"), common in
//     security tooling and PoC scripts.
//   - cc: Cocos Islands' ccTLD vs. C++ source files ("main.cc").
//   - rs: Serbia's ccTLD vs. Rust source files ("main.rs").
//   - ai: Anguilla's ccTLD vs. Adobe Illustrator files ("logo.ai",
//     "banner.ai"), common in phishing-simulation and report assets.
//   - mov: an Apple-operated gTLD vs. QuickTime video files
//     ("exploit.mov"), a common proof-of-concept recording format.
//   - in: India's ccTLD vs. classic autotools input files
//     ("configure.in").
//   - gs: South Georgia's ccTLD vs. Google Apps Script source
//     ("Code.gs").
//   - py: Paraguay's ccTLD vs. Python source files ("exploit.py",
//     "server.py"), as common in security tooling and PoC references as
//     any extension already in this set, maybe more so.
var filenameCollisionTLDs = map[string]bool{
	"md": true, "sh": true, "style": true, "do": true,
	"so": true, "pl": true, "cc": true, "rs": true, "ai": true, "mov": true,
	"in": true, "gs": true, "py": true,
}

// looksLikeBareFilename reports whether a domain candidate whose suffix is
// in filenameCollisionTLDs is more likely a plain filename mention than a
// real domain: no subdomain, no URL scheme/"www." prefix, and nothing
// URL-shaped (a path, port, or query string) immediately following. A
// filename reference essentially never carries any of those; a domain
// mentioned in running prose usually carries at least one; real .sh/.md
// domains (e.g. "https://crt.sh/?q=...") still pass through untouched by
// this check and get redacted normally. Every other TLD is unaffected.
func looksLikeBareFilename(text string, start, end int, parts domainParts) bool {
	if !filenameCollisionTLDs[parts.suffix] {
		return false
	}
	if parts.subdomainPrefix != "" {
		return false
	}
	before := strings.ToLower(text[:start])
	if strings.HasSuffix(before, "http://") || strings.HasSuffix(before, "https://") ||
		strings.HasSuffix(before, "ftp://") || strings.HasSuffix(before, "www.") {
		return false
	}
	if end < len(text) {
		switch text[end] {
		case '/', ':', '?':
			return false
		}
	}
	return true
}

// --- IPv4 ----------------------------------------------------------------

var ipv4Re = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}\b`)

type ipv4Detector struct{}

func (ipv4Detector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, loc := range ipv4Re.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		if strings.HasPrefix(val, tokenstore.TokenIPNetworkPrefix) {
			continue // already a token
		}
		addr, err := netip.ParseAddr(val)
		if err != nil {
			continue // shouldn't happen given the regex, but never trust a match blindly
		}
		if isReservedIP(addr) {
			continue // loopback or an RFC 5737 documentation range
		}

		// Tokenize the /24 network (first three octets), preserve the
		// host octet: two real addresses in the same /24 (e.g.
		// "203.0.113.24" and "203.0.113.22") get the SAME fake network
		// with only the last octet differing, so Claude can still see
		// they're neighbors, the same way subdomain labels stay visible
		// under a tokenized org domain.
		b := addr.As4()
		networkKey := fmt.Sprintf("%d.%d.%d", b[0], b[1], b[2])
		hostOctet := fmt.Sprintf("%d", b[3])

		out = append(out, Detection{
			Start: loc[0], End: loc[1],
			Lookups: []lookup{{Real: networkKey, Type: tokenstore.EntityIPNetwork}},
			Format:  func(tokens []string) string { return tokens[0] + "." + hostOctet },
		})
	}
	return out, nil
}

// --- IPv6 ------------------------------------------------------------------
//
// RE2 has no lookaround, so rather than trying to avoid matching inside
// a larger token via (?<!...)/(?!...), this uses a loose candidate
// regex (any maximal run of hex digits and colons) and leans entirely
// on netip.ParseAddr for precision. \b doesn't work well as a boundary
// here (":" is a non-word character, so a leading "::"
// after whitespace has no word/non-word transition for \b to anchor on),
// so this deliberately matches on the character class alone;
// candidate's edges are already exact because the regex stops at the
// first character outside [0-9A-Fa-f:]. Requiring at least two colons in
// code (not in the regex; it's awkward to express "at least 2 colons
// somewhere in a variable-length run" as a single RE2 pattern) rejects a
// bare hex number immediately; ParseAddr rejects everything else that
// isn't a real address, including a MAC address, which looks
// superficially similar (hex groups separated by colons) but is
// syntactically invalid IPv6 (6 groups of exactly 2 hex digits, no valid
// "::" compression), so it fails to parse and is skipped for free.
var ipv6CandidateRe = regexp.MustCompile(`[0-9A-Fa-f:]{2,45}`)

// formatIPv6Groups renders an even-length byte slice as colon-separated
// 4-hex-digit groups, e.g. formatIPv6Groups([]byte{0,0,0,0,0,0,0x12,0x34})
// -> "0000:0000:0000:1234". Used to render the preserved interface-ID
// half of an IPv6 address in canonical form.
func formatIPv6Groups(b []byte) string {
	groups := make([]string, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		groups = append(groups, fmt.Sprintf("%02x%02x", b[i], b[i+1]))
	}
	return strings.Join(groups, ":")
}

// minIPv6HexDigits is the fewest explicit hex digits (not colons) a
// candidate must contain before it's even tried against netip.ParseAddr.
// Bare "::" (zero hex digits) is a syntactically valid, complete IPv6
// address (the "unspecified"
// address), and short forms like "d::" (one hex digit) are valid too,
// but both shapes are also exactly what C++/Rust/Ruby scope resolution,
// LDIF's "attribute:: value" notation, and even prose quoting a
// colon-delimited protocol string look like. A genuinely allocated
// address a pentest target would actually use (link-local, ULA, or
// global) virtually always carries substantially more explicit hex
// content than that, even fully compressed (e.g. "fe80::1" already has
// 5 hex digits). This is a shape/volume heuristic, not a semantic one:
// it can't be fooled by picking hex-looking segment names, but it also
// can't tell a genuinely rare, hand-crafted low-hex-content real address
// from a false positive: an explicit, deliberate trade favoring the
// vastly more common false-positive class over that vanishingly rare
// true-positive shape.
const minIPv6HexDigits = 4

func countHexDigits(s string) int {
	n := 0
	for _, r := range s {
		if r != ':' {
			n++
		}
	}
	return n
}

type ipv6Detector struct{}

func (ipv6Detector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, loc := range ipv6CandidateRe.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		if strings.Count(val, ":") < 2 {
			continue
		}
		if countHexDigits(val) < minIPv6HexDigits {
			continue // e.g. "::" or "d::": syntactically valid but far more likely a code/protocol separator than a real address
		}
		if strings.HasPrefix(strings.ToLower(val), tokenstore.TokenIPv6NetworkPrefix) {
			continue // already a token
		}
		addr, err := netip.ParseAddr(val)
		if err != nil {
			continue // candidate wasn't actually a valid IPv6 address
		}
		if !addr.Is6() {
			continue
		}
		if isReservedIP(addr) {
			continue // ::1, or the RFC 3849 documentation range
		}

		// Same principle as IPv4: tokenize the /64 network (first 64
		// bits), preserve the interface ID (last 64 bits): two real
		// addresses on the same /64 stay visibly related. As16() gives
		// the full 128-bit form regardless of how "::" compressed the
		// input, so there's no manual compression-parsing needed.
		b := addr.As16()
		networkKey := hex.EncodeToString(b[:8])
		hostPart := formatIPv6Groups(b[8:])

		out = append(out, Detection{
			Start: loc[0], End: loc[1],
			Lookups: []lookup{{Real: networkKey, Type: tokenstore.EntityIPv6Network}},
			Format: func(tokens []string) string {
				full := tokens[0] + ":" + hostPart
				// Re-parse and re-render through netip so the visible
				// token uses Go's canonical "::"-compressed form instead
				// of the fully-expanded 8-group form built above; pure
				// readability, functionally identical either way.
				if addr, err := netip.ParseAddr(full); err == nil {
					return addr.String()
				}
				return full
			},
		})
	}
	return out, nil
}

// --- phone (US/NANP-shaped) ----------------------------------------------

// phoneRe covers both conversational formats (555-867-5309, 555.867.5309,
// (555) 867-5309) and the whois-style "+1.4155551234" format: a country
// code, a single dot, then the remaining digits with no further
// separators, which is how registrars commonly report registrant phone
// numbers.
var phoneRe = regexp.MustCompile(`\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b|\+\d{1,3}\.\d{6,14}\b`)

type phoneDetector struct{}

func (phoneDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, loc := range phoneRe.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		normalized := strings.ReplaceAll(strings.ReplaceAll(val, ".", "-"), " ", "-")
		if strings.Contains(normalized, tokenstore.TokenPhonePrefix) {
			continue // already a token
		}
		out = append(out, simpleDetection(loc[0], loc[1], val, tokenstore.EntityPhone))
	}
	return out, nil
}

// --- international phone (non-NANP, "+"-prefixed) -------------------------
//
// phoneRe above only covers NANP-shaped numbers (with or without a "+1")
// and the whois dot-separated format. A general international number
// ("+91 98765 43210", "+44 20 7946 0958", ...) has no single regex shape;
// group sizes and lengths vary by country. This uses the same "loose
// candidate, precise Go-side validation" split as the IPv6 detector: a
// permissive regex finds anything shaped like "+ digits and common
// separators", then parseIntlPhone (intlphone.go) validates it against a
// curated real-calling-code table and plausible length bounds; see that
// file's doc comment for why this is a deliberately hand-rolled check
// rather than a full libphonenumber-equivalent dependency.
//
// The store key is the canonical "+<cc><subscriber digits>" (E.164-style,
// no separators), not the exact matched text, so "+91 98765 43210" and
// "+919876543210" (same number, different
// human formatting) share one token, the same reasoning as lowercasing a
// domain before using it as a store key. One consequence: Detokenize
// restores that canonical digit form, not necessarily byte-identical to
// however the original was written, unlike the NANP phoneDetector above,
// which stores the literal matched text and round-trips byte-exact
// because it has no cross-format dedup need to solve.
// The separator class deliberately excludes newlines (space/tab only,
// not \s): in text like "+91-8082282294\n3. Nikhil Raut" (a phone number
// at the end of a numbered list item), \s would match the newline and
// pull the next line's "3" in as if it were another digit of the phone
// number. Since the whole match becomes the replacement span (unlike
// Snyk/Azure-key above, whose capture group insulates them from this),
// that would silently drop "\n3" from the output, corrupting the list
// numbering below.
var intlPhoneCandidateRe = regexp.MustCompile(`\+[1-9](?:[ \t().-]?\d){6,14}`)

// ownIntlPhoneTokenRe matches this detector's OWN emitted output shape:
// "+<real country code>-" followed by the minted subscriber token
// ("555-" + 4 digits). See intlPhoneDetector.Format below for where
// that shape is produced, and engine.go's intlPhoneTokenRe for where
// it's parsed back.
//
// The guard exists because the fake output is itself syntactically a
// valid-looking international number: without it, re-scanning a prior
// turn's output echoed back in conversation history would mint an
// entirely new, different fake number every time, breaking both
// idempotency and the "same real value always maps to the same
// placeholder" guarantee.
//
// Anchored to the whole candidate rather than a substring test for
// TokenIntlPhonePrefix, because "555-" is four ordinary characters that
// turn up inside real human phone formatting all the time: an Indian
// mobile written "+91-98555-01234" contains it by coincidence, and a
// substring test reads that as already-tokenized and sends the real
// number to the model untouched, while the same number written with
// spaces is redacted normally.
//
// A token that a wider greedy match swallows along with adjacent digits
// (e.g. "+91-555-4953 4567" in a column of numbers) won't match this
// anchored pattern, and doesn't need to: the whole token is a
// registered wire span, so Engine.filterAlreadyTokenized drops any
// detection overlapping it, from the store rather than by shape guess.
var ownIntlPhoneTokenRe = regexp.MustCompile(`^\+\d{1,3}-` + regexp.QuoteMeta(tokenstore.TokenIntlPhonePrefix) + `\d{4}$`)

type intlPhoneDetector struct{}

func (intlPhoneDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, loc := range intlPhoneCandidateRe.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]

		if ownIntlPhoneTokenRe.MatchString(val) {
			continue // already a token
		}

		cc, subscriber, ok := parseIntlPhone(val)
		if !ok {
			continue
		}
		real := "+" + cc + subscriber // canonical E.164-style form, restored verbatim on Detokenize

		out = append(out, Detection{
			Start: loc[0], End: loc[1],
			Lookups: []lookup{{Real: real, Type: tokenstore.EntityIntlPhone}},
			Format: func(tokens []string) string {
				// The real country calling code is preserved literally,
				// the same principle as a domain's public suffix, so Claude
				// retains the number's country/region context; only the
				// subscriber portion (tokens[0]) is opaque.
				return fmt.Sprintf("+%s-%s", cc, tokens[0])
			},
		})
	}
	return out, nil
}

// --- JWT -------------------------------------------------------------------

var jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)

var jwtDetector = wholeMatchDetector{jwtRe, tokenstore.EntityJWT, tokenstore.TokenJWTPrefix}

// --- Flask itsdangerous-signed tokens --------------------------------------
//
// A Flask CSRF token like "csrf_token=ImMyYjM3YWJhN2RlNzg0MDM0NDgw
// OTM3ZjhjMGU2ZjI5ZGVjMzVmZjYi.Dudyfw.q4PuqxwtjVP8GhkK5xzf1dsLYg" would
// otherwise pass through completely untouched: decoding the first
// segment shows it's itsdangerous's URLSafeTimedSerializer format
// (payload.timestamp.signature), the standard way Flask apps sign CSRF
// tokens and session cookies. Same 3-dot-segment shape as a JWT, but it
// never starts with "eyJ" (that's a JSON header specifically;
// itsdangerous payloads aren't JSON), so jwtRe correctly doesn't match
// it; it genuinely isn't a JWT.
//
// Two ways to close this gap, with different false-positive tradeoffs:
// broaden the JWT-shape match to drop the "eyJ" requirement (any 3
// generic dot-separated base64url segments), or keep the shape narrow
// but require nearby context. The former is a meaningfully bigger
// false-positive surface: "3 dot-separated alnum/hyphen/underscore
// segments, each 10+ chars" is generic enough to risk matching things
// like a version-qualified namespaced identifier. Chose the latter:
// require a keyword (csrf_token=, session=, or the literal word
// itsdangerous) within a tight window before the value, the same
// PrefixRegex technique already used for snykRe. Trade-off accepted
// deliberately: this will miss itsdangerous tokens used for other
// purposes (password-reset/email-confirmation tokens under a different
// variable name): narrower coverage in exchange for not firing on
// unrelated dot-separated text.
// The middle segment (itsdangerous's base64url-encoded 4-byte Unix
// timestamp) is inherently short (a real timestamp segment is only
// around 6 characters , e.g. "Dudyfw"), so only the payload and
// signature segments require a meaningful minimum length; requiring 10+
// on all three (a generic "3 long segments" assumption) would miss the
// real-world shape entirely.
var itsdangerousRe = regexp.MustCompile(`(?i:csrf_token|csrftoken|session|itsdangerous)(?:.|[\n\r]){0,20}?\b([A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,10}\.[A-Za-z0-9_-]{15,})\b`)

type itsdangerousDetector struct{}

func (itsdangerousDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, m := range itsdangerousRe.FindAllStringSubmatchIndex(text, -1) {
		start, end := m[2], m[3]
		val := text[start:end]
		if strings.HasPrefix(val, tokenstore.TokenItsdangerousPrefix) || strings.HasPrefix(val, tokenstore.TokenJWTPrefix) {
			continue // already a token
		}
		if jwtRe.MatchString(val) {
			continue // JWT-shaped (starts with eyJ); let jwtDetector claim it instead
		}
		out = append(out, simpleDetection(start, end, val, tokenstore.EntityItsdangerousToken))
	}
	return out, nil
}

// --- Bearer / opaque API tokens --------------------------------------------
//
// Matches only the token VALUE, not the literal word "Bearer"; that word
// is protocol furniture, not PII, and leaving it visible costs nothing
// while helping Claude recognize "this is an auth header" at a glance.
// JWT-shaped bearer tokens are deliberately left to jwtDetector instead of
// being claimed here too, so each secret is redacted by exactly one
// detector rather than two overlapping ones fighting over the same span.
var bearerRe = regexp.MustCompile(`(?i)\bBearer[ \t]+([A-Za-z0-9_\-.~+/]{20,}={0,2})\b`)

// bareCredentialKeywordRe is a real leak found live: bearerRe alone only
// catches a token framed as an HTTP Authorization header ("Bearer
// <token>"). A real API key handed to the model as a bare value in
// ordinary chat/documentation prose -- "you can use this key <token>
// save it", "API key: <token>" -- carries no such framing at all, and
// went completely unredacted, repeatedly, because nothing else in this
// detector set claims a bare high-entropy value with no other shape to
// anchor on. Same keyword-anchored-window technique already used for
// hashKeywordRe/awsSecretKeyKeywordRe: only claim a candidate value when
// a real credential-labeling keyword appears before it, not any bare
// 20+ char token-shaped string unconditionally (that would be a
// false-positive minefield -- git SHAs, session IDs, correlation IDs
// are all the same shape).
//
// The 0,200 window is deliberately much wider than hashKeywordRe's 0,80:
// confirmed from the real leak that real-world phrasing puts substantial
// text between the keyword and the value -- a sentence explaining what
// the key is for and how to use it, THEN the value, easily 100+
// characters. Still lazy ({0,200}?), so it only ever claims the CLOSEST
// candidate after the keyword, never reaching past a nearer one.
//
// The candidate value class is deliberately NARROWER than bearerRe's --
// [A-Za-z0-9_-] only, no ".", "/", "+", "~", or "=" padding. bearerRe can
// safely allow those (a URL essentially never follows "Bearer " directly,
// so its tight adjacency alone rules out false matches), but this
// detector's much wider 200-char window doesn't have that protection: a
// real ordinary URL sitting within 200 chars of any trigger keyword is a
// completely routine thing to find in pentest-adjacent text, and "." /
// "/" are exactly the characters URLs are made of. With the wider
// bearerRe-style class, a single sentence mentioning "SECRET_KEY"
// followed by an ordinary Django docs URL shreds into two bogus
// "credentials" -- the domain and the URL fragment. Real
// vendor API keys (the motivating case) are essentially always
// underscore/hyphen-separated alphanumeric segments, never containing
// "."/"/" themselves, so this loses no real coverage for the actual
// target shape. Known, accepted narrower miss: a bare (non-AWS-specific)
// classic base64 secret using "+"/"/" in this exact bare-with-keyword
// framing won't match -- the same tradeoff already accepted elsewhere in
// this file (see awsSecretKeyKeywordRe, which needs its own specific
// keyword for exactly that shape).
//
// This window also over-claims plain-English identifiers sitting near
// a keyword -- an env var NAME (not its value,
// e.g. "WIDGETCORP_SERVICE_API_KEY_CONFIG_NAME") or a URL path slug
// (e.g. "std-setting-SECRET_KEY-reference-page"), both 20+ char runs of
// nothing but letters/underscores/hyphens. Every credential shape this
// detector set recognizes anywhere in this file -- vendor API keys, AWS
// keys, JWTs, password hashes -- is generated from random bytes, so it
// always mixes digits in with letters; a run with zero digits across
// 20+ characters is a reliable, general signal of "human-authored
// identifier," not "generated secret." See the digit check in
// bearerDetector.Detect below, applied only to matches from this regex
// (not bearerRe's tightly-framed "Bearer <token>" matches, which don't
// need it and are left alone).
var bareCredentialKeywordRe = regexp.MustCompile(`(?i:\bapi[ _-]?key\b|\baccess[ _-]?token\b|\bauth[ _-]?token\b|\bsecret[ _-]?key\b|\bclient[ _-]?secret\b|\bauth[ _-]?key\b|\baccess[ _-]?key\b|\bapi[ _-]?secret\b)(?:.|[\n\r]){0,200}?\b([A-Za-z0-9_-]{20,})\b`)

// awsSecretValueShapeRe is the exact value shape awsSecretKeyKeywordRe
// requires (40 base64-alphabet characters, no underscore/hyphen/tilde).
// bareCredentialKeywordRe's keyword list overlaps with AWS's own labeling
// ("aws_secret_access_key" contains "access_key") and its value character
// class is a superset of this one, so without some check a value like
// this would get claimed here too, with the wrong, generic bearer-token
// format instead of the structured AWS-secret-key one both detectors
// would otherwise agree on.
//
// This shape check alone is deliberately NOT sufficient to defer, and
// bearerDetector.Detect doesn't use it that way (see there): confirmed
// live, an ordinary 40-char hex git commit SHA near an unrelated keyword
// ("access token") matches this shape too, and deferring unconditionally
// on shape meant it got skipped entirely: no redaction at all, not even
// the generic bearer-token placeholder. Deferring must additionally
// confirm an AWS-secret-labeling keyword genuinely preceded THIS value
// (i.e. awsSecretKeyKeywordRe itself would also claim the identical
// span), not just that the value happens to be the right shape.
var awsSecretValueShapeRe = regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)

type bearerDetector struct{}

func (bearerDetector) Detect(text string) ([]Detection, error) {
	var out []Detection

	// Spans genuinely preceded by an AWS-secret-labeling keyword (not
	// just shaped like one); see awsSecretValueShapeRe's doc comment.
	awsAnchored := make(map[[2]int]bool)
	for _, m := range awsSecretKeyKeywordRe.FindAllStringSubmatchIndex(text, -1) {
		awsAnchored[[2]int{m[2], m[3]}] = true
	}

	claim := func(start, end int) {
		val := text[start:end]
		if strings.HasPrefix(val, tokenstore.TokenBearerPrefix) || strings.HasPrefix(val, tokenstore.TokenJWTPrefix) {
			return // already a token
		}
		if jwtRe.MatchString(val) {
			return // JWT-shaped; let jwtDetector claim it instead
		}
		if awsKeyRe.MatchString(val) {
			return // AWS-key-ID shaped; let awsKeyDetector claim it instead
		}
		if awsSecretValueShapeRe.MatchString(val) && awsAnchored[[2]int{start, end}] {
			return // genuinely AWS-secret-keyword-anchored; let awsKeyDetector claim it with the right format
		}
		out = append(out, simpleDetection(start, end, val, tokenstore.EntityBearerToken))
	}
	for _, m := range bearerRe.FindAllStringSubmatchIndex(text, -1) {
		claim(m[2], m[3]) // capture group 1: the token, not "Bearer "
	}
	for _, m := range bareCredentialKeywordRe.FindAllStringSubmatchIndex(text, -1) {
		start, end := m[2], m[3]
		if !strings.ContainsAny(text[start:end], "0123456789") {
			continue // no digit at all -- an ordinary identifier/slug/name, not a generated secret
		}
		claim(start, end)
	}
	return out, nil
}

// --- AWS access key ID -------------------------------------------------

// All eight of AWS's own documented unique-identifier prefixes for this
// ID shape, not just AKIA (long-term IAM user key) and ASIA
// (temporary/STS session key): AIDA (IAM user), AROA (IAM role, which shows
// up constantly in cloud recon via sts:AssumeRole/GetCallerIdentity),
// AIPA (EC2 instance profile, legacy), ANPA (managed policy), ANVA
// (policy version), APKA (public key). Same 16-char suffix shape for
// all eight.
var awsKeyRe = regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b`)

// awsSecretKeyKeywordRe covers the OTHER half of an AWS credential pair:
// awsKeyRe above only ever matches the key ID (AKIA/ASIA/...), never
// the secret access key that's always issued alongside it, which is the
// actual authentication material. The secret has no fixed prefix to
// anchor detection on the way the ID does: it's 40 characters of
// free-form base64-alphabet output, a shape common enough on its own
// (any base64-encoded hash or random token is the same length/charset)
// that matching it unconditionally would be a false-positive minefield.
// Same keyword-anchored-window technique as hashKeywordRe: only claim a
// 40-char base64-alphabet run when a secret-key-labeling keyword
// (aws_secret_access_key, AWS_SECRET_ACCESS_KEY, SecretAccessKey, "aws
// secret access key", aws_secret_key) appears shortly before it,
// covering AWS CLI credentials files, environment variable dumps,
// Terraform state/output, and IAM API JSON responses, which all label
// the value this way.
var awsSecretKeyKeywordRe = regexp.MustCompile(`(?i:aws_secret_access_key|aws secret access key|secretaccesskey|aws_secret_key|aws secret key)(?:.|[\n\r]){0,40}?\b([A-Za-z0-9/+]{40})\b`)

// awsKeyDetector covers both halves of an AWS credential pair under one
// "cloud.aws" category (matching how a real credential pair is always
// handled together, not toggled independently): the key ID via awsKeyRe
// and the secret access key via awsSecretKeyKeywordRe.
type awsKeyDetector struct{}

func (awsKeyDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, loc := range awsKeyRe.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		if strings.HasPrefix(val, tokenstore.TokenAWSKeyPrefix) {
			continue // already a token
		}
		out = append(out, simpleDetection(loc[0], loc[1], val, tokenstore.EntityAWSKey))
	}
	for _, m := range awsSecretKeyKeywordRe.FindAllStringSubmatchIndex(text, -1) {
		start, end := m[2], m[3]
		val := text[start:end]
		if strings.HasPrefix(val, tokenstore.TokenAWSSecretKeyPrefix) {
			continue // already a token
		}
		out = append(out, simpleDetection(start, end, val, tokenstore.EntityAWSSecretKey))
	}
	return out, nil
}

// --- Password hashes (MD5/NTLM/SHA-1/SHA-256) --------------------------
//
// Bare hex-length-only hash detection is a genuine gap for pentest work
// (hash dumps from Mimikatz/secretsdump/hashcat are
// directly-crackable-credential artifacts) but also a genuine
// false-positive trap if done naively: a 40-char hex string is EXACTLY
// the shape of a git commit SHA, which appears constantly in completely
// unremarkable tool output (git log, git blame, commit URLs, CI logs).
// Uses the same keyword-anchored-gate technique already used for
// itsdangerousRe/snykRe: hashKeywordRe only claims a value when a
// hash-type keyword (ntlm, md5, sha1, sha256, "nt hash", "lm hash",
// "password hash") appears within a tight window before it. An
// ordinary git SHA or file checksum with no such label nearby is
// deliberately left untouched.
//
// Longest length alternative listed first so a 64-char SHA-256 isn't
// mis-matched as just its own first-32-chars MD5-shaped prefix (RE2 has
// no backreferences/lookaround, so this needs the length ordering to be
// explicit rather than relying on a possessive/atomic quantifier).
//
// Each keyword is individually \b-wrapped: without it, "sha256" matches
// as a bare substring of "sha256sum"/"md5sum", the completely ordinary
// file-integrity-checksum commands (`sha256sum file.tar.gz`), not a
// password hash at all. \b requires a real word-boundary transition,
// which "256sum" (all word characters, no break) never has, so
// word-wrapping excludes the checksum-command case while still matching
// "SHA256:" / "sha256 hash" (":" and " " are non-word characters, so the
// boundary is genuinely there).
//
// "sha256"/"sha-256" is deliberately NOT a trigger keyword at all: even
// word-boundary-wrapped, it's still too overloaded with legitimate
// non-password meanings that use the exact same "sha256:<64 hex>" shape
// (e.g. "docker image sha256:e3b0c442..." is an ordinary image digest,
// not a credential). Real AD/Windows password
// hashes practically never get labeled "SHA256" anyway (NTLM/LM/MD5/
// SHA-1 are what actually shows up in credential-dump contexts), so
// dropping it loses effectively no real coverage. A SHA-256-length
// value under a genuinely unambiguous label ("password hash: <64
// hex>") is still caught via the "password hash"/"hashed password"
// keywords below; only the bare, overloaded "sha256" trigger is gone.
// The 0,80 window (previously 0,20) was widened after confirming it
// missed a genuinely common real-world shape: a descriptive header line
// followed by the actual "username:hash" dump line, e.g.
// "NTLM hashes found:\nadmin:aad3b435b51404eeaad3b435b51404ee". The
// gap from the keyword to the hash there is ~21 chars, just over the
// old window. 80 comfortably covers a header line's remaining text plus
// a following line's username/RID prefix, while staying lazy (0,80?)
// so it still only ever claims the CLOSEST hex-shaped match after the
// keyword. A keyword mention with no genuinely nearby hash still
// leaves ordinary distant hex content (a git SHA later in the same
// paragraph, say) untouched, matching TestPasswordHash_NoKeywordNoMatch.
var hashKeywordRe = regexp.MustCompile(`(?i:\bntlm\b|\bnt hash\b|\blm hash\b|\bmd5\b|\bsha-?1\b|\bpassword hash\b|\bhashed password\b)(?:.|[\n\r]){0,80}?\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b`)

// secretsdumpPairRe matches the LM:NT hash pair from Impacket
// secretsdump.py / pwdump-style output:
// "user:rid:LMHASH:NTHASH:::". No keyword anchoring needed here: the
// trailing triple-colon is distinctive enough on its own (virtually
// nothing else produces this exact "32hex:32hex:::" shape), the same
// reasoning as awsKeyRe needing no extra context beyond its own
// prefix+length.
var secretsdumpPairRe = regexp.MustCompile(`\b([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::`)

type hashDetector struct{}

func (hashDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	claim := func(start, end int) {
		val := text[start:end]
		if strings.HasPrefix(val, tokenstore.TokenPasswordHashPrefix) {
			return // already a token
		}
		out = append(out, simpleDetection(start, end, val, tokenstore.EntityPasswordHash))
	}
	for _, m := range hashKeywordRe.FindAllStringSubmatchIndex(text, -1) {
		claim(m[2], m[3])
	}
	for _, m := range secretsdumpPairRe.FindAllStringSubmatchIndex(text, -1) {
		claim(m[2], m[3]) // LM hash
		claim(m[4], m[5]) // NT hash
	}
	return out, nil
}

// --- AD machine account name (secretsdump.py/pwdump line shape) --------

// machineAccountSecretsdumpRe matches a $-suffixed AD machine/computer
// account name in the same secretsdump.py/pwdump line shape
// secretsdumpPairRe already matches for the hash pair on that same line
// -- "MACHINE$:1000:LMHASH:NTHASH:::". Restructured from the reference
// tool's lookahead-based pattern into a full-line-shape match with a
// capture group, since RE2 has no lookaround -- same restructuring
// secretsdumpPairRe itself needed. Deliberately narrow: ONLY $-suffixed
// names (a hard, unambiguous AD naming convention), never the ordinary
// human usernames that can appear in the exact same line shape
// ("jdoe:1105:...:::") -- those are prose-shaped free text, the same
// deferred general-NER problem as any other name, not something a
// structural regex can safely claim.
var machineAccountSecretsdumpRe = regexp.MustCompile(`\b([A-Za-z][A-Za-z0-9_-]{0,30}\$):\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::`)

var adMachineAccountDetector = capturedMatchDetector{machineAccountSecretsdumpRe, tokenstore.EntityADMachineAccount, tokenstore.TokenADMachineAccountPrefix}

// --- Group Policy Preferences cpassword ---------------------------------

// gppCPasswordRe matches a Group Policy Preferences "cpassword" XML
// attribute value -- a base64, AES-256-CBC "encrypted" password that is,
// in practice, exactly as sensitive as a plaintext one: Microsoft
// published the fixed AES key used for EVERY GPP cpassword value in
// MS14-025, so any real GPP-password-cracking tool (Get-GPPPassword.ps1,
// gpp-decrypt, etc.) decrypts it directly with that same published key.
// The "cpassword=" attribute name itself is distinctive enough alone
// (a fixed, literal XML attribute name that appears in exactly this one
// context -- Groups.xml/ScheduledTasks.xml/Services.xml and nowhere
// else) that no additional keyword gate is needed, same reasoning as
// secretsdumpPairRe's trailing triple-colon needing no keyword either.
var gppCPasswordRe = regexp.MustCompile(`(?i)\bcpassword\s*=\s*"([A-Za-z0-9+/]{16,}={0,2})"`)

var gppCPasswordDetector = capturedMatchDetector{gppCPasswordRe, tokenstore.EntityGPPCPassword, tokenstore.TokenGPPCPasswordPrefix}

// --- PEM private key block --------------------------------------------

// Matches the whole armored block, any key type (RSA/EC/DSA/OPENSSH/
// generic). RE2 has no backreferences, so the BEGIN and END labels can't
// be required to match each other exactly; over-matching a block whose
// labels happen to differ is safe (still redacts real key material); it
// just can't be expressed as a single precise regex.
var pemKeyRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)

type pemKeyDetector struct{}

func (pemKeyDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, loc := range pemKeyRe.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		if strings.Contains(val, "REDACTED PRIVATE KEY") {
			continue // already a token
		}
		out = append(out, simpleDetection(loc[0], loc[1], val, tokenstore.EntityPEMKey))
	}
	return out, nil
}

// --- MAC address ---------------------------------------------------------

var macRe = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`)

type macDetector struct{}

func (macDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, loc := range macRe.FindAllStringIndex(text, -1) {
		// Stored (and later restored) lowercased, the same dedup-by-
		// canonical-form tradeoff as domains/emails/intl-phone numbers:
		// case carries no meaning in a MAC address, so an uppercase and
		// lowercase writing of the same address share one token instead
		// of minting two. Detokenize is therefore not byte-identical to
		// whatever case the original was written in.
		lower := strings.ToLower(text[loc[0]:loc[1]])
		switch lower {
		case "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00":
			continue // broadcast / null, never a real device identifier
		}
		if strings.HasPrefix(lower, tokenstore.TokenMACPrefix) {
			continue // already a token (our own locally-administered range)
		}
		out = append(out, simpleDetection(loc[0], loc[1], lower, tokenstore.EntityMAC))
	}
	return out, nil
}

// --- Aadhaar (Indian national ID) ---------------------------------------

// Matches a bare 12-digit run, or the common 4-4-4 space-grouped display
// form. \b on both ends means this can never match a 12-digit substring
// carved out of a longer digit run (there's no word/non-word transition
// between two digits for \b to anchor on there); see the doc comment on
// verhoeffValid for why the checksum gate matters beyond this shape check.
var aadhaarRe = regexp.MustCompile(`\b\d{4} \d{4} \d{4}\b|\b\d{12}\b`)

type aadhaarDetector struct{}

func (aadhaarDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, loc := range aadhaarRe.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		digits := strings.ReplaceAll(val, " ", "")
		if strings.HasPrefix(digits, "0000") {
			continue // this tool's own token range (real Aadhaar numbers never start 0 or 1)
		}
		if isDegenerateDigitRun(digits) {
			continue // e.g. "000000000000" or "123456789012", never a real Aadhaar
		}
		if !verhoeffValid(digits) {
			continue
		}
		// Keyed by the canonical 4-4-4 spaced form (UIDAI's own display
		// convention) rather than the exact matched text, so a
		// continuous and a spaced mention of the SAME number share one
		// token, the same principle as lowercasing a domain before using it
		// as the store key. This also means Detokenize always restores
		// the conventional spaced form, not necessarily byte-identical
		// to however the original was written.
		canonical := digits[:4] + " " + digits[4:8] + " " + digits[8:]
		out = append(out, simpleDetection(loc[0], loc[1], canonical, tokenstore.EntityAadhaar))
	}
	return out, nil
}

// isDegenerateDigitRun reports whether digits is all one repeated digit,
// or a simple ascending/descending run: placeholder-shaped values
// ("000000000000", "123456789012") that could coincidentally pass the
// Verhoeff check but are never real.
func isDegenerateDigitRun(digits string) bool {
	if digits == "" {
		return false
	}
	allSame := true
	ascending := true
	descending := true
	for i := 1; i < len(digits); i++ {
		if digits[i] != digits[0] {
			allSame = false
		}
		if digits[i] != digits[i-1]+1 {
			ascending = false
		}
		if digits[i] != digits[i-1]-1 {
			descending = false
		}
	}
	return allSame || ascending || descending
}

// --- PAN (Indian Permanent Account Number) -------------------------------
//
// Structure (confirmed against the Income Tax Department's own published
// description, not assumed): positions 1-3 are an arbitrary AAA-ZZZ
// letter sequence with no individual significance; position 4 is a
// holder-type code from a small fixed set (checked below); position 5 is
// the first letter of the holder's name/surname (no constraint, so it can't be
// used for validation); positions 6-9 are 4 digits; position 10 is
// documented as "a check-sum to verify validity" but, unlike Aadhaar's
// publicly specified Verhoeff algorithm, the Income Tax Department has
// never published the actual checksum formula, so it can't be
// implemented or verified here. The holder-type-code gate below is
// therefore the strongest structural check available without guessing at
// an unverified algorithm, which risks false negatives (rejecting real
// PANs) worse than the false-positive reduction it would buy.

var panRe = regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`)

// panValidHolderCodes are the real, documented 4th-character values (the
// "holder type") a genuine PAN can have: P (individual), C (company), H
// (HUF), A (AOP), B (BOI), G (government), J (artificial juridical
// person), L (local authority), F (firm), T (trust). Restricting to this
// set (instead of accepting any letter) rejects most of the random
// 10-char uppercase-alnum strings shape alone would otherwise match.
var panValidHolderCodes = map[byte]bool{
	'P': true, 'C': true, 'H': true, 'A': true, 'B': true,
	'G': true, 'J': true, 'L': true, 'F': true, 'T': true,
}

type panDetector struct{}

func (panDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, loc := range panRe.FindAllStringIndex(text, -1) {
		val := text[loc[0]:loc[1]]
		if strings.HasPrefix(val, tokenstore.TokenPANPrefix) {
			continue // already a token
		}
		if !panValidHolderCodes[val[3]] {
			continue // 4th character isn't a real holder-type code
		}
		out = append(out, simpleDetection(loc[0], loc[1], val, tokenstore.EntityPAN))
	}
	return out, nil
}

// --- vendor credential detectors -------------------------------------------
//
// All ten below are fully opaque, whole-secret detections (see
// EntityGitHubToken's doc comment in store.go for why no structure is
// preserved), narrowed to the subset genuinely likely to show up in
// pentest recon (leaked configs, .env files, CI logs, source code)
// rather than the full space of consumer-SaaS API key formats, which is
// out of scope for this tool. None of these detectors validate via
// checksum math or a live API call (GitHub user lookup, Slack auth.test,
// etc.), deliberately: a silent redaction proxy making outbound calls
// to test whether a found credential is real would itself be a
// detectable, unwanted side effect (see intlphone.go's sibling reasoning
// on this same tradeoff).

var githubTokenRe = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255}\b`)

var githubTokenDetector = wholeMatchDetector{githubTokenRe, tokenstore.EntityGitHubToken, tokenstore.TokenGitHubPrefix}

var gitlabTokenRe = regexp.MustCompile(`\bglpat-[a-zA-Z0-9\-=_]{20,22}\b`)

var gitlabTokenDetector = wholeMatchDetector{gitlabTokenRe, tokenstore.EntityGitLabToken, tokenstore.TokenGitLabPrefix}

// slackTokenRe covers all four Slack token sub-types (xoxb/xoxp/xoxa/
// xoxr: bot/user/workspace-access/workspace-refresh) in one pattern,
// since RE2 character classes make that a safe merge (the shapes are
// otherwise identical) and this tool doesn't need to distinguish the
// sub-type.
var slackTokenRe = regexp.MustCompile(`\bxox[bpar]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b`)

var slackTokenDetector = wholeMatchDetector{slackTokenRe, tokenstore.EntitySlackToken, tokenstore.TokenSlackTokenPrefix}

// slackWebhookRe matches both the "services" and "workflows" webhook URL
// shapes, capturing (group 1) the sensitive workspace/secret path
// separately from (implicit, outside the match) nothing. Unlike Bearer,
// the whole match including "hooks.slack.com/..." is redacted here,
// because unlike "Bearer " that host IS worth hiding: it confirms the
// target uses Slack at all, which combined with the rest of a report is
// more identifying than the generic word "Bearer" ever was.
//
// The scheme is optional, not required: a webhook noted or pasted
// without its "https://" (a config value storing host+path only,
// markdown that stripped the protocol) still has the same sensitive
// path after "hooks.slack.com/services/...", and requiring the scheme
// would leave that path to the generic domain detector instead, which
// only protects "hooks.slack.com" itself and leaves the actual secret
// (the team/bot/token path) unredacted right next to it.
var slackWebhookRe = regexp.MustCompile(`\b(?:https?://)?hooks\.slack\.com/(?:services|workflows)/\S+`)

var slackWebhookDetector = wholeMatchDetector{slackWebhookRe, tokenstore.EntitySlackWebhook, tokenstore.TokenSlackWebhookMarker}

// stripeKeyRe matches secret (sk_) and restricted (rk_) Stripe keys, live
// or test mode; publishable keys (pk_live_/pk_test_) are meant to be
// public and aren't secrets, so they're out of scope for this detector.
// Test-mode secret/restricted keys (sk_test_/rk_test_) are
// included too: same character shape and zero additional false-positive
// risk as the live-mode pattern, and test keys turn up in leaked
// .env/config dumps at least as often as live ones since they're
// handled less carefully: a real Stripe account credential either way,
// just scoped to Stripe's test environment instead of production.
var stripeKeyRe = regexp.MustCompile(`\b[rs]k_(?:live|test)_[a-zA-Z0-9]{20,247}\b`)

var stripeKeyDetector = wholeMatchDetector{stripeKeyRe, tokenstore.EntityStripeKey, tokenstore.TokenStripePrefix}

// googleAPIKeyRe matches the "AIzaSy"-prefixed key shape, used broadly
// across Google Cloud API keys (not just Gemini/Generative Language API
// keys, which is where this prefix is most commonly seen leaked).
var googleAPIKeyRe = regexp.MustCompile(`\bAIzaSy[A-Za-z0-9_-]{33}\b`)

var googleAPIKeyDetector = wholeMatchDetector{googleAPIKeyRe, tokenstore.EntityGoogleAPIKey, tokenstore.TokenGoogleAPIKeyPrefix}

var npmTokenRe = regexp.MustCompile(`\bnpm_[0-9a-zA-Z]{36}\b`)

var npmTokenDetector = wholeMatchDetector{npmTokenRe, tokenstore.EntityNPMToken, tokenstore.TokenNPMPrefix}

// twilioSIDRe matches only the Account SID ("AC" + 32 hex), not a paired
// auth-token pattern: a generic 32-hex-char "auth token" is
// indistinguishable from any other 32-hex string (an MD5 hash, a git
// blob-ish string, any random hex blob constantly present in pentest
// output) and would be a real false-positive-flood risk. The SID alone,
// with its "AC" prefix and fixed length, is distinctive enough to keep.
var twilioSIDRe = regexp.MustCompile(`\bAC[0-9a-f]{32}\b`)

var twilioSIDDetector = wholeMatchDetector{twilioSIDRe, tokenstore.EntityTwilioSID, tokenstore.TokenTwilioSIDPrefix}

var sendGridKeyRe = regexp.MustCompile(`\bSG\.[\w-]{20,24}\.[\w-]{39,50}\b`)

var sendGridKeyDetector = wholeMatchDetector{sendGridKeyRe, tokenstore.EntitySendGridKey, tokenstore.TokenSendGridPrefix}

// --- connection strings with embedded credentials --------------------------
//
// Two distinct shapes, both genuinely common in pentest recon (config
// dumps, .env files, appsettings.json, web.config):
//
//  1. URL-style: scheme://user:pass@host[:port]: mongodb(+srv),
//     postgres(ql), mysql, redis(s), amqp(s), ldap(s), ftp, sqlserver,
//     http(s), optionally jdbc: prefixed (jdbc:mysql://...). The real
//     scheme is preserved outside the detection span (via a submatch,
//     same technique as bearerDetector). Like "Bearer ", it's useful
//     context ("this is a MongoDB connection") that isn't itself
//     sensitive. http(s) is included alongside the DB/service schemes
//     since credentials embedded in a plain http(s) URL (e.g.
//     "curl -x http://user:pass@host:port", HTTP Basic Auth embedded in
//     a URL) are at least as common a real leak shape. Note this means
//     the host portion of a credential-
//     bearing URL loses domain-structure preservation (the whole
//     "user:pass@host[:port]" becomes one opaque block, same as it
//     already did for the DB schemes), consistent with, not a new
//     exception to, the existing behavior for this detector.
//  2. ADO.NET/ODBC-style: semicolon-separated "Key=Value;..." pairs, e.g.
//     "Server=10.0.0.5;Database=erp;User Id=sa;Password=...;", common in
//     .NET/Windows environments. There's no fixed scheme prefix to anchor
//     on here, only a "Password="/"Pwd=" keyword, which is exactly the
//     shape of "context-anchored generic secret" detection that was
//     deliberately deferred elsewhere in this package as too broad/
//     high-false-positive on its own. The gate here is narrower than that
//     general case: a bare "password=" is only treated as a real
//     connection-string credential if a server/host-identifying key
//     (Server=/Data Source=/Uid=/User Id=) also appears nearby in the
//     same string, i.e. this only fires on the specific DB-connection-
//     string shape, not on any "password=" mention anywhere in text.
var connStringURLRe = regexp.MustCompile(`\b((?:jdbc:)?(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|rediss?|amqps?|ldaps?|ftp|sqlserver|https?)://)([^\s:@/'"]{1,64}:[^\s@'"]{1,128}@[^\s/'"]+)`)

var adoPasswordRe = regexp.MustCompile(`(?i)\b(?:password|pwd)\s*=\s*([^;'"\s]{1,128})`)

var adoContextRe = regexp.MustCompile(`(?i)(?:server|data source|uid|user id)\s*=`)

// adoContextWindow is how far around a "password=" match this looks for
// a server/host-identifying key before treating it as a genuine
// connection-string credential rather than an unrelated "password=" in
// prose.
const adoContextWindow = 150

type connStringDetector struct{}

func (connStringDetector) Detect(text string) ([]Detection, error) {
	var out []Detection

	for _, m := range connStringURLRe.FindAllStringSubmatchIndex(text, -1) {
		credStart, credEnd := m[4], m[5] // group 2: "user:pass@host[:port]"
		val := text[credStart:credEnd]
		if strings.Contains(val, tokenstore.TokenConnStringMarker) {
			continue // already a token
		}
		out = append(out, simpleDetection(credStart, credEnd, val, tokenstore.EntityConnString))
	}

	for _, m := range adoPasswordRe.FindAllStringSubmatchIndex(text, -1) {
		valStart, valEnd := m[2], m[3]
		val := text[valStart:valEnd]
		if strings.Contains(val, tokenstore.TokenConnStringMarker) {
			continue // already a token
		}
		winStart := max(valStart-adoContextWindow, 0)
		winEnd := min(valEnd+adoContextWindow, len(text))
		if !adoContextRe.MatchString(text[winStart:winEnd]) {
			continue // no nearby Server=/Data Source=/Uid=, so not a connection string
		}
		out = append(out, simpleDetection(valStart, valEnd, val, tokenstore.EntityConnString))
	}

	return out, nil
}

// --- second batch: cloud/CI/secrets-manager/AI-provider credentials -------
//
// Azure DevOps PAT and Travis CI tokens are deliberately left out: both
// are just a loose keyword near a generic 20-50 character alnum blob
// with no distinctive fixed prefix baked into the credential's own
// shape, a meaningfully higher false-positive risk than everything else
// in this file, which all anchor on a fixed, credential-specific prefix
// or marker substring that's vanishingly unlikely to appear by
// coincidence.

var digitalOceanRe = regexp.MustCompile(`\b(?:dop|doo|dor)_v1_[a-f0-9]{64}\b`)

var digitalOceanDetector = wholeMatchDetector{digitalOceanRe, tokenstore.EntityDigitalOcean, tokenstore.TokenDigitalOceanPrefix}

// cloudflareRe combines the API-token (cfat_/cfut_) and global-API-key
// (cfk_) shapes, both "cf" + a fixed suffix length.
var cloudflareRe = regexp.MustCompile(`\bcf(?:[ua]t|k)_[a-zA-Z0-9]{40}[a-f0-9]{8}\b`)

var cloudflareDetector = wholeMatchDetector{cloudflareRe, tokenstore.EntityCloudflare, tokenstore.TokenCloudflarePrefix}

// azureStorageKeyRe looks for an "AccountKey="/"AccessKey="/"StorageKey="
// keyword immediately (within 25 chars) followed by the base64-shaped
// key value itself (86-88 chars, optionally "="-padded); the value
// shape alone is distinctive enough (a coincidental 86+ char base64 run
// is vanishingly unlikely) that the short keyword window is just extra
// confidence, not the sole signal, unlike a bare "password=" keyword.
var azureStorageKeyRe = regexp.MustCompile(`(?i)(?:account|access|storage)[_.-]?key(?:.|\s){0,25}?([A-Za-z0-9+/-]{86,88}={0,2})`)

var azureStorageKeyDetector = capturedMatchDetector{azureStorageKeyRe, tokenstore.EntityAzureStorageKey, tokenstore.TokenAzureStorageKeyPrefix}

// artifactoryRe combines the API-key (AKCp...) and reference-token
// (cmVmdGtu..., base64 of the literal string "reftkn") shapes.
var artifactoryRe = regexp.MustCompile(`\b(?:AKCp[a-zA-Z0-9]{69}|cmVmdGtu[A-Za-z0-9]{56})\b`)

var artifactoryDetector = wholeMatchDetector{artifactoryRe, tokenstore.EntityArtifactory, tokenstore.TokenArtifactoryPrefix}

var dockerHubRe = regexp.MustCompile(`\b(?:dckr_pat_[a-zA-Z0-9_-]{27}|dckr_oat_[a-zA-Z0-9_-]{32})\b`)

var dockerHubDetector = wholeMatchDetector{dockerHubRe, tokenstore.EntityDockerHub, tokenstore.TokenDockerHubPrefix}

var circleCIRe = regexp.MustCompile(`\bCCIPAT_[a-zA-Z0-9]{22}_[a-fA-F0-9]{40}\b`)

var circleCIDetector = wholeMatchDetector{circleCIRe, tokenstore.EntityCircleCI, tokenstore.TokenCircleCIPrefix}

// terraformRe requires the literal ".atlasv1." infix, a highly
// distinctive fixed anchor baked into the token's own shape.
var terraformRe = regexp.MustCompile(`\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67}\b`)

var terraformDetector = wholeMatchDetector{terraformRe, tokenstore.EntityTerraform, tokenstore.TokenTerraformPrefix}

// snykRe uses a keyword-then-any-chars-then-pattern sequence, an
// ordinary forward-only match that needs no lookaround at all despite
// RE2 not supporting it. Detection span is the capture group (the UUID
// alone), leaving the "snyk" keyword and whatever sits between it and
// the token as untouched literal context.
var snykRe = regexp.MustCompile(`(?i:snyk)(?:.|[\n\r]){0,40}?\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`)

var snykDetector = capturedMatchDetector{snykRe, tokenstore.EntitySnyk, tokenstore.TokenSnykPrefix}

var bitbucketRe = regexp.MustCompile(`\bATBB[A-Za-z0-9_=.-]{20,}\b`)

var bitbucketDetector = wholeMatchDetector{bitbucketRe, tokenstore.EntityBitbucket, tokenstore.TokenBitbucketPrefix}

// vaultRe covers the two current, fixed-prefix HashiCorp Vault token
// shapes (hvs. service tokens, hvb. batch tokens). Deliberately excludes
// the legacy "s." + 18-40 char form: "s." is far too short and common a
// substring to safely anchor on.
var vaultRe = regexp.MustCompile(`\bhv[sb]\.[A-Za-z0-9_.-]{50,300}\b`)

var vaultDetector = wholeMatchDetector{vaultRe, tokenstore.EntityVault, tokenstore.TokenVaultPrefix}

// openAIRe requires the literal "T3BlbkFJ" infix (base64 of a fixed
// byte sequence OpenAI always embeds), the distinctive anchor, not the
// surrounding alnum runs.
var openAIRe = regexp.MustCompile(`\bsk-(?:(?:proj|svcacct|service)-[A-Za-z0-9_-]+|[a-zA-Z0-9]+)T3BlbkFJ[A-Za-z0-9_-]+\b`)

var openAIDetector = wholeMatchDetector{openAIRe, tokenstore.EntityOpenAI, tokenstore.TokenOpenAIPrefix}

// anthropicKeyRe is worth having given this proxy's own domain: it
// forwards every request to the Anthropic API, so a real Anthropic key
// leaking through it (e.g. a client's own key pasted into a debugging
// session) would be a direct, self-referential failure.
var anthropicKeyRe = regexp.MustCompile(`\bsk-ant-(?:admin01|api03)-[\w-]{93}AA\b`)

var anthropicKeyDetector = wholeMatchDetector{anthropicKeyRe, tokenstore.EntityAnthropicKey, tokenstore.TokenAnthropicPrefix}

// razorpayRe matches only the key ID (rzp_live_...), not a paired
// "secret" pattern: a generic 24-char alnum secret (like Twilio's
// generic auth-token half) is indistinguishable from any other 24-char
// alnum string and would be a false-positive-flood risk on its own, so
// it's deliberately left out here.
var razorpayRe = regexp.MustCompile(`(?i)\brzp_live_[A-Za-z0-9]{14}\b`)

var razorpayDetector = wholeMatchDetector{razorpayRe, tokenstore.EntityRazorpay, tokenstore.TokenRazorpayPrefix}
