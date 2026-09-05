package redact

import (
	"regexp"
	"unicode"
	"unicode/utf8"
)

// isInvisibleFormatChar reports whether r is a Unicode character with no
// visible glyph of its own -- specifically categories Cf (Format:
// zero-width space/joiner, soft hyphen, word joiner, BOM, every bidi
// control character, invisible math operators, ...) and Mn (Nonspacing
// Mark: variation selectors, combining grapheme joiner, and ordinary
// combining diacritics).
//
// This is a category check, not a hand-picked list of specific code
// points: Cf alone spans dozens of code points across many Unicode
// blocks -- left-to-right/right-to-left marks, every bidi embedding/
// override/isolate control, the Arabic letter mark, the Mongolian vowel
// separator, invisible math operators, and more, beyond the handful
// (ZWSP, ZWNJ, ZWJ, soft hyphen, word joiner, BOM) that come to mind
// first -- so a hand-maintained list is structurally unable to stay
// complete. Using the category directly covers all of them, and any
// future addition to either category, automatically.
//
// Deliberately excludes Zs/Zl/Zp (space/line/paragraph separators --
// NO-BREAK SPACE, U+2028, U+2029): these render as visible whitespace,
// so a human reading text containing one perceives it as separating two
// things, not as one continuous word with an invisible join -- treating
// them as a hard boundary (this function's default, since they're not
// included) is the semantically correct behavior, not a gap.
func isInvisibleFormatChar(r rune) bool {
	return unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Mn, r)
}

// stripInvisibleFormatChars returns a copy of text with every character
// isInvisibleFormatChar reports true for removed, plus origOffset such
// that origOffset[i] is the byte position in the ORIGINAL text
// corresponding to byte i of the returned copy. origOffset has
// len(stripped)+1 entries so the position right after the last byte is
// also recoverable (needed when a match ends at the very end of the
// stripped text).
//
// A nil origOffset means "identity": stripped IS text, nothing was
// removed, and byte i of one is byte i of the other. That's the case for
// any all-ASCII input, which every invisible character this strips is by
// definition not (they're all multi-byte), and which the overwhelming
// majority of scanned text is. It matters because the offset table costs
// 8 bytes per input byte: building one for a megabyte of ordinary nmap
// output meant 8 MB of []int, per detector, per call, to describe a
// mapping that is just i -> i. See mapCleanOffset for the reading half.
func stripInvisibleFormatChars(text string) (stripped string, origOffset []int) {
	if isASCII(text) {
		return text, nil
	}
	b := make([]byte, 0, len(text))
	origOffset = make([]int, 0, len(text)+1)
	i := 0
	for i < len(text) {
		r, size := utf8.DecodeRuneInString(text[i:])
		if isInvisibleFormatChar(r) {
			i += size
			continue
		}
		for k := range size {
			origOffset = append(origOffset, i+k)
			b = append(b, text[i+k])
		}
		i += size
	}
	origOffset = append(origOffset, len(text))
	return string(b), origOffset
}

// isASCII reports whether text is entirely single-byte (< 0x80)
// characters, in which case it can contain no invisible format character
// (every code point in Cf and Mn is above U+007F) and needs no stripping
// or offset mapping at all.
func isASCII(text string) bool {
	for i := range len(text) {
		if text[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// domainCandidate is one domain-shaped span found in some original text.
// Detection, validation, and final redaction each need a DIFFERENT view
// of it:
//   - Clean (invisible characters removed) is what public-suffix/TLD
//     validation must run against -- golang.org/x/net/publicsuffix does
//     its own dot-splitting and suffix lookup, which an embedded
//     invisible character breaks the same way the ASCII-only regex used
//     to (e.g. a trailing bidi mark turns "com" into an unrecognized
//     "com<U+202C>").
//   - ToOrig maps a byte offset WITHIN Clean back to the corresponding
//     byte offset in the ORIGINAL text, so whichever sub-span of Clean
//     validation decides is the real "registrable" domain (which may be
//     shorter than the whole candidate -- see domainDetector.Detect's
//     shortening-retry loop) can be translated back to the exact
//     original bytes for both the redaction span and the value actually
//     stored as the token's real value.
//
// Deliberately does NOT extend a match through an invisible/format
// character sitting immediately OUTSIDE it (before the start or after
// the end) the way it does for one sitting INSIDE it (between two real
// characters, which the byte-range [ToOrig(0), ToOrig(len(Clean)))
// already includes automatically, no special-casing needed): an
// invisible character adjacent to, but not between, two real domain
// characters is indistinguishable from wrapper/decoration -- the same
// role quotes, backticks, or a directional-override pair play when they
// visibly surround a value -- and this codebase already leaves that kind
// of surrounding punctuation outside the redacted span rather than
// swallowing it (see accidental_leak_test.go's markdown-code-span and
// curly-quote cases). Extending into such a run is also unsafe on its
// own terms: a domain wrapped in a RIGHT-TO-LEFT OVERRIDE / POP
// DIRECTIONAL FORMATTING pair would fold the trailing mark into the
// stored real value, which then no longer matches the plain ".com" the
// domain's own structure-preserving format() reconstruction re-appends
// as literal text on tokenize -- producing a doubled suffix on
// detokenize (".com<U+202C>.com"). Leaving the wrapping marks as literal
// text immediately outside the token, same as quotes, avoids that while
// still finding and redacting the domain inside correctly.
type domainCandidate struct {
	Clean  string
	ToOrig func(cleanOffset int) int
}

// domainLabelUnicodeRe finds every domain-shaped span in text. It is
// THE domain-candidate pattern (findDomainCandidates is the only way
// domainDetector ever sees a candidate); there is deliberately no
// separate ASCII-only variant kept alongside it, since a second copy of
// this grammar is a second thing to keep in sync with the boundary rules
// below.
//
// Two things about its shape carry hard-won history:
//
// The leading boundary is a capture group wrapped in
// (?:^|[^\p{Latin}\p{N}]), not a plain \b, and deliberately excludes "-"
// from the negated class -- found from a real leak: RE2's \b treats "_"
// as a word character, so a domain glued directly onto a preceding
// identifier via underscore (e.g. a locally-created filename like
// "hdr_widgetcorp-fixture.com", a genuinely common pattern for a
// captured-response dump) never gets a \b to fire on, and the ENTIRE
// domain, not just a fragment, was invisible to this regex. "-" stays
// out of the negated class specifically to preserve behavior for a
// domain hyphen-glued to another identifier (e.g. "get-crt.sh"), which
// already worked correctly under \b (hyphen was never a word character).
// findDomainCandidates reads the capture group's own indices (not the
// whole match's) so the consumed boundary character is never included in
// the candidate. Every detokenize pattern in engine.go uses this same
// underscore-safe boundary, for the same reason.
//
// The label character class is widened from ASCII-only ([A-Za-z0-9]) to
// Latin script (\p{Latin}\p{N}) -- e.g. "münchen-realtest.de" matches as
// ONE complete label instead of being truncated to "nchen-realtest.de"
// at the non-ASCII "ü".
//
// Deliberately scoped to \p{Latin}, not the much broader \p{L} (every
// Unicode letter): CJK, Japanese, and Arabic script don't use
// inter-word spacing the way Latin-script text does, so under \p{L} an
// ASCII domain touching such prose with no space boundary between them
// matches as ONE "domain" spanning the whole surrounding sentence (e.g.
// "这是一个重要的网站example.com请访问谢谢" as a single match). Real
// international domains encountered in practice are overwhelmingly
// Latin-script-with-diacritics (German, French, Spanish, Nordic,
// Turkish, Portuguese, ...); restricting to \p{Latin} covers those while
// leaving CJK/Arabic/Cyrillic/Greek prose exactly as unaffected as
// plain ASCII matching already leaves it.
var domainLabelUnicodeRe = regexp.MustCompile(`(?:^|[^\p{Latin}\p{N}])([\p{Latin}\p{N}](?:[\p{Latin}\p{N}-]{0,61}[\p{Latin}\p{N}])?(?:\.[\p{Latin}\p{N}](?:[\p{Latin}\p{N}-]{0,61}[\p{Latin}\p{N}])?)*\.[\p{Latin}]{2,24})\b`)

// mapCleanOffset translates cleanOffset (a byte position relative to the
// start of some match in the stripped copy, base+cleanOffset being its
// absolute position there) back to the ORIGINAL text. A nil offsets
// means the identity mapping; see stripInvisibleFormatChars.
//
// Deliberately NOT simply offsets[base+cleanOffset]: that value is the
// original position of the NEXT byte the stripped copy actually kept,
// which for a non-zero cleanOffset sitting right before a trailing
// invisible/format run silently walks past that entire run to whatever
// real content follows it -- e.g. for "com<U+202C> -- please" this would
// resolve to the position of the space after "<U+202C> -- please",
// pulling the wrapper mark into whatever span this offset is meant to
// end. Using the position of the LAST byte actually consumed, plus one,
// stops exactly after that byte instead. cleanOffset 0 (the very start
// of a match) has no "previous byte" to anchor on and needs no such care
// -- offsets[base] is already exactly the first real byte's own position.
func mapCleanOffset(offsets []int, base, cleanOffset int) int {
	if offsets == nil {
		return base + cleanOffset
	}
	if cleanOffset == 0 {
		return offsets[base]
	}
	return offsets[base+cleanOffset-1] + 1
}

// findDomainCandidates finds every domain-shaped span in text, including
// ones a plain ASCII/Latin-only regex pass would miss or truncate due to
// an invisible/format character sitting BETWEEN two real domain
// characters (e.g. "münchen<ZWSP>realtest.de").
func findDomainCandidates(text string) []domainCandidate {
	stripped, offsets := stripInvisibleFormatChars(text)
	matches := domainLabelUnicodeRe.FindAllStringSubmatchIndex(stripped, -1)
	if matches == nil {
		return nil
	}
	out := make([]domainCandidate, 0, len(matches))
	for _, loc := range matches {
		groupStart, groupEnd := loc[2], loc[3]
		if groupStart < 0 {
			continue // no capture (shouldn't happen -- domainLabelUnicodeRe always captures on match)
		}
		out = append(out, domainCandidate{
			Clean:  stripped[groupStart:groupEnd],
			ToOrig: func(cleanOffset int) int { return mapCleanOffset(offsets, groupStart, cleanOffset) },
		})
	}
	return out
}

// emailUnicodeRe is emailRe with only the DOMAIN portion widened to
// Latin script, for the same reason and with the same \p{Latin} scoping
// as domainLabelUnicodeRe -- an email's domain is just a domain, so it
// needs the identical IDN support. The local part (before "@") is left
// ASCII-only, matching current behavior: internationalized local parts
// (RFC 6531) exist but are rare enough in practice, relative to how
// mainstream IDN domains already are, that widening them wasn't in
// scope for this fix.
var emailUnicodeRe = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[\p{Latin}\p{N}](?:[\p{Latin}\p{N}-]{0,61}[\p{Latin}\p{N}])?(?:\.[\p{Latin}\p{N}](?:[\p{Latin}\p{N}-]{0,61}[\p{Latin}\p{N}])?)+\b`)

// findEmailCandidates mirrors findDomainCandidates for emailUnicodeRe --
// same strip-for-detection/map-back-to-original mechanism -- but the
// whole match IS the candidate (no separate capture group; emailUnicodeRe has none).
func findEmailCandidates(text string) []domainCandidate {
	stripped, offsets := stripInvisibleFormatChars(text)
	matches := emailUnicodeRe.FindAllStringIndex(stripped, -1)
	if matches == nil {
		return nil
	}
	out := make([]domainCandidate, 0, len(matches))
	for _, loc := range matches {
		start, end := loc[0], loc[1]
		out = append(out, domainCandidate{
			Clean:  stripped[start:end],
			ToOrig: func(cleanOffset int) int { return mapCleanOffset(offsets, start, cleanOffset) },
		})
	}
	return out
}
