package redact

import (
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// knownValues finds, in any text, the label-only secrets the store has
// already tokenized (see tokenstore.LabelOnlyValues): passwords, bearer
// tokens, labelled hashes and keys.
//
// Those values are detected only by the label beside them. After one is
// redacted, Claude's reply is restored for the operator, and Claude Code
// sends it back as history on every later request, usually without the
// label: "the decoded file gives the password as Winter#2024x". Seen
// live in a 20-turn session, the password went upstream from the next
// turn on. Searching for every value already known closes that, and
// gives each occurrence the token it already has.
//
// The search is one regexp alternation over the known values, rebuilt
// only when the store's set changes.
type knownValues struct {
	mu  sync.Mutex
	ver uint64
	re  *regexp.Regexp
	typ map[string]tokenstore.EntityType
}

// knownValueMinLen and knownValueEligible keep this pass from turning a
// weak password into a word redacted everywhere: "admin" or "123456" as a
// password would otherwise take every later "admin" or "123456" with it.
// Those still get redacted next to their label; they just aren't chased
// through unlabelled text.
const knownValueMinLen = 6

func knownValueEligible(v string) bool {
	if utf8.RuneCountInString(v) < knownValueMinLen || strings.ContainsAny(v, "\n\r") {
		return false
	}
	var lower, upper, digit, other bool
	for _, r := range v {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			classes++
		}
	}
	return classes >= 2
}

func (k *knownValues) current(store *tokenstore.Store) (*regexp.Regexp, map[string]tokenstore.EntityType) {
	ver := store.LabelOnlyVersion()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.typ != nil && k.ver == ver {
		return k.re, k.typ
	}
	values, ver := store.LabelOnlyValues()
	typ := make(map[string]tokenstore.EntityType, len(values))
	var alts []string
	for v, t := range values {
		if knownValueEligible(v) {
			typ[v] = t
			alts = append(alts, v)
		}
	}
	// Longest first, so a value that contains another wins the match.
	slices.SortFunc(alts, func(a, b string) int { return len(b) - len(a) })
	var re *regexp.Regexp
	if len(alts) > 0 {
		quoted := make([]string, len(alts))
		for i, a := range alts {
			quoted[i] = regexp.QuoteMeta(a)
		}
		re = regexp.MustCompile(strings.Join(quoted, "|"))
	}
	k.ver, k.re, k.typ = ver, re, typ
	return re, typ
}

// knownValueDetections returns a detection for every occurrence in text
// of a known label-only value that stands on its own: not glued to a
// letter or digit on a side where the value itself starts or ends with
// one, so "Winter#2024x" is found in "is Winter#2024x." but not inside
// "Winter#2024xyz".
func (e *Engine) knownValueDetections(text string) []Detection {
	re, typ := e.known.current(e.store)
	if re == nil {
		return nil
	}
	var out []Detection
	for _, loc := range re.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		val := text[start:end]
		if first, _ := utf8.DecodeRuneInString(val); isWordRune(first) {
			if prev, _ := utf8.DecodeLastRuneInString(text[:start]); start > 0 && isWordRune(prev) {
				continue
			}
		}
		if last, _ := utf8.DecodeLastRuneInString(val); isWordRune(last) {
			if next, _ := utf8.DecodeRuneInString(text[end:]); end < len(text) && isWordRune(next) {
				continue
			}
		}
		out = append(out, simpleDetection(start, end, val, typ[val]))
	}
	return out
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}
