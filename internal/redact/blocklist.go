package redact

import (
	"regexp"
	"strings"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// NewBlockDetector builds a Detector from user-supplied patterns: the
// exact-string or regex "always redact this" entries a config file or
// the setup wizard produces (see the internal/rules package). Every
// pattern here is a *regexp.Regexp compiled through Go's standard
// regexp package: same RE2 engine as every built-in detector, so a
// user-authored pattern is exactly as immune to ReDoS as any pattern
// in this codebase, and that guarantee doesn't get weaker just because
// the pattern text came from a config file instead of source code.
//
// Each match is fully opaque (EntityCustomBlock); there's no
// structure worth preserving since the value could be anything a real
// engagement needs redacted that no built-in detector covers (a
// customer name variant, an internal project codename, ...).
func NewBlockDetector(patterns []*regexp.Regexp) Detector {
	return blockDetector{patterns: patterns}
}

type blockDetector struct {
	patterns []*regexp.Regexp
}

func (d blockDetector) Detect(text string) ([]Detection, error) {
	var out []Detection
	for _, re := range d.patterns {
		for _, loc := range re.FindAllStringIndex(text, -1) {
			val := text[loc[0]:loc[1]]
			if strings.HasPrefix(val, tokenstore.TokenCustomBlockPrefix) {
				continue // already a token
			}
			out = append(out, simpleDetection(loc[0], loc[1], val, tokenstore.EntityCustomBlock))
		}
	}
	return out, nil
}
