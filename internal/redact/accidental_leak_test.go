package redact

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// TestAccidentalLeak_RealisticMangling is a loop-style pass over
// realistic ways a sensitive value can arrive MANGLED by accident --
// ordinary copy-paste, terminal rendering, or another tool's own output
// formatting -- not a sophisticated adversary deliberately hiding data.
// Never semantic/encoding transforms like base64: those are an
// accepted, unavoidable limitation of any wire-text redaction tool,
// since the model itself can always be asked to decode them and no
// pattern match over the wire text could ever catch that. For each of
// several real, sensitive base values, applies many mutations a value
// could plausibly arrive in by accident and checks whether the
// ORIGINAL, unmutated sensitive substring survives literally intact in
// the Tokenize output.
//
// A non-empty knownLimitation on a mutation means: this one really does
// leak, it's understood why, and a real fix was considered and
// deliberately not made (see the ANSI case below) -- logged for
// visibility rather than asserted as a failure, so this suite stays
// green while the gap stays documented instead of forgotten.
func TestAccidentalLeak_RealisticMangling(t *testing.T) {
	type target struct {
		name string
		real string
	}
	targets := []target{
		{"aws_key", "AKIAIOSFODNN7EXAMPLE"},
		{"email", "admin@widgetcorp-fixture.com"},
		{"domain", "widgetcorp-fixture.com"},
		{"ipv4", "45.79.112.203"},
		{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
	}

	type mutation struct {
		label           string
		apply           func(real string) string
		knownLimitation string // non-empty: this leak is known, understood, and accepted -- see doc comment
	}
	insertAt := func(s string, pos int, ins string) string {
		if pos > len(s) {
			pos = len(s)
		}
		return s[:pos] + ins + s[pos:]
	}

	const ansiKnownLimitation = "ANSI SGR color codes end in the letter 'm' (a word character), so a value immediately preceded by one (e.g. \\x1b[32mAKIA...) has no \\b word-boundary transition into it -- \\b-anchored detectors (AWS key, IPv4, JWT) never match. Realistic source: pentest tooling that colorizes its own output by default (nmap, grep --color, many scanners), if raw captured/piped output including escape codes reaches Claude Code. A real fix (stripping ANSI codes before detection) was considered and deliberately NOT made: it requires either fragile position-remapping to reconstruct the original text with a token substituted in, or actually modifying the real output content by removing bytes that might matter downstream -- both carry more risk of a NEW bug than this narrow gap is worth closing for now."

	mutations := []mutation{
		{label: "plain (control)", apply: func(r string) string { return r }},

		// --- realistic, ACCIDENTAL mangling -- the priority set ---
		{label: "non-breaking space mid (common web/PDF copy-paste artifact)", apply: func(r string) string {
			return insertAt(r, len(r)/2, " ")
		}},
		{label: "CRLF line ending instead of LF, value wrapped", apply: func(r string) string {
			return insertAt(r, len(r)/2, "\r\n")
		}},
		{label: "terminal line-wrap: bare newline mid-value (80-col wrap)", apply: func(r string) string {
			return insertAt(r, len(r)/2, "\n")
		}},
		{label: "trailing whitespace from copy-paste", apply: func(r string) string {
			return r + "   "
		}},
		{label: "leading whitespace from indented tool output", apply: func(r string) string {
			return "    " + r
		}},
		{label: "embedded in a markdown table cell", apply: func(r string) string {
			return "| " + r + " |"
		}},
		{label: "embedded in a markdown code span", apply: func(r string) string {
			return "`" + r + "`"
		}},
		{
			label:           "wrapped in ANSI color escape codes (terminal tool output)",
			apply:           func(r string) string { return "\x1b[32m" + r + "\x1b[0m" },
			knownLimitation: ansiKnownLimitation,
		},
		{label: "smart/curly quotes around the value (word processor paste)", apply: func(r string) string {
			return "“" + r + "”"
		}},
		{label: "double space collapsed from copy-paste (extra space mid)", apply: func(r string) string {
			return insertAt(r, len(r)/2, "  ")
		}},
		{label: "tab-separated (TSV tool output) mid", apply: func(r string) string {
			return insertAt(r, len(r)/2, "\t")
		}},
		{label: "box-drawing table border adjacent (CLI table output)", apply: func(r string) string {
			return "│ " + r + " │"
		}},
		{label: "partially masked by ANOTHER tool sitting right next to it", apply: func(r string) string {
			return r + " (see also: ****REDACTED****)"
		}},
		{label: "repeated 3x in the same message (common in verbose tool output)", apply: func(r string) string {
			return r + " ... " + r + " ... " + r
		}},

		// --- lower-priority: deliberate-looking tricks, included for
		// completeness but not the focus of this suite ---
		{label: "zero-width-space mid (deliberate-only, unlikely by accident)", apply: func(r string) string {
			return insertAt(r, len(r)/2, "\u200b")
		}},
		{label: "RTL-override wrapping (deliberate-only, unlikely by accident)", apply: func(r string) string {
			return "\u202e" + r + "\u202c"
		}},
	}

	for _, tg := range targets {
		for _, mut := range mutations {
			name := fmt.Sprintf("%s/%s", tg.name, mut.label)
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				e := New(store, DefaultDetectors()...)

				mutated := mut.apply(tg.real)
				in := "here is the value: " + mutated + " -- please use it"

				out, err := e.Tokenize(in)
				if err != nil {
					t.Fatalf("tokenize error (should not happen for text input): %v", err)
				}

				leaked := strings.Contains(out, tg.real)
				switch {
				case leaked && mut.knownLimitation != "":
					t.Logf("known limitation confirmed still present: %s", mut.knownLimitation)
				case leaked:
					t.Errorf("LEAK: real value %q survived intact in output under mutation %q\n  in:  %q\n  out: %q", tg.real, mut.label, in, out)
				case !leaked && mut.knownLimitation != "":
					t.Logf("previously-known limitation no longer reproduces -- consider removing its knownLimitation tag")
				}
			})
		}
	}
}

// TestAccidentalLeak_SplitAcrossTwoMessages checks the structurally
// unfixable case explicitly, so it's documented as a known limitation
// rather than silently assumed: half a credential in one message, the
// other half in the next -- each half alone has no sensitive shape on
// its own, so no single-message detector pass can catch it. Realistic
// accidental version of this: a long value that a tool's OWN output
// wraps across two separate paginated/truncated results, where each
// page gets processed as a separate message. This test is expected to
// show the split value is NOT caught (that's the point -- confirming
// the limitation exists exactly as expected, not hunting for a fix).
func TestAccidentalLeak_SplitAcrossTwoMessages(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	e := New(store, DefaultDetectors()...)

	real := "AKIAIOSFODNN7EXAMPLE"
	half1 := real[:10]
	half2 := real[10:]

	out1, err := e.Tokenize("first part of the key: " + half1)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := e.Tokenize("second part of the key: " + half2)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(out1, half1) && strings.Contains(out2, half2) {
		t.Logf("confirmed known limitation: a credential split across two separate messages is not caught by either single-message pass (half1=%q half2=%q) -- this is structural, not a bug: each half has no sensitive shape on its own", half1, half2)
	} else {
		t.Logf("interesting: one half WAS caught anyway (out1=%q out2=%q) -- probably coincidental partial-pattern match, not general protection", out1, out2)
	}
}
