package redact

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/debuglog"
)

// lastReplacementSpan tokenizes in through e (which must already have a
// debug logger with Replacements enabled attached) and returns the exact
// composite wire span the LAST detection substituted, i.e. exactly what
// Engine.Tokenize registered via Store.RegisterSpan.
func lastReplacementSpan(t *testing.T, buf *bytes.Buffer, e *Engine, in string) (out, span string) {
	t.Helper()
	buf.Reset()
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("expected at least one replacement logged for %q, got none", in)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatal(err)
	}
	span, _ = m["token"].(string)
	if span == "" {
		t.Fatalf("no composite span logged for %q", in)
	}
	return out, span
}

// TestEngineSafeFlushPoint_ProtectsEveryRegisteredEntityType mints a
// real token for every entity type in invariantCases (the same coverage
// table TestAllDetectors_FirstPrinciplesInvariants sweeps) and confirms
// SafeFlushPoint holds back a truncated version of each one.
func TestEngineSafeFlushPoint_ProtectsEveryRegisteredEntityType(t *testing.T) {
	for _, tc := range invariantCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			e := newTypesEngine(t)
			var buf bytes.Buffer
			e.SetDebugLogger(debuglog.New(debuglog.Replacements, &buf))

			_, span := lastReplacementSpan(t, &buf, e, tc.in1)
			const truncateBy = 4
			if len(span) <= truncateBy {
				t.Skipf("registered span %q too short to meaningfully truncate", span)
			}
			truncated := span[:len(span)-truncateBy]

			probe := []byte("prefix text " + truncated)
			got := e.SafeFlushPoint(probe)
			if got == len(probe) {
				t.Errorf("expected SafeFlushPoint to hold back a truncated %s span (%q), but it flushed the whole buffer", tc.name, truncated)
			}
		})
	}
}

// TestEngineSafeFlushPoint_ExhaustiveSplitPoints tries every possible
// split point strictly inside every registered entity type's composite
// span (not just one truncation depth) and confirms SafeFlushPoint holds
// back to at or before where the span starts, for all of them.
func TestEngineSafeFlushPoint_ExhaustiveSplitPoints(t *testing.T) {
	for _, tc := range invariantCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			e := newTypesEngine(t)
			var buf bytes.Buffer
			e.SetDebugLogger(debuglog.New(debuglog.Replacements, &buf))

			out, span := lastReplacementSpan(t, &buf, e, tc.in1)
			start := strings.Index(out, span)
			if start == -1 {
				t.Fatalf("registered span %q not found verbatim in tokenize output %q", span, out)
			}
			end := start + len(span)
			if len(span) < 2 {
				t.Skipf("registered span %q too short to meaningfully split", span)
			}

			// k < end: the span has only PARTIALLY arrived, must stay
			// held back.
			for k := start + 1; k < end; k++ {
				probe := []byte(out[:k])
				got := e.SafeFlushPoint(probe)
				if got > start {
					t.Errorf("split at byte %d (of span [%d,%d)): expected SafeFlushPoint to hold back to <= %d, got %d, flushed %q",
						k, start, end, start, got, probe[got:])
				}
			}
			// k == end doesn't always mean "must fully flush right this
			// instant": if the span's own tail happens to coincide with
			// the start of its own literal prefix (PEM's end marker
			// closes with "-----", the same five bytes its begin marker
			// opens with), a SECOND real PEM key really could start
			// streaming right after; that's not a hypothetical, this
			// exact literal marker is reused identically for every PEM
			// key this store ever registers. Holding back in that narrow
			// case is the safe call, not a bug, and it's bounded (at
			// most the length of the self-overlap) and resolves the
			// instant something that ISN'T a valid continuation arrives,
			// checked here directly rather than assuming instant
			// resolution at the exact completion byte.
			withDivergence := out[:end] + "\n\nDEFINITELY NOT A CONTINUATION\n\n"
			if got := e.SafeFlushPoint([]byte(withDivergence)); got != len(withDivergence) {
				t.Errorf("expected full flush once clearly-diverging content followed the complete span, got cut point %d of %d: %q",
					got, len(withDivergence), withDivergence[got:])
			}
		})
	}
}

// TestEngineSafeFlushPoint_OrdinaryProseFlushesImmediately confirms text
// with nothing registered anywhere near it flushes in full, immediately,
// regardless of buffer size.
func TestEngineSafeFlushPoint_OrdinaryProseFlushesImmediately(t *testing.T) {
	e := newTypesEngine(t)
	if _, err := e.Tokenize("contact admin@widgetcorp-fixture.com"); err != nil {
		t.Fatal(err)
	}
	prose := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 20))
	if got := e.SafeFlushPoint(prose); got != len(prose) {
		t.Fatalf("expected ordinary unrelated prose to flush in full immediately, got cut point %d of %d", got, len(prose))
	}
}
