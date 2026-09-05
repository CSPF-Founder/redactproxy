package jsonwalk

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CSPF-Founder/redactproxy/internal/redact"
	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// buildPerHostBody constructs a per_host-style tool_use.input -- the
// shape a scan-result tool (nmap and similar) commonly returns -- with n
// distinct host entries, each with its own hostname and a fixed contact
// email, wrapped in a full Messages API request body.
func buildPerHostBody(t *testing.T, n int) []byte {
	t.Helper()
	perHost := make(map[string]any, n)
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		perHost[ip] = map[string]any{
			"hostname":   fmt.Sprintf("host-%d.perftest-fixture.local", i),
			"state":      "up",
			"open_ports": []int{22, 443, 3389},
		}
	}
	body := map[string]any{
		"model": "claude-mock", "max_tokens": 100,
		"messages": []any{map[string]any{
			"role": "assistant",
			"content": []any{map[string]any{
				"type": "tool_use", "id": "tu1", "name": "record_nmap_results",
				"input": map[string]any{"per_host": perHost, "contact": "admin@perftest-fixture.com"},
			}},
		}},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// countingTF is a deliberately trivial stand-in for a real tokenize
// function: it rewrites the two value shapes buildPerHostBody plants
// (per_host object keys, which are IPs, and hostname values) to
// same-length replacements, and leaves everything else alone.
//
// The guard below measures how jsonwalk writes replacements back into a
// document, so the transform itself has to contribute as close to
// nothing as possible. Handing it redact.Engine instead measures the
// detector regexes and, far more heavily, one fsync'd bbolt transaction
// per newly minted token -- ~2000 of them for a 1000-host body, which on
// a spinning or sync-honouring filesystem is seconds of pure disk wait
// with no relationship whatsoever to the quadratic-rewrite bug this
// exists to catch. That made the budget a measure of the test machine's
// fsync latency: the same unmodified code came in at ~280ms against a
// tmpfs TMPDIR and ~8.7s against ext4.
//
// It must return a *different* string for the paths it touches, or
// apply() short-circuits every no-op write and the splice path under
// test never runs at all; assertRewrote pins that.
func countingTF(calls *int) func(string) (string, error) {
	return func(s string) (string, error) {
		*calls++
		if strings.HasPrefix(s, hostPrefix) {
			return tokHostPrefix + strings.TrimPrefix(s, hostPrefix), nil
		}
		if strings.HasPrefix(s, ipPrefix) {
			return docIPPrefix + strings.TrimPrefix(s, ipPrefix), nil
		}
		return s, nil
	}
}

const (
	hostPrefix    = "host-"
	tokHostPrefix = "tok01234-"
	ipPrefix      = "10."
	docIPPrefix   = "203."
)

// TestTokenize_LargeBodyStaysNearLinear is a regression guard against
// apply()'s old per-path sjson.SetBytes loop, which re-scanned the whole
// (progressively growing) document once per redacted value -- O(paths)
// full-document rewrites, quadratic in practice since document size
// grows with that same count.
//
// Measured on a 1000-host per_host body with countingTF, the two
// implementations are three orders of magnitude apart, so the budget
// below has room to be both generous and decisive:
//
//	apply()        ~16ms plain   ~70ms under -race
//	applyPerPath() ~1.0s plain   ~4.3s under -race
//
// Race instrumentation costs ~4x on its own with no algorithmic change,
// which is why the budget takes a separate race-mode value rather than
// one number loose enough for both: a single 1s budget would stop
// distinguishing anything under -race.
func TestTokenize_LargeBodyStaysNearLinear(t *testing.T) {
	body := buildPerHostBody(t, 1000)

	calls := 0
	start := time.Now()
	out, err := Tokenize(body, countingTF(&calls))
	dur := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if json.Unmarshal(out, &v) != nil {
		t.Fatal("output is not valid JSON")
	}
	assertRewrote(t, out)

	budget := 250 * time.Millisecond
	if raceDetectorEnabled {
		budget = 1 * time.Second
	}
	if dur > budget {
		t.Errorf("tokenizing a 1000-host body took %v over %d transform calls, want under %v -- likely a reintroduced O(n^2) in apply()", dur, calls, budget)
	}
}

// assertRewrote fails if countingTF's replacements are absent from out,
// which would mean the timing above measured a walk that found nothing
// to splice rather than the rewrite path it claims to guard.
func assertRewrote(t *testing.T, out []byte) {
	t.Helper()
	s := string(out)
	if strings.Contains(s, `"`+hostPrefix) {
		t.Fatal("hostnames were left unrewritten; the timing above did not exercise the splice path")
	}
	if strings.Contains(s, `"`+ipPrefix) {
		t.Fatal("per_host IP keys were left unrewritten; the timing above did not exercise the splice path")
	}
	if !strings.Contains(s, tokHostPrefix) || !strings.Contains(s, docIPPrefix) {
		t.Fatal("replacements missing from output")
	}
}

// TestTokenize_CacheStillHitsOnRepeatedBody confirms apply()'s rewrite
// (splicing all changes into raw in one pass instead of one
// sjson.SetBytes rewrite per path) didn't change how many times or with
// what arguments tf() gets called -- it only changed how the results get
// written back into the JSON bytes -- so the engine's own tokenize cache
// still works exactly as before. Resending the identical body a second
// time (same rules generation) must produce byte-identical output and be
// dramatically faster, the same as it would under the old
// implementation.
func TestTokenize_CacheStillHitsOnRepeatedBody(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(dir + "/tokens.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	e := redact.New(store, redact.DefaultDetectors()...)

	body := buildPerHostBody(t, 500)

	start := time.Now()
	out1, err := Tokenize(body, e.Tokenize)
	firstDur := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}

	start = time.Now()
	out2, err := Tokenize(body, e.Tokenize)
	secondDur := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}

	if string(out1) != string(out2) {
		t.Fatal("resending the identical body produced different output")
	}
	if secondDur*3 > firstDur {
		t.Errorf("expected the repeated (cache-hit) call to be dramatically faster than the first, got first=%v second=%v", firstDur, secondDur)
	}
}
