package jsonwalk

import (
	"path/filepath"
	"testing"

	"github.com/tidwall/gjson"

	"github.com/CSPF-Founder/redactproxy/internal/redact"
	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// newFuzzEngine builds a real redact.Engine, backed by a real on-disk
// token store, wired with the full built-in detector set -- the same
// construction production code uses (see cmd/redactproxy/main.go), so
// this fuzz target exercises the genuine request/response redaction
// path end to end rather than a simplified stand-in.
func newFuzzEngine(t testing.TB) *redact.Engine {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatalf("tokenstore.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return redact.New(store, redact.DefaultDetectors()...)
}

// FuzzJSONWalkTokenize fuzzes Tokenize (the request-body direction) with
// arbitrary bytes as the raw JSON body -- most fuzzer-generated inputs
// will be rejected outright (not valid JSON, invalid UTF-8, a duplicate
// key, an unrecognized block type), which is correct, expected
// behavior, not a finding. What must always hold:
//   - Tokenize never panics or hangs on any input.
//   - When it succeeds, the output is itself valid JSON -- callers
//     forward it straight to the upstream API, so a structurally broken
//     body here would be a real bug, not just a formatting nit.
//   - Tokenizing the identical raw bytes twice against the same store
//     produces byte-identical output (every real value referenced is
//     already minted after the first call).
func FuzzJSONWalkTokenize(f *testing.F) {
	e := newFuzzEngine(f)

	for _, seed := range jsonWalkFuzzSeeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		out1, err1 := Tokenize(raw, e.Tokenize)
		if err1 != nil {
			return // rejected on purpose -- not a bug
		}
		if !gjson.ValidBytes(out1) {
			t.Fatalf("Tokenize produced invalid JSON:\n  in:  %s\n  out: %s", raw, out1)
		}

		out2, err2 := Tokenize(raw, e.Tokenize)
		if err2 != nil {
			t.Fatalf("Tokenize(raw) succeeded once then failed on the identical input: %v", err2)
		}
		if string(out1) != string(out2) {
			t.Fatalf("Tokenize(raw) is not deterministic against its own store:\n  first:  %s\n  second: %s", out1, out2)
		}
	})
}

// FuzzJSONWalkDetokenize fuzzes Detokenize (the response-body direction)
// directly on arbitrary bytes, NOT restricted to Tokenize's own output --
// a response body is upstream-API/model-generated content this proxy
// does not control, so it is never guaranteed to look like anything
// Tokenize would have produced. Detokenize's own doc comment already
// commits to failing open (raw returned unchanged) rather than erroring
// on a structural problem, so the only invariant that can be checked
// here is the one that actually matters for a proxy sitting in the
// middle of live traffic: it must never panic or hang, regardless of
// how malformed or adversarial the input is.
func FuzzJSONWalkDetokenize(f *testing.F) {
	e := newFuzzEngine(f)

	for _, seed := range jsonWalkFuzzSeeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = Detokenize(raw, e.Detokenize)
	})
}

// FuzzApplyFastSlowPathAgreement fuzzes apply's byte-splicing fast path
// against applyPerPath's original per-path sjson.SetBytes fallback,
// pinning the exact property TestApply_FastPathVerifiedAgainstSlowPath
// already covers by hand (see apply's own doc comment for why the two
// must always agree) against whatever shapes the fuzzer finds beyond
// that test's fixed set of bodies.
//
// Scoped to ordinary leaf paths only (inputPaths skipped whenever
// collectPaths reports any), matching that same hand-written test: the
// two implementations are DELIBERATELY different for tool_use.input
// (see applyPerPath's own doc comment) -- comparing that path would be
// asserting a known, intentional divergence, not looking for a bug.
func FuzzApplyFastSlowPathAgreement(f *testing.F) {
	for _, seed := range jsonWalkFuzzSeeds {
		f.Add([]byte(seed))
	}

	tf := func(s string) (string, error) {
		if len(s) < 4 {
			return s, nil // exercises the no-op skip mixed with real changes
		}
		return "TOK:" + s, nil
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if !gjson.ValidBytes(raw) {
			return
		}
		paths, inputPaths, unknownType := collectPaths(raw)
		if unknownType != "" || len(inputPaths) != 0 {
			return
		}

		fast, err1 := apply(raw, paths, nil, tf)
		slow, err2 := applyPerPath(raw, paths, nil, tf)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("fast/slow path disagree on whether this errors:\n  raw: %s\n  fast_err: %v\n  slow_err: %v", raw, err1, err2)
		}
		if err1 != nil {
			return
		}
		if string(fast) != string(slow) {
			t.Fatalf("fast and slow paths disagree:\n  raw:  %s\n  fast: %s\n  slow: %s", raw, fast, slow)
		}
		if !gjson.ValidBytes(fast) {
			t.Fatalf("fast path produced invalid JSON:\n  raw: %s\n  out: %s", raw, fast)
		}
	})
}

// FuzzDetokenizeValue fuzzes DetokenizeValue directly -- the function
// behind the SSE streaming path's tool_use/mcp_tool_use "input"
// handling (see handleBlockStop's tool_use case in sse.go): every real
// tool call a live agentic session makes streams its arguments through
// here. Unlike jsonwalk.Detokenize (fuzzed above, covers the
// non-streaming response-body direction), DetokenizeValue is never
// reached by that fuzzer at all -- it's a separate function used only
// for this one streaming shape.
//
// The store is fresh per fuzz call (nothing was ever minted into it),
// so tf is a pure identity function regardless of input shape, and
// DetokenizeValue's own documented contract is checkable exactly:
//   - never panics or hangs.
//   - if raw is not valid JSON, the output must equal raw byte-for-byte
//     (DetokenizeValue's own fail-open branch on gjson.ValidBytes).
//   - if raw IS valid JSON, the output must also be valid JSON -- it
//     gets spliced into an SSE frame as partial_json and reparsed by
//     whatever client is on the other end of this proxy.
func FuzzDetokenizeValue(f *testing.F) {
	e := newFuzzEngine(f)

	for _, seed := range detokenizeValueFuzzSeeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		out := DetokenizeValue(raw, e.Detokenize)
		if !gjson.ValidBytes(raw) {
			if string(out) != string(raw) {
				t.Fatalf("DetokenizeValue changed invalid-JSON input instead of passing it through:\n  in:  %s\n  out: %s", raw, out)
			}
			return
		}
		if !gjson.ValidBytes(out) {
			t.Fatalf("DetokenizeValue turned valid JSON into invalid JSON:\n  in:  %s\n  out: %s", raw, out)
		}
	})
}

// detokenizeValueFuzzSeeds covers realistic tool_use.input shapes: a
// per-host map keyed by IP address (the real published nmap-MCP-server
// shape redactValue's own doc comment names), ordinary flat params,
// nested arrays and objects, object keys containing characters
// significant to gjson paths (., *, ?, |, \), every non-object/array
// JSON root type (redactValue's default case), escaped characters,
// multi-byte Unicode, embedded invalid UTF-8, and non-JSON garbage.
var detokenizeValueFuzzSeeds = []string{
	``,
	`{}`,
	`[]`,
	`null`,
	`true`,
	`42`,
	`"just a string"`,
	`{"per_host":{"10.1.2.3":{"open_ports":[22,443]},"10.1.2.4":{"open_ports":[80]}},"target":"widgetcorp-fixture.com"}`,
	`{"query":"select * from widgetcorp-fixture.customers where email='admin@widgetcorp-fixture.com'"}`,
	`{"a.b":"c","d*e":"f","g?h":"i","j|k":"l","m\\n":"o"}`,
	`{"nested":{"deeply":{"array":[1,2,{"x":"admin@widgetcorp-fixture.com"}]}}}`,
	`{"unicode":"🔥東京émoji-café-🎉 and 东京-value too"}`,
	"{\"bad_utf8\":\"" + string([]byte{0xff, 0xfe}) + "\"}",
	`not json at all`,
	`{"truncated":`,
	`{"dup":"a","dup":"b"}`,
}

// jsonWalkFuzzSeeds gives the fuzzer realistic starting points for the
// JSON-document-level machinery -- every block type this package
// recognizes, the system-reminder shapes it special-cases (known-fixed
// boilerplate, the environment-context wrapper with a scannable claudeMd
// section, and an unrecognized shape that must fall through to full
// scanning), a tool_use.input with a per-host-map-shaped object (the
// real MCP shape redactValue exists for), structural edge cases
// (duplicate keys, an unknown block type, deeply nested arrays, escaped
// characters, multi-byte Unicode, embedded invalid UTF-8), and a few
// non-object/degenerate JSON documents.
var jsonWalkFuzzSeeds = []string{
	``,
	`{}`,
	`[]`,
	`null`,
	`"just a string"`,
	`{"messages":[]}`,

	// basic content-carrying fields
	`{"system":"contact admin@widgetcorp-fixture.com","messages":[{"role":"user","content":"host is 10.20.30.40"}]}`,
	`{"messages":[{"role":"user","content":[{"type":"text","text":"nmap found fileserver.corp.widgetcorp-fixture.local"}]}]}`,

	// tool_use / tool_result, including a per-host-map-shaped input
	// (the real published-MCP-server shape redactValue exists for)
	`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"nmap_scan","input":{"per_host":{"10.1.2.3":{"open_ports":[22,443]},"10.1.2.4":{"open_ports":[80]}}}}]}]}`,
	`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"line1\nline2\ttabbed \"quoted\" back\\slash done"}]}]}`,
	`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"🔥東京émoji-café-🎉 and 东京-value too"}]}]}`,

	// mcp_tool_use / mcp_tool_result -- deliberately NOT in skipBlockTypes
	`{"messages":[{"role":"assistant","content":[{"type":"mcp_tool_use","id":"t1","name":"db_query","server_name":"internal-db","input":{"query":"select * from widgetcorp-fixture.customers"}}]}]}`,

	// skipped block types -- must pass through untouched, never touched
	// as a candidate content-carrying field
	`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"admin@widgetcorp-fixture.com should stay exactly as-is","signature":"abc123"}]}]}`,
	`{"messages":[{"role":"assistant","content":[{"type":"server_tool_use","id":"t1","name":"web_search","input":{"query":"widgetcorp-fixture.com"}}]}]}`,

	// system-reminder shapes: known-fixed boilerplate (protected
	// verbatim), the environment-context wrapper (selectively scans
	// only claudeMd), and an unrecognized shape (fully scanned by
	// default -- see handleSystemReminder's doc comment for the real
	// leak this default covers)
	`{"messages":[{"role":"user","content":"<system-reminder>## Auto Mode Active\nadmin@widgetcorp-fixture.com should stay exactly as-is</system-reminder>"}]}`,
	`{"messages":[{"role":"user","content":"<system-reminder>As you answer the user's questions, you can use the following context:\n# userEmail\nadmin@widgetcorp-fixture.com\n# claudeMd\ncontact admin@widgetcorp-fixture.com for the engagement\n</system-reminder>"}]}`,
	`{"messages":[{"role":"user","content":"<system-reminder>Tool call replayed: admin@widgetcorp-fixture.com</system-reminder>"}]}`,
	`{"messages":[{"role":"user","content":"before <system-reminder>## Auto Mode Active\nok</system-reminder> admin@widgetcorp-fixture.com after"}]}`,
	`{"messages":[{"role":"user","content":"<system-reminder><system-reminder>nested admin@widgetcorp-fixture.com</system-reminder></system-reminder>"}]}`,
	`{"messages":[{"role":"user","content":"<system-reminder>unterminated admin@widgetcorp-fixture.com"}]}`,

	// structural edge cases this package is meant to fail closed on
	`{"messages":[{"role":"user","content":"x"}],"messages":[{"role":"user","content":"y"}]}`, // duplicate top-level key
	`{"messages":[{"role":"user","content":[{"type":"totally_unknown_block_type","text":"admin@widgetcorp-fixture.com"}]}]}`,
	"{\"messages\":[{\"role\":\"user\",\"content\":\"" + string([]byte{0xff, 0xfe}) + "\"}]}", // invalid UTF-8 inside a string value
	`not json at all`,
	`{"messages":`, // truncated

	// deep nesting / many leaves, keys containing gjson-path-significant
	// characters (., *, ?, |, \)
	`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"a"},{"type":"text","text":"b"},{"type":"text","text":"c"}]}]}]}`,
	`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"x","input":{"a.b":"c","d*e":"f","g?h":"i","j|k":"l","m\\n":"o"}}]}]}`,
}
