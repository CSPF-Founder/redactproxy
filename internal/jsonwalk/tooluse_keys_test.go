package jsonwalk

import (
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/redact"
	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
	"github.com/tidwall/gjson"
)

// newEngine builds a real redact.Engine backed by a fresh, temp-dir
// token store, for tests that need to see actual detector/tokenstore
// behavior rather than a synthetic markTransform probe.
func newEngine(t *testing.T) *redact.Engine {
	t.Helper()
	store, err := tokenstore.Open(t.TempDir() + "/tokens.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return redact.New(store, redact.DefaultDetectors()...)
}

// TestRedactValue_RealValueUsedAsObjectKeyIsRedacted is the core case
// this whole mechanism exists for: a domain or IP used as a JSON object
// KEY inside tool_use.input -- the shape a published nmap-scanning MCP
// server actually returns ("per_host": {"<ip>": {...}}) -- not just a
// value. Before redactValue, jsonwalk's tool_use.input walk only ever
// recursed into object VALUES; a real value used as a key reached
// upstream in plaintext even though the exact same value used as a
// value elsewhere in the same request was correctly redacted.
func TestRedactValue_RealValueUsedAsObjectKeyIsRedacted(t *testing.T) {
	e := newEngine(t)
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"record_nmap_results","input":{
		"per_host": {
			"10.35.251.1": {"hostname": "gateway.keytest-fixture.local", "state": "up"},
			"10.35.251.20": {"hostname": "", "state": "up"}
		},
		"contact": "admin@keytest-fixture.com"
	}}]}]}`)

	out, err := Tokenize(in, e.Tokenize)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)

	if strings.Contains(s, "10.35.251.1") || strings.Contains(s, "10.35.251.20") {
		t.Fatalf("real IP used as an object key leaked unredacted: %s", s)
	}
	if strings.Contains(s, "keytest-fixture.local") {
		t.Fatalf("real hostname (a value) leaked unredacted: %s", s)
	}
	if strings.Contains(s, "admin@keytest-fixture.com") {
		t.Fatalf("real email (a value) leaked unredacted: %s", s)
	}
	if !gjson.ValidBytes(out) {
		t.Fatalf("output is not valid JSON: %s", s)
	}

	// Round-trip: Detokenize must restore both the key-positioned IPs and
	// the value-positioned hostname/email back to their real form.
	back := Detokenize(out, e.Detokenize)
	if string(back) != string(in) {
		// IPs get network-tokenized (only the host octet is preserved
		// literally), so a byte-exact round-trip isn't guaranteed for
		// them the way it is for domains/emails -- check restoration by
		// content instead.
		bs := string(back)
		if !strings.Contains(bs, "10.35.251.1") || !strings.Contains(bs, "10.35.251.20") {
			t.Fatalf("real IPs not restored on detokenize:\n  in:   %s\n  back: %s", in, back)
		}
		if !strings.Contains(bs, "keytest-fixture.local") || !strings.Contains(bs, "admin@keytest-fixture.com") {
			t.Fatalf("real hostname/email not restored on detokenize:\n  in:   %s\n  back: %s", in, back)
		}
	}
}

// TestRedactValue_NestedKeysAtMultipleLevels confirms key redaction
// applies at every nesting depth within tool_use.input, not just the
// top level.
func TestRedactValue_NestedKeysAtMultipleLevels(t *testing.T) {
	e := newEngine(t)
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"n","input":{
		"level1": {"nestedkeytest-fixture.com": {"level3key@nestedkeytest-fixture.com": {"status": "found"}}}
	}}]}]}`)

	out, err := Tokenize(in, e.Tokenize)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "nestedkeytest-fixture.com") {
		t.Fatalf("real domain leaked at a nested key position: %s", s)
	}
	// "level1" and "status" are ordinary schema-shaped words, not PII --
	// they should never match any detector and so stay untouched.
	if !strings.Contains(s, `"level1"`) || !strings.Contains(s, `"status"`) {
		t.Fatalf("non-PII structural keys were unexpectedly altered: %s", s)
	}
}

// TestRedactValue_ArrayOfObjectsWithKeys confirms arrays containing
// objects whose keys carry real data are handled correctly -- keys
// inside each array element, not just top-level object keys.
func TestRedactValue_ArrayOfObjectsWithKeys(t *testing.T) {
	e := newEngine(t)
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"n","input":{
		"results": [
			{"arrayfixture1-fixture.com": {"ok": true}},
			{"arrayfixture2-fixture.com": {"ok": false}}
		]
	}}]}]}`)

	out, err := Tokenize(in, e.Tokenize)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "arrayfixture1-fixture.com") || strings.Contains(s, "arrayfixture2-fixture.com") {
		t.Fatalf("real domains used as keys inside array elements leaked: %s", s)
	}
}

// TestRedactValue_NonStringValuesPassThroughVerbatim confirms numbers,
// booleans, and null inside tool_use.input are never touched or
// reformatted -- only string leaves and object keys are ever candidates
// for redaction.
func TestRedactValue_NonStringValuesPassThroughVerbatim(t *testing.T) {
	e := newEngine(t)
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"n","input":{
		"port": 8443, "verbose": true, "extra": null, "ratio": 3.14, "contact": "admin@numtest-fixture.com"
	}}]}]}`)

	out, err := Tokenize(in, e.Tokenize)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"port":8443`) || !strings.Contains(s, `"verbose":true`) ||
		!strings.Contains(s, `"extra":null`) || !strings.Contains(s, `"ratio":3.14`) {
		t.Fatalf("non-string values were altered: %s", s)
	}
	if strings.Contains(s, "numtest-fixture.com") {
		t.Fatalf("real domain leaked: %s", s)
	}
}

// TestRedactValue_NoOpWhenNothingNeedsRedaction confirms a tool_use.input
// with no real content stays completely byte-identical to what
// collectLeafStrings-only redaction already guaranteed for the plain
// value-only case -- verifying the new key-aware path doesn't introduce
// unnecessary rewrites (which would matter for prompt-cache stability)
// when there's nothing to redact.
func TestRedactValue_NoOpWhenNothingNeedsRedaction(t *testing.T) {
	e := newEngine(t)
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"n","input":{"command":"ls -la","count":5}}]}]}`)

	out, err := Tokenize(in, e.Tokenize)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(in) {
		t.Fatalf("body with nothing to redact was rewritten:\n  in:  %s\n  out: %s", in, out)
	}
}

// TestRedactValue_MCPToolUseKeyRedacted confirms mcp_tool_use gets the
// same key-aware treatment as tool_use -- collectBlockArrayPaths routes
// both block types through the same inputPaths mechanism.
func TestRedactValue_MCPToolUseKeyRedacted(t *testing.T) {
	e := newEngine(t)
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"mcp_tool_use","id":"tu1","name":"n","server_name":"nmap","input":{
		"mcpkeytest-fixture.com": {"finding": "open port 22"}
	}}]}]}`)

	out, err := Tokenize(in, e.Tokenize)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "mcpkeytest-fixture.com") {
		t.Fatalf("real domain used as an mcp_tool_use input key leaked: %s", out)
	}
}

// TestDetokenizeValue_KeyAndValueBothRestored confirms the STREAMING
// reconstruction path (DetokenizeValue, used when a tool_use.input is
// rebuilt from buffered SSE deltas) also restores tokens used as keys,
// not just values -- otherwise a local tool invoked with a token instead
// of the real value it needs would silently fail or scan the wrong
// target.
func TestDetokenizeValue_KeyAndValueBothRestored(t *testing.T) {
	e := newEngine(t)
	// First establish real tokens for this engine's store by tokenizing a
	// realistic request containing the values under test, so Detokenize
	// has something to resolve.
	realIn := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"n","input":{
		"per_host": {"10.44.1.1": {"note": "svtest-fixture.local"}}
	}}]}]}`)
	tokenizedOut, err := Tokenize(realIn, e.Tokenize)
	if err != nil {
		t.Fatal(err)
	}

	// Extract just the "input" object as its own standalone JSON value,
	// simulating what the streaming SSE reconstruction path hands to
	// DetokenizeValue.
	idx := strings.Index(string(tokenizedOut), `"input":`)
	if idx == -1 {
		t.Fatal("could not locate input object in tokenized output")
	}
	inputStart := strings.Index(string(tokenizedOut)[idx:], "{") + idx
	depth := 0
	inputEnd := -1
	for i := inputStart; i < len(tokenizedOut); i++ {
		switch tokenizedOut[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				inputEnd = i + 1
			}
		}
		if inputEnd != -1 {
			break
		}
	}
	standaloneInput := tokenizedOut[inputStart:inputEnd]

	restored := DetokenizeValue(standaloneInput, e.Detokenize)
	rs := string(restored)
	if !strings.Contains(rs, "10.44.1.1") {
		t.Fatalf("real IP (used as a key) not restored by DetokenizeValue: %s", rs)
	}
	if !strings.Contains(rs, "svtest-fixture.local") {
		t.Fatalf("real hostname (a value) not restored by DetokenizeValue: %s", rs)
	}
}

// TestRedactValue_ByteLayoutPreservedOutsideInput confirms redacting
// keys inside one tool_use.input block never touches anything outside
// that block's own byte span -- the same property apply's fast path
// already guarantees for ordinary leaf values.
func TestRedactValue_ByteLayoutPreservedOutsideInput(t *testing.T) {
	e := newEngine(t)
	in := []byte(`{"model":"claude-mock","system":[{"type":"text","text":"You are Claude Code."}],"messages":[` +
		`{"role":"user","content":"plain text turn, nothing sensitive here"},` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"n","input":{"layoutfixture-fixture.com":{"ok":true}}}]}` +
		`]}`)

	out, err := Tokenize(in, e.Tokenize)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"model":"claude-mock"`) {
		t.Fatalf("model field was touched: %s", s)
	}
	if !strings.Contains(s, `"text":"You are Claude Code."`) {
		t.Fatalf("system text was touched: %s", s)
	}
	if !strings.Contains(s, `"content":"plain text turn, nothing sensitive here"`) {
		t.Fatalf("unrelated earlier message was touched: %s", s)
	}
	if strings.Contains(s, "layoutfixture-fixture.com") {
		t.Fatalf("real domain used as a key leaked: %s", s)
	}
}
