package jsonwalk

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// applyPerPath is the fallback apply drops to when gjson can't report a
// byte offset it can verify, and its tool_use.input branch
// (collectLeafStrings -> escapeGJSONKey) is the part no other test
// reaches: TestApply_FastPathVerifiedAgainstSlowPath and
// FuzzApplyFastSlowPathAgreement both pass a nil inputPaths on purpose,
// since the two implementations deliberately differ there (the fast path
// redacts input object KEYS as well as values, the fallback only
// values).
//
// That leaves a redaction path with no coverage at all, which matters
// because of what escapeGJSONKey is for: an object key containing a
// character gjson's path parser treats as special makes the lookup below
// silently resolve to nothing, so the value under it is never handed to
// a detector and goes upstream in the clear. The fallback firing at all
// is not expected against real Messages API bodies, but a defensive
// branch nobody has ever executed is exactly the one that breaks the
// first time it runs.
func TestApplyPerPath_RedactsToolUseInputValuesThroughAwkwardKeys(t *testing.T) {
	// Every key here contains at least one character that is syntactically
	// significant to gjson's path parser (".", "*", "?", "|", "\"), the
	// set gjson.Escape covers. Values are what must come back redacted.
	input := map[string]any{
		"plain":            "reach-me-1.example",
		"dotted.key":       "reach-me-2.example",
		"star*key":         "reach-me-3.example",
		"question?key":     "reach-me-4.example",
		"pipe|key":         "reach-me-5.example",
		"back\\slash":      "reach-me-6.example",
		"nested":           map[string]any{"inner|key": "reach-me-7.example"},
		"list":             []any{"reach-me-8.example", "reach-me-9.example"},
		"not-a-string":     42,
		"also-not-a-strin": true,
	}
	raw, err := json.Marshal(map[string]any{
		"messages": []any{map[string]any{
			"role": "assistant",
			"content": []any{map[string]any{
				"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": input,
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	paths, inputPaths, unknownType := collectPaths(raw)
	if unknownType != "" {
		t.Fatalf("unexpected unknown block type: %s", unknownType)
	}
	if len(inputPaths) != 1 {
		t.Fatalf("expected exactly one tool_use input path, got %v", inputPaths)
	}

	tf := func(s string) (string, error) { return "TOK:" + s, nil }
	out, err := applyPerPath(raw, paths, inputPaths, tf)
	if err != nil {
		t.Fatalf("applyPerPath: %v", err)
	}
	if !gjson.ValidBytes(out) {
		t.Fatalf("applyPerPath produced invalid JSON: %s", out)
	}

	// Every string value must have been transformed. An unescaped
	// awkward key shows up here as its value surviving verbatim.
	for i := 1; i <= 9; i++ {
		bare := "reach-me-" + string(rune('0'+i)) + ".example"
		if strings.Contains(string(out), `"`+bare+`"`) {
			t.Errorf("value %q was left unredacted; its key's path lookup did not resolve:\n%s", bare, out)
		}
		if !strings.Contains(string(out), "TOK:"+bare) {
			t.Errorf("value %q never appears in transformed form:\n%s", bare, out)
		}
	}

	// Non-strings are structure, not content, and must survive untouched.
	got := gjson.ParseBytes(out).Get("messages.0.content.0.input")
	if v := got.Get("not-a-string"); v.Int() != 42 {
		t.Errorf("number value was altered: %v", v.Raw)
	}
	if v := got.Get(`also-not-a-strin`); !v.Bool() {
		t.Errorf("bool value was altered: %v", v.Raw)
	}
}

// TestApplyPerPath_LeavesToolUseInputKeysAlone pins the one place the
// fallback is deliberately weaker than apply's fast path, so the
// difference stays a known, chosen limitation rather than something a
// future change quietly assumes away: the fallback redacts input VALUES
// only, never the object keys around them.
func TestApplyPerPath_LeavesToolUseInputKeysAlone(t *testing.T) {
	raw := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"scan","input":{"10.1.2.3":{"port":"22"}}}]}]}`)

	paths, inputPaths, _ := collectPaths(raw)
	tf := func(s string) (string, error) { return "TOK:" + s, nil }

	slow, err := applyPerPath(raw, paths, inputPaths, tf)
	if err != nil {
		t.Fatalf("applyPerPath: %v", err)
	}
	if !strings.Contains(string(slow), `"10.1.2.3"`) {
		t.Errorf("fallback unexpectedly rewrote an input object key; that is the fast path's job:\n%s", slow)
	}
	if !strings.Contains(string(slow), `TOK:22`) {
		t.Errorf("fallback failed to redact the value under that key:\n%s", slow)
	}

	// The fast path does redact the key, which is the whole reason the
	// two are not compared directly.
	fast, err := apply(raw, paths, inputPaths, tf)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !strings.Contains(string(fast), `"TOK:10.1.2.3"`) {
		t.Errorf("fast path should redact input object keys:\n%s", fast)
	}
}
