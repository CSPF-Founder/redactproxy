package jsonwalk

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// markTransform prefixes every string it sees with "TOK:" so tests can
// see exactly which leaves the walker chose to touch.
func markTransform(s string) (string, error) {
	return "TOK:" + s, nil
}

func mustPretty(t *testing.T, raw []byte) string {
	t.Helper()
	if !gjson.ValidBytes(raw) {
		t.Fatalf("walker produced invalid JSON: %s", raw)
	}
	return string(raw)
}

// TestTokenize_SystemStringNeverWalked pins the deliberate exclusion
// documented on collectPaths: the top-level "system" field is Claude
// Code's own fixed harness content, never end-user/client data, and
// must pass through completely untouched -- byte-for-byte, not just
// "not transformed to the same value" (which a no-op replacement could
// satisfy trivially).
func TestTokenize_SystemStringNeverWalked(t *testing.T) {
	in := []byte(`{"model":"claude-opus-5","system":"You are a helpful assistant. client-target.example","messages":[]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(in) {
		t.Fatalf("expected the body byte-for-byte unchanged (system field must never be walked), got: %s", out)
	}
}

func TestTokenize_SystemArrayTextBlocksNeverWalked(t *testing.T) {
	in := []byte(`{"system":[{"type":"text","text":"real-value.example","cache_control":{"type":"ephemeral"}}],"messages":[]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(in) {
		t.Fatalf("expected the body byte-for-byte unchanged (system field must never be walked), got: %s", out)
	}
}

func TestTokenize_UserContentPlainString(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":"check headers of real-target.example"}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	if !strings.Contains(s, `"content":"TOK:check headers of real-target.example"`) {
		t.Fatalf("user content string not transformed: %s", s)
	}
}

// TestTokenize_EnvironmentContextUserEmailProtectedButRealContentScanned
// pins the environment-context reminder's per-section handling: the
// wrapper's own fixed identity facts (userEmail, currentDate) stay
// untouched, while real content outside the reminder entirely still
// gets tokenized normally -- otherwise the operator's own account email
// would get needlessly tokenized.
func TestTokenize_EnvironmentContextUserEmailProtectedButRealContentScanned(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":"check real-target.example\n\n<system-reminder>As you answer the user's questions, you can use the following context:\n# userEmail\noperator@internal-harness.example\n# currentDate\n2026-08-11\n</system-reminder>"}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	// Decode (not raw byte substring match) since sjson HTML-escapes
	// "<"/">" whenever it rewrites a JSON string literal -- the escaped
	// and unescaped forms decode to the identical string value.
	content := gjson.GetBytes(out, "messages.0.content").String()
	want := "TOK:check real-target.example\n\n<system-reminder>As you answer the user's questions, you can use the following context:\n# userEmail\noperator@internal-harness.example\n# currentDate\n2026-08-11\n</system-reminder>"
	if content != want {
		t.Fatalf("expected real content transformed and reminder's fixed sections untouched:\n  got:  %q\n  want: %q", content, want)
	}
}

// TestTokenize_EnvironmentContextClaudeMdScannedUserEmailNot is a
// regression test for a real leak found live: the environment-context
// reminder's "# claudeMd" section is the project's own CLAUDE.md file
// contents -- genuinely operator-authored, and known to carry real
// engagement-specific text (methodology notes, scope, findings-in-
// progress). It used to be protected along with the rest of the
// reminder wrapper; now it's the one section that gets scanned, while
// userEmail in the same reminder still doesn't.
func TestTokenize_EnvironmentContextClaudeMdScannedUserEmailNot(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":"<system-reminder>As you answer the user's questions, you can use the following context:\n# claudeMd\nProject notes: real-target.example\n# userEmail\noperator@internal-harness.example\n</system-reminder>"}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	content := gjson.GetBytes(out, "messages.0.content").String()
	want := "<system-reminder>As you answer the user's questions, you can use the following context:\n# claudeMd\nTOK:Project notes: real-target.example\n# userEmail\noperator@internal-harness.example\n</system-reminder>"
	if content != want {
		t.Fatalf("expected claudeMd section scanned and userEmail section untouched:\n  got:  %q\n  want: %q", content, want)
	}
}

// TestTokenize_KnownFixedReminderBoilerplateNeverScanned verifies
// multiple reminder blocks matching a known-fixed shape (agent/skill
// listings, plan-mode notices, etc.) in the same string all pass through
// byte-for-byte untouched -- including anything domain-shaped inside
// them, since this content is Claude-Code-authored boilerplate, never
// something a user or client typed -- while real content between and
// after them still gets tokenized normally.
func TestTokenize_KnownFixedReminderBoilerplateNeverScanned(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":"<system-reminder>## Exited Plan Mode\nyou can now edit real-target.example</system-reminder> real content real-second.example <system-reminder>## Auto Mode Active\nsecond block real-third.example</system-reminder> tail real-fourth.example"}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	content := gjson.GetBytes(out, "messages.0.content").String()
	want := "<system-reminder>## Exited Plan Mode\nyou can now edit real-target.example</system-reminder>TOK: real content real-second.example <system-reminder>## Auto Mode Active\nsecond block real-third.example</system-reminder>TOK: tail real-fourth.example"
	if content != want {
		t.Fatalf("expected known-fixed reminder blocks untouched and surrounding content transformed:\n  got:  %q\n  want: %q", content, want)
	}
}

// TestTokenize_UnrecognizedSystemReminderScannedByDefault is a
// regression test for the real leak that motivated inverting this
// package's default: Claude Code replays an earlier tool call's real
// input/result back into context wrapped in a <system-reminder> tag
// after a compaction event ("Called the Read tool with the following
// input: ...\nResult of calling the Read tool:\n<real file content>").
// This shape isn't in knownFixedReminderPrefixes and isn't the
// environment-context wrapper, so it falls through to the default: scan
// it like ordinary text, exactly like any reminder shape Claude Code
// might add in the future that this package has never seen.
func TestTokenize_UnrecognizedSystemReminderScannedByDefault(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":"<system-reminder>Called the Read tool with the following input: {\"file_path\":\"/tmp/list.txt\"}\nResult of calling the Read tool:\nreal-target.example</system-reminder>"}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	content := gjson.GetBytes(out, "messages.0.content").String()
	want := "<system-reminder>TOK:Called the Read tool with the following input: {\"file_path\":\"/tmp/list.txt\"}\nResult of calling the Read tool:\nreal-target.example</system-reminder>"
	if content != want {
		t.Fatalf("expected an unrecognized reminder shape to be scanned like ordinary text:\n  got:  %q\n  want: %q", content, want)
	}
}

func TestTokenize_UserContentTextBlock(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"real-target.example"}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	if !strings.Contains(s, `"text":"TOK:real-target.example"`) {
		t.Fatalf("text block not transformed: %s", s)
	}
	if !strings.Contains(s, `"role":"user"`) {
		t.Fatalf("role field disturbed: %s", s)
	}
}

func TestTokenize_ToolResultStringContent(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_abc123","content":"Client data: real-target.example is the target"}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	if !strings.Contains(s, `"content":"TOK:Client data: real-target.example is the target"`) {
		t.Fatalf("tool_result string content not transformed: %s", s)
	}
	if !strings.Contains(s, `"tool_use_id":"toolu_abc123"`) {
		t.Fatalf("tool_use_id must never be transformed: %s", s)
	}
}

func TestTokenize_ToolResultArrayContent(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"real-target.example"}]}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	if !strings.Contains(s, `"text":"TOK:real-target.example"`) {
		t.Fatalf("tool_result array-content text not transformed: %s", s)
	}
}

func TestTokenize_ToolUseInputRecursive(t *testing.T) {
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_9","name":"Bash","input":{"command":"curl -I https://real-target.example","nested":{"note":"about real-target.example too"}}}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	// Keys are content too (see redactValue) -- markTransform touches
	// everything it sees, keys included, same as it would for any other
	// leaf string.
	if !strings.Contains(s, `"TOK:command":"TOK:curl -I https://real-target.example"`) {
		t.Fatalf("top-level input string not transformed: %s", s)
	}
	if !strings.Contains(s, `"TOK:note":"TOK:about real-target.example too"`) {
		t.Fatalf("nested input string not transformed: %s", s)
	}
	// Protocol fields on the tool_use block itself must never be touched.
	if !strings.Contains(s, `"id":"toolu_9"`) || !strings.Contains(s, `"name":"Bash"`) {
		t.Fatalf("tool_use id/name must never be transformed: %s", s)
	}
}

// TestTokenize_ToolUseInputKeyWithPipeCharacter confirms an object key
// containing "|" (e.g. a grep-pattern-shaped key from an MCP tool's own
// free-form input) doesn't make its value silently skipped. redactValue
// recurses on gjson.Result values directly rather than building
// gjson/sjson dot-path strings for tool_use.input, so a key's own
// content can never collide with path syntax the way it could when this
// used to go through the same path-based mechanism as ordinary leaves.
func TestTokenize_ToolUseInputKeyWithPipeCharacter(t *testing.T) {
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Grep","input":{"grep|pattern":"about real-target.example too"}}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	if !strings.Contains(s, `"TOK:grep|pattern":"TOK:about real-target.example too"`) {
		t.Fatalf("input key containing '|' must still be transformed, not silently skipped: %s", s)
	}
}

// TestTokenize_ToolUseInputKeyWithBackslashCharacter mirrors the pipe
// case above for the other previously-unescaped reserved character.
func TestTokenize_ToolUseInputKeyWithBackslashCharacter(t *testing.T) {
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"C:\\path\\key":"about real-target.example too"}}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	if !strings.Contains(s, `TOK:about real-target.example too`) {
		t.Fatalf("input key containing '\\\\' must still be transformed, not silently skipped: %s", s)
	}
}

func TestTokenize_ThinkingBlockNeverTouched(t *testing.T) {
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"real-target.example is interesting","signature":"abc123signature"},{"type":"text","text":"real-target.example"}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	// thinking + signature must be byte-identical to the input.
	if !strings.Contains(s, `"thinking":"real-target.example is interesting"`) {
		t.Fatalf("thinking block content was modified (must never happen): %s", s)
	}
	if !strings.Contains(s, `"signature":"abc123signature"`) {
		t.Fatalf("thinking block signature was modified (must never happen): %s", s)
	}
	// The sibling text block must still be transformed normally.
	if !strings.Contains(s, `"text":"TOK:real-target.example"`) {
		t.Fatalf("sibling text block not transformed: %s", s)
	}
}

func TestTokenize_ImageAndDocumentBlocksSkipped(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"not-a-real-base64-value"}}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	if s != string(in) {
		t.Fatalf("image block should be entirely untouched:\n  in:  %s\n  out: %s", in, s)
	}
}

func TestTokenize_ByteLayoutPreservedForUntouchedFields(t *testing.T) {
	// Deliberately unusual key order: a naive decode/re-encode through
	// map[string]any would alphabetize or otherwise reorder these.
	in := []byte(`{"zeta_field":"z","model":"claude-opus-5","max_tokens":16000,"alpha_field":"a","messages":[{"role":"user","content":"hello"}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	// Order and exact formatting of untouched top-level fields must be
	// preserved byte-for-byte, since only "messages.0.content" changed.
	zIdx := strings.Index(s, `"zeta_field"`)
	mIdx := strings.Index(s, `"model"`)
	mtIdx := strings.Index(s, `"max_tokens"`)
	aIdx := strings.Index(s, `"alpha_field"`)
	inOriginalOrder := zIdx < mIdx && mIdx < mtIdx && mtIdx < aIdx
	if !inOriginalOrder {
		t.Fatalf("key order was disturbed: %s", s)
	}
}

func TestTokenize_NoOpWhenTransformIsIdentity(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":"nothing to change here"}]}`)
	out, err := Tokenize(in, func(s string) (string, error) { return s, nil })
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(in) {
		t.Fatalf("identity transform should leave bytes unchanged:\n  in:  %s\n  out: %s", in, out)
	}
}

func TestTokenize_FailsClosedPropagatesError(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":"real-target.example"}]}`)
	wantErr := errors.New("boom")
	_, err := Tokenize(in, func(s string) (string, error) { return "", wantErr })
	if err == nil {
		t.Fatal("expected error to propagate, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped wantErr, got %v", err)
	}
}

// TestTokenize_MalformedJSON_FailsClosed is a regression test: gjson is
// a lenient, non-validating parser, so a malformed body used to make
// collectPaths silently find zero paths and Tokenize return the
// original bytes completely unchanged with a nil error -- indistinguishable
// from "valid JSON, nothing to redact" to the caller, and confirmed live
// to forward real PII (an AWS-key-shaped string) upstream untouched
// before this fix.
func TestTokenize_MalformedJSON_FailsClosed(t *testing.T) {
	// The AWS key prefix is a separate operand so the assembled key never
	// appears as a literal here: secret scanners match raw file bytes and
	// cannot tell a fixture from a live credential. See the redact
	// package's credprefix_test.go.
	in := []byte(`{"messages": [ this is not valid json AKIA` + `QWERTYUIOPASDFGH`)
	out, err := Tokenize(in, markTransform)
	if err == nil {
		t.Fatalf("expected malformed JSON to fail closed, got output: %s", out)
	}
	if out != nil {
		t.Fatalf("expected nil output on failure, got: %s", out)
	}
}

// TestTokenize_UnrecognizedContentBlockType_FailsClosed is a regression
// test: the block-type switch in collectBlockArrayPaths used to have no
// default case, so any block type not in its fixed list (a future
// Anthropic feature, a provider-specific block) silently contributed
// zero paths -- its real content reached the outbound request body
// completely unredacted, with no error.
func TestTokenize_UnrecognizedContentBlockType_FailsClosed(t *testing.T) {
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"some_future_block_type","text":"the real domain widgetcorp-secret.example was seen"}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err == nil {
		t.Fatalf("expected an unrecognized block type to fail closed, got output: %s", out)
	}
	if !strings.Contains(err.Error(), "some_future_block_type") {
		t.Fatalf("expected the error to name the unrecognized type, got: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil output on failure, got: %s", out)
	}
}

// TestTokenize_UnrecognizedToolResultSubBlockType_FailsClosed is the
// same regression as above, one level deeper: a tool_result's own
// content array can hold sub-blocks (text, image, and potentially
// others), and that inner loop had the identical missing-default gap.
func TestTokenize_UnrecognizedToolResultSubBlockType_FailsClosed(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"some_future_sub_block","data":"widgetcorp-secret.example"}]}]}]}`)
	_, err := Tokenize(in, markTransform)
	if err == nil {
		t.Fatal("expected an unrecognized tool_result sub-block type to fail closed")
	}
	if !strings.Contains(err.Error(), "some_future_sub_block") {
		t.Fatalf("expected the error to name the unrecognized sub-block type, got: %v", err)
	}
}

// TestTokenize_ToolResultToolReference_PassesThrough is a regression
// test: Claude Code's client-side tool search (ToolSearch) answers with
// a tool_result whose content is tool_reference sub-blocks, and those
// used to hit the unrecognized-type default, blocking every request
// after the first deferred tool was loaded. The references must pass
// through byte-for-byte (tool_name has to keep matching tools[]) while
// real content elsewhere in the same message is still tokenized.
func TestTokenize_ToolResultToolReference_PassesThrough(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"tool_reference","tool_name":"WebFetch"},{"type":"tool_reference","tool_name":"mcp__internal-db__query","cache_control":{"type":"ephemeral"}}]},{"type":"text","text":"now scan real-target.example"}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatalf("expected tool_reference sub-blocks to be accepted, got: %v", err)
	}
	s := mustPretty(t, out)
	for _, ref := range []string{
		`{"type":"tool_reference","tool_name":"WebFetch"}`,
		`{"type":"tool_reference","tool_name":"mcp__internal-db__query","cache_control":{"type":"ephemeral"}}`,
	} {
		if !strings.Contains(s, ref) {
			t.Fatalf("tool_reference must pass through byte-for-byte, missing %s in: %s", ref, s)
		}
	}
	if !strings.Contains(s, `"text":"TOK:now scan real-target.example"`) {
		t.Fatalf("text alongside a tool_reference result not transformed: %s", s)
	}
}

// TestTokenize_ToolReferenceWithUnexpectedField_FailsClosed pins the
// limit on the pass-through above: it's justified only for the exact
// tool_reference shape, so one carrying any other field must still
// block rather than let that field's value reach the model untouched.
func TestTokenize_ToolReferenceWithUnexpectedField_FailsClosed(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"tool_reference","tool_name":"WebFetch","description":"queries widgetcorp-secret.example"}]}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err == nil {
		t.Fatalf("expected a tool_reference with an unexpected field to fail closed, got output: %s", out)
	}
	if !strings.Contains(err.Error(), "tool_reference") || !strings.Contains(err.Error(), "description") {
		t.Fatalf("expected the error to name the block type and the unexpected field, got: %v", err)
	}
}

// TestTokenize_TopLevelToolReference_FailsClosed: tool_reference is
// only accepted nested in a tool_result's content, where tool search
// puts it, not as a message-level content block.
func TestTokenize_TopLevelToolReference_FailsClosed(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_reference","tool_name":"WebFetch"}]}]}`)
	if _, err := Tokenize(in, markTransform); err == nil || !strings.Contains(err.Error(), "tool_reference") {
		t.Fatalf("expected a message-level tool_reference to fail closed, got err: %v", err)
	}
}

// TestTokenize_MidConversationToolChanges_PassThrough covers the role
// "system" message Claude Code sends when an MCP server connects or
// disconnects mid-session: tool_removal / tool_addition blocks naming a
// tool by reference or (additions only) by full definition. Like
// tool_reference above, these used to fail closed as unrecognized and
// block the rest of the session. References pass through byte-for-byte;
// an MCP tool's inline definition has only its description text scanned
// (see TestTokenize_ToolAddition_MCPDefinitionScanned), like its entry
// in tools[]; a text block in the same message is scanned as usual.
func TestTokenize_MidConversationToolChanges_PassThrough(t *testing.T) {
	removal := `{"type":"tool_removal","tool":{"type":"tool_reference","name":"mcp__old__query"}}`
	byRef := `{"type":"tool_addition","tool":{"type":"tool_reference","name":"mcp__internal-db__query"}}`
	byValue := `{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"mcp__internal-db__lookup","description":"Look up a host","input_schema":{"type":"object","properties":{"host":{"type":"string"}}}}},"cache_control":{"type":"ephemeral"}}`
	in := []byte(`{"messages":[{"role":"user","content":"hi"},{"role":"system","content":[{"type":"text","text":"MCP server for real-target.example reconnected"},` + removal + `,` + byRef + `,` + byValue + `]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatalf("expected tool_addition/tool_removal blocks to be accepted, got: %v", err)
	}
	s := mustPretty(t, out)
	byValueScanned := strings.Replace(byValue, `"description":"Look up a host"`, `"description":"TOK:Look up a host"`, 1)
	for _, block := range []string{removal, byRef, byValueScanned} {
		if !strings.Contains(s, block) {
			t.Fatalf("tool change block changed beyond a definition's description, missing %s in: %s", block, s)
		}
	}
	if !strings.Contains(s, `"text":"TOK:MCP server for real-target.example reconnected"`) {
		t.Fatalf("text alongside tool change blocks not transformed: %s", s)
	}
}

// TestTokenize_MidConversationToolChanges_UnexpectedShape_FailsClosed
// pins the limit on the pass-through above, for each part of the shape
// it's justified by.
func TestTokenize_MidConversationToolChanges_UnexpectedShape_FailsClosed(t *testing.T) {
	cases := map[string]string{
		"extra field on block":         `{"type":"tool_addition","tool":{"type":"tool_reference","name":"q"},"note":"real-target.example"}`,
		"extra field on reference":     `{"type":"tool_removal","tool":{"type":"tool_reference","name":"q","note":"real-target.example"}}`,
		"extra field on definition":    `{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"q"},"note":"real-target.example"}}`,
		"definition in a removal":      `{"type":"tool_removal","tool":{"type":"tool_definition","definition":{"name":"q"}}}`,
		"definition not an object":     `{"type":"tool_addition","tool":{"type":"tool_definition","definition":"real-target.example"}}`,
		"unknown tool type":            `{"type":"tool_addition","tool":{"type":"some_future_tool_ref","name":"real-target.example"}}`,
		"tool not an object":           `{"type":"tool_addition","tool":"real-target.example"}`,
		"tool missing":                 `{"type":"tool_removal"}`,
		"reference uses tool_name key": `{"type":"tool_removal","tool":{"type":"tool_reference","tool_name":"q"}}`,
	}
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			in := []byte(`{"messages":[{"role":"system","content":[` + block + `]}]}`)
			out, err := Tokenize(in, markTransform)
			if err == nil {
				t.Fatalf("expected fail closed, got output: %s", out)
			}
			if !strings.Contains(err.Error(), "tool_addition") && !strings.Contains(err.Error(), "tool_removal") {
				t.Fatalf("expected the error to name the block type, got: %v", err)
			}
		})
	}
}

// TestTokenize_FallbackBlock_PassesThrough: after a server-side refusal
// fallback switches models mid-response, the assistant turn Claude Code
// echoes back can carry a fallback marker. It used to fail closed as
// unrecognized; it must pass through byte-for-byte while the turn's text
// is still scanned.
func TestTokenize_FallbackBlock_PassesThrough(t *testing.T) {
	fallback := `{"type":"fallback","from":{"model":"claude-fable-5-1"},"to":{"model":"claude-opus-4-8"}}`
	in := []byte(`{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":[` + fallback + `,{"type":"text","text":"scanning real-target.example"}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatalf("expected a fallback block to be accepted, got: %v", err)
	}
	s := mustPretty(t, out)
	if !strings.Contains(s, fallback) {
		t.Fatalf("fallback block must pass through byte-for-byte: %s", s)
	}
	if !strings.Contains(s, `"text":"TOK:scanning real-target.example"`) {
		t.Fatalf("text after a fallback block not transformed: %s", s)
	}
}

// TestTokenize_FallbackBlock_UnexpectedShape_FailsClosed pins the limit
// on the pass-through above.
func TestTokenize_FallbackBlock_UnexpectedShape_FailsClosed(t *testing.T) {
	cases := map[string]string{
		"extra field on block":  `{"type":"fallback","from":{"model":"a"},"to":{"model":"b"},"note":"real-target.example"}`,
		"extra field on from":   `{"type":"fallback","from":{"model":"a","note":"real-target.example"},"to":{"model":"b"}}`,
		"to missing":            `{"type":"fallback","from":{"model":"a"}}`,
		"model not a string":    `{"type":"fallback","from":{"model":{"x":"real-target.example"}},"to":{"model":"b"}}`,
		"from not an object":    `{"type":"fallback","from":"real-target.example","to":{"model":"b"}}`,
		"model missing from to": `{"type":"fallback","from":{"model":"a"},"to":{}}`,
	}
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			in := []byte(`{"messages":[{"role":"assistant","content":[` + block + `]}]}`)
			out, err := Tokenize(in, markTransform)
			if err == nil {
				t.Fatalf("expected fail closed, got output: %s", out)
			}
			if !strings.Contains(err.Error(), "fallback") {
				t.Fatalf("expected the error to name the block type, got: %v", err)
			}
		})
	}
}

// TestDetokenize_FallbackBlock_RestOfResponseDetokenized: a
// non-streaming response carrying a fallback marker must still have its
// other blocks detokenized; the marker itself is left as-is.
func TestDetokenize_FallbackBlock_RestOfResponseDetokenized(t *testing.T) {
	in := []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8","content":[{"type":"fallback","from":{"model":"claude-fable-5-1"},"to":{"model":"claude-opus-4-8"}},{"type":"text","text":"found abc123.tok.internal"}]}`)
	out := string(Detokenize(in, func(s string) string {
		return strings.ReplaceAll(s, "abc123.tok.internal", "real-target.example")
	}))
	if !strings.Contains(out, `"text":"found real-target.example"`) {
		t.Fatalf("text alongside a fallback block not detokenized: %s", out)
	}
	if !strings.Contains(out, `{"type":"fallback","from":{"model":"claude-fable-5-1"},"to":{"model":"claude-opus-4-8"}}`) {
		t.Fatalf("fallback block changed: %s", out)
	}
}

// TestTokenize_ToolResultSearchResult_Scanned: a local MCP search tool
// (or Claude Code's web search with citations on) returns search_result
// sub-blocks, which used to fail closed as unrecognized. Their source,
// title and every text block must be scanned -- they're tool output like
// any other -- while protocol fields stay untouched. Covers both
// tool_result and mcp_tool_result, which share the sub-block routing.
func TestTokenize_ToolResultSearchResult_Scanned(t *testing.T) {
	for _, resultType := range []string{"tool_result", "mcp_tool_result"} {
		t.Run(resultType, func(t *testing.T) {
			in := []byte(`{"messages":[{"role":"user","content":[{"type":"` + resultType + `","tool_use_id":"toolu_1","content":[{"type":"search_result","source":"https://wiki.real-target.example/runbook","title":"real-target.example runbook","content":[{"type":"text","text":"db host is db01.real-target.example"},{"type":"text","text":"second snippet"}],"citations":{"enabled":true}}]}]}]}`)
			out, err := Tokenize(in, markTransform)
			if err != nil {
				t.Fatalf("expected a search_result sub-block to be accepted, got: %v", err)
			}
			s := mustPretty(t, out)
			for _, want := range []string{
				`"source":"TOK:https://wiki.real-target.example/runbook"`,
				`"title":"TOK:real-target.example runbook"`,
				`"text":"TOK:db host is db01.real-target.example"`,
				`"text":"TOK:second snippet"`,
				`"citations":{"enabled":true}`,
				`"tool_use_id":"toolu_1"`,
			} {
				if !strings.Contains(s, want) {
					t.Fatalf("missing %s in: %s", want, s)
				}
			}
		})
	}
}

// TestTokenize_SearchResult_UnexpectedShape_FailsClosed: scanning a
// search_result is complete only for the fields searchResultPaths knows,
// so anything else must block rather than go out unscanned.
func TestTokenize_SearchResult_UnexpectedShape_FailsClosed(t *testing.T) {
	cases := map[string]string{
		"extra field":                `{"type":"search_result","source":"s","title":"t","content":[],"snippet":"real-target.example"}`,
		"source not a string":        `{"type":"search_result","source":{"url":"real-target.example"},"title":"t","content":[]}`,
		"title missing":              `{"type":"search_result","source":"s","content":[]}`,
		"content not an array":       `{"type":"search_result","source":"s","title":"t","content":"real-target.example"}`,
		"non-text content block":     `{"type":"search_result","source":"s","title":"t","content":[{"type":"some_future_sub_block","data":"real-target.example"}]}`,
		"extra field on text block":  `{"type":"search_result","source":"s","title":"t","content":[{"type":"text","text":"x","note":"real-target.example"}]}`,
		"text not a string":          `{"type":"search_result","source":"s","title":"t","content":[{"type":"text","text":{"x":"real-target.example"}}]}`,
		"extra field in citations":   `{"type":"search_result","source":"s","title":"t","content":[],"citations":{"enabled":true,"note":"real-target.example"}}`,
		"citations.enabled a string": `{"type":"search_result","source":"s","title":"t","content":[],"citations":{"enabled":"real-target.example"}}`,
	}
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			in := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[` + block + `]}]}]}`)
			out, err := Tokenize(in, markTransform)
			if err == nil {
				t.Fatalf("expected fail closed, got output: %s", out)
			}
			if !strings.Contains(err.Error(), "search_result") {
				t.Fatalf("expected the error to name the block type, got: %v", err)
			}
		})
	}
}

// TestTokenize_MCPToolDefinitions_TextScanned: an MCP server's tool
// description and the free text in its input schema are operator-written
// and must be scanned, while everything structural -- and every built-in
// tool -- is left exactly as sent.
func TestTokenize_MCPToolDefinitions_TextScanned(t *testing.T) {
	builtin := `{"name":"Artifact","description":"loads scripts only from cdn.real-target.example","input_schema":{"type":"object","properties":{"url":{"type":"string","description":"a real-target.example link"}}}}`
	server := `{"type":"web_search_20250305","name":"web_search","allowed_domains":["real-target.example"]}`
	mcp := `{"name":"mcp__db__query","description":"Query db01.real-target.example","input_schema":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","title":"real-target.example query","properties":{"description":{"type":"string","description":"free text about real-target.example","default":"real-target.example","pattern":"^real-target\\.example$"},"env":{"type":"string","enum":["prod.real-target.example","staging"],"examples":[{"host":"a.real-target.example"}]},"rows":{"type":"array","items":{"type":"object","properties":{"host":{"const":"b.real-target.example","format":"hostname"}}}},"mode":{"anyOf":[{"type":"string","description":"c.real-target.example"},{"type":"null"}]}},"required":["description","env"],"additionalProperties":false},"defer_loading":true,"cache_control":{"type":"ephemeral"}}`
	in := []byte(`{"model":"m","tools":[` + builtin + `,` + server + `,` + mcp + `],"messages":[]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	for _, want := range []string{
		builtin,
		server,
		`"name":"mcp__db__query","description":"TOK:Query db01.real-target.example"`,
		`"$schema":"https://json-schema.org/draft/2020-12/schema"`,
		`"title":"TOK:real-target.example query"`,
		`"properties":{"description":{"type":"string","description":"TOK:free text about real-target.example","default":"TOK:real-target.example","pattern":"^real-target\\.example$"}`,
		`"enum":["TOK:prod.real-target.example","TOK:staging"]`,
		`"examples":[{"host":"TOK:a.real-target.example"}]`,
		`"const":"TOK:b.real-target.example","format":"hostname"`,
		`"anyOf":[{"type":"string","description":"TOK:c.real-target.example"},{"type":"null"}]`,
		`"required":["description","env"],"additionalProperties":false`,
		`"defer_loading":true,"cache_control":{"type":"ephemeral"}`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in: %s", want, s)
		}
	}
}

// TestTokenize_ToolAddition_MCPDefinitionScanned: an MCP tool defined
// mid-conversation carries the same text as one in "tools", and gets the
// same scan; a built-in tool's definition does not.
func TestTokenize_ToolAddition_MCPDefinitionScanned(t *testing.T) {
	block := func(name string) string {
		return `{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"` + name + `","description":"Ping gw.real-target.example","input_schema":{"type":"object","properties":{"host":{"type":"string","default":"gw.real-target.example"}}}}}}`
	}
	in := []byte(`{"messages":[{"role":"user","content":[` + block("mcp__net__ping") + `,` + block("Ping") + `]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	if !strings.Contains(s, `"name":"mcp__net__ping","description":"TOK:Ping gw.real-target.example","input_schema":{"type":"object","properties":{"host":{"type":"string","default":"TOK:gw.real-target.example"}}}`) {
		t.Fatalf("MCP tool_definition not scanned: %s", s)
	}
	if !strings.Contains(s, block("Ping")) {
		t.Fatalf("built-in tool_definition must pass through unchanged: %s", s)
	}
}

// TestTokenize_Safeguards_ContextScanned: auto mode's "safeguards"
// field repeats the working directory, git remote and permission rules
// the conversation already carries tokenized; every string in it must be
// scanned too, except the type tags and the tool_use IDs that tie a
// prior turn's context to its blocks in "messages".
func TestTokenize_Safeguards_ContextScanned(t *testing.T) {
	in := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"safeguards":[{"type":"dangerous_tool_use","classifier_context":{"v":1,"permission_mode":"auto","live_cwd":"/home/u/real-target.example","git_state":{"visibility":{"origin":{"host":"git.real-target.example","remote":"acme/payroll","visibility":"private"}},"status":{"clean":false,"counts":{"staged":0}}},"rules":{"allow":[{"rule":"Bash(curl https://portal.real-target.example/*)","source":"localSettings"}]},"auto_mode":{"environment":["vpn.real-target.example"]},"prior_turn_context":[{"tool_use_ids":["toolu_01ABC"],"context":{"live_cwd":"/home/u/real-target.example","type":"snapshot"}}],"restricted":false,"some_future_field":{"note":"10.20.30.40"}}}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatalf("expected a safeguards field to be accepted, got: %v", err)
	}
	s := mustPretty(t, out)
	for _, want := range []string{
		`"live_cwd":"TOK:/home/u/real-target.example"`,
		`"host":"TOK:git.real-target.example"`,
		`"remote":"TOK:acme/payroll"`,
		`"rule":"TOK:Bash(curl https://portal.real-target.example/*)"`,
		`"environment":["TOK:vpn.real-target.example"]`,
		`"context":{"live_cwd":"TOK:/home/u/real-target.example","type":"snapshot"}`,
		`"note":"TOK:10.20.30.40"`,
		`"type":"dangerous_tool_use"`,
		`"tool_use_ids":["toolu_01ABC"]`,
		`"v":1`,
		`"restricted":false`,
		`"counts":{"staged":0}`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in: %s", want, s)
		}
	}
	if gjson.GetBytes(out, "safeguards.0.classifier_context|@keys").Raw != gjson.GetBytes(in, "safeguards.0.classifier_context|@keys").Raw {
		t.Fatalf("classifier_context key order changed: %s", s)
	}

	// Response bodies never carry the field, but the walk is shared, so a
	// body without it must come out exactly as before.
	plain := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
	if out, err := Tokenize(plain, func(s string) (string, error) { return s, nil }); err != nil || string(out) != string(plain) {
		t.Fatalf("body without safeguards changed: %s, %v", out, err)
	}
}

// TestTokenize_Safeguards_TransformErrorFailsClosed: a scan failure
// inside safeguards blocks the request like one anywhere else.
func TestTokenize_Safeguards_TransformErrorFailsClosed(t *testing.T) {
	in := []byte(`{"messages":[],"safeguards":[{"type":"dangerous_tool_use","classifier_context":{"live_cwd":"/x"}}]}`)
	boom := errors.New("boom")
	_, err := Tokenize(in, func(string) (string, error) { return "", boom })
	if !errors.Is(err, boom) {
		t.Fatalf("expected the transform error, got: %v", err)
	}
}

// TestTokenize_CompactionBlock_NeverTouched: a server-side compaction
// block is signed, so like a thinking block it must go back
// byte-for-byte -- even when its summary contains a value a detector
// would otherwise match -- while the turns after it are still scanned.
// It used to fail closed as unrecognized.
func TestTokenize_CompactionBlock_NeverTouched(t *testing.T) {
	compaction := `{"type":"compaction","content":"Summary: the user is assessing real-target.example","encrypted_content":"EqQBCkgIARABGAIiQHg","tool_changes":[{"type":"tool_addition","tool":{"type":"tool_reference","name":"mcp__db__query"}}]}`
	in := []byte(`{"messages":[{"role":"assistant","content":[` + compaction + `]},{"role":"user","content":"now check real-target.example"}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatalf("expected a compaction block to be accepted, got: %v", err)
	}
	s := mustPretty(t, out)
	if !strings.Contains(s, compaction) {
		t.Fatalf("compaction block must pass through byte-for-byte: %s", s)
	}
	if !strings.Contains(s, `"content":"TOK:now check real-target.example"`) {
		t.Fatalf("message after a compaction block not transformed: %s", s)
	}

	nullContent := []byte(`{"messages":[{"role":"assistant","content":[{"type":"compaction","content":null}]}]}`)
	if _, err := Tokenize(nullContent, markTransform); err != nil {
		t.Fatalf("expected a compaction block with null content to be accepted, got: %v", err)
	}
}

// TestTokenize_CompactionBlock_UnexpectedShape_FailsClosed pins the
// limit on the pass-through above.
func TestTokenize_CompactionBlock_UnexpectedShape_FailsClosed(t *testing.T) {
	cases := map[string]string{
		"extra field":                    `{"type":"compaction","content":"s","note":"real-target.example"}`,
		"content not a string":           `{"type":"compaction","content":{"text":"real-target.example"}}`,
		"encrypted_content not a string": `{"type":"compaction","content":"s","encrypted_content":["real-target.example"]}`,
		"tool_changes not an array":      `{"type":"compaction","content":"s","tool_changes":{"type":"tool_addition"}}`,
		"tool_changes unknown entry":     `{"type":"compaction","content":"s","tool_changes":[{"type":"text","text":"real-target.example"}]}`,
		"tool_changes bad shape":         `{"type":"compaction","content":"s","tool_changes":[{"type":"tool_removal","tool":{"type":"tool_reference","name":"q","note":"real-target.example"}}]}`,
	}
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			in := []byte(`{"messages":[{"role":"assistant","content":[` + block + `]}]}`)
			out, err := Tokenize(in, markTransform)
			if err == nil {
				t.Fatalf("expected fail closed, got output: %s", out)
			}
			if !strings.Contains(err.Error(), "compaction") {
				t.Fatalf("expected the error to name the block type, got: %v", err)
			}
		})
	}
}

// TestDetokenize_CompactionBlock_LeftAsIs: in a response, the signed
// compaction block must reach the client unchanged (it has to echo the
// exact bytes back), even if its summary contains a token.
func TestDetokenize_CompactionBlock_LeftAsIs(t *testing.T) {
	compaction := `{"type":"compaction","content":"Summary mentions abc123.tok.internal"}`
	in := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[` + compaction + `]}`)
	out := Detokenize(in, func(s string) string {
		return strings.ReplaceAll(s, "abc123.tok.internal", "real-target.example")
	})
	if string(out) != string(in) {
		t.Fatalf("compaction block changed on detokenize: %s", out)
	}
}

// TestDetokenize_UnrecognizedContentBlockType_StillFailsOpen confirms
// Tokenize's new fail-closed behavior for an unrecognized block type
// does NOT change Detokenize's own, deliberately different, fail-open
// contract for the response direction (see Detokenize's doc comment):
// worst case here is a token left unresolved, never a blocked/corrupted
// response.
func TestDetokenize_UnrecognizedContentBlockType_StillFailsOpen(t *testing.T) {
	in := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"some_future_block_type","text":"abc123.tok.internal"}]}`)
	out := Detokenize(in, func(s string) string {
		return strings.ReplaceAll(s, "abc123.tok.internal", "real-target.example")
	})
	if string(out) != string(in) {
		t.Fatalf("expected an unrecognized block type to leave the response unchanged (fail open), got: %s", out)
	}
}

// TestTokenize_MCPToolUse_InputTokenized is a regression test: mcp_tool_use
// used to be in skipBlockTypes, treating an MCP server's tool call
// parameters -- real, locally-controlled input, not Anthropic-server-side
// content -- as something to never touch. It's now routed the same as
// plain tool_use.
func TestTokenize_MCPToolUse_InputTokenized(t *testing.T) {
	in := []byte(`{"messages":[{"role":"assistant","content":[{"type":"mcp_tool_use","id":"mcptoolu_1","name":"query","server_name":"internal-db","input":{"query":"SELECT * FROM users WHERE email='real-target.example'"}}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	if !strings.Contains(s, `TOK:SELECT * FROM users WHERE email='real-target.example'`) {
		t.Fatalf("mcp_tool_use input not transformed: %s", s)
	}
	if !strings.Contains(s, `"server_name":"internal-db"`) || !strings.Contains(s, `"name":"query"`) {
		t.Fatalf("mcp_tool_use protocol fields must never be transformed: %s", s)
	}
}

// TestTokenize_MCPToolResult_ContentTokenized is the same regression as
// above for mcp_tool_result -- an MCP server's real response content
// (e.g. a database query result, an internal API's output) used to
// reach the model completely unredacted.
func TestTokenize_MCPToolResult_ContentTokenized(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":[{"type":"mcp_tool_result","tool_use_id":"mcptoolu_1","content":[{"type":"text","text":"result: real-target.example"}]}]}]}`)
	out, err := Tokenize(in, markTransform)
	if err != nil {
		t.Fatal(err)
	}
	s := mustPretty(t, out)
	if !strings.Contains(s, `"text":"TOK:result: real-target.example"`) {
		t.Fatalf("mcp_tool_result content not transformed: %s", s)
	}
}

func TestDetokenize_RestoresRealValues(t *testing.T) {
	// Shaped like a real non-streaming Message response: content is a
	// top-level array, no "messages" wrapper.
	in := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"visiting abc123.tok.internal now"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"curl abc123.tok.internal"}}]}`)
	out := Detokenize(in, func(s string) string {
		return strings.ReplaceAll(s, "abc123.tok.internal", "real-target.example")
	})
	s := mustPretty(t, out)
	if !strings.Contains(s, `"text":"visiting real-target.example now"`) {
		t.Fatalf("text not detokenized: %s", s)
	}
	if !strings.Contains(s, `"command":"curl real-target.example"`) {
		t.Fatalf("tool_use input not detokenized: %s", s)
	}
	if !strings.Contains(s, `"id":"msg_1"`) || !strings.Contains(s, `"role":"assistant"`) {
		t.Fatalf("protocol fields disturbed: %s", s)
	}
}

func TestDetokenize_MalformedInputFallsBackToOriginal(t *testing.T) {
	in := []byte(`not valid json at all`)
	out := Detokenize(in, func(s string) string { return "SHOULD-NOT-APPEAR" })
	if string(out) != string(in) {
		t.Fatalf("expected malformed input to pass through unchanged, got %s", out)
	}
}

// TestTokenize_RealisticMultiTurnBody exercises a body shaped like a real
// captured Claude Code request: initial user text, an injected
// Claude-Code system-role message, an assistant tool_use turn, and a
// tool_result reply, verifying every content-bearing leaf across the
// whole structure gets found in one pass, matching the "messages only
// ever carry role user/assistant, or the documented mid-conversation
// system role" shape confirmed against the API spec earlier.
func TestTokenize_RealisticMultiTurnBody(t *testing.T) {
	body := map[string]any{
		"model": "claude-opus-5",
		"system": []map[string]any{
			{"type": "text", "text": "You are Claude Code."},
		},
		"messages": []map[string]any{
			{"role": "user", "content": "Read the file and tell me about real-target.example"},
			{"role": "system", "content": "Operator note: engagement scope includes real-target.example"},
			{"role": "assistant", "content": []map[string]any{
				{"type": "text", "text": "I'll check that."},
				{"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": map[string]any{"command": "curl real-target.example"}},
			}},
			{"role": "user", "content": []map[string]any{
				{"type": "tool_result", "tool_use_id": "toolu_1", "content": "200 OK from real-target.example"},
			}},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	var touched []string
	out, err := Tokenize(raw, func(s string) (string, error) {
		if strings.Contains(s, "real-target.example") {
			touched = append(touched, s)
		}
		return strings.ReplaceAll(s, "real-target.example", "TOKENIZED"), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(touched) != 4 {
		t.Fatalf("expected 4 leaves containing the real value (user text, system-role message, tool_use input, tool_result content), got %d: %v", len(touched), touched)
	}
	if strings.Contains(string(out), "real-target.example") {
		t.Fatalf("real value leaked into output: %s", out)
	}
}

// TestApply_FastPathVerifiedAgainstSlowPath pins the property apply's
// own doc comment leans on for safety: the byte-splicing fast path and
// applyPerPath's original per-path sjson.SetBytes implementation must
// always produce byte-identical output for the same (raw, paths, tf).
// Covers the shapes most likely to stress gjson's Index/Raw offset
// reporting -- deep nesting, arrays, object keys containing characters
// that are syntactically significant in gjson paths (., *, ?, |, \),
// escaped quotes/control characters, and multi-byte Unicode -- plus a
// large per_host-style map (the nmap-MCP shape a per-host scan result
// commonly takes) at a size big enough that a silently-wrong fast path
// would show up as a byte diff, not just a slowdown.
func TestApply_FastPathVerifiedAgainstSlowPath(t *testing.T) {
	transforms := map[string]func(string) (string, error){
		"marker": func(s string) (string, error) { return "TOK:" + s, nil },
		"identity-for-short": func(s string) (string, error) {
			if len(s) < 4 {
				return s, nil // exercises the no-op skip mixed with real changes
			}
			return "TOK:" + s, nil
		},
	}

	bodies := map[string][]byte{}

	// Deep array nesting of ordinary leaf paths (tool_result's own
	// content-block-array shape, not tool_use.input -- that one routes
	// through redactValue now, see TestRedactValue_* below, and has its
	// own dedicated correctness tests instead of this fast/slow
	// comparison, since apply's fast path and applyPerPath's fallback
	// are now DELIBERATELY different for tool_use.input specifically).
	var subBlocks []map[string]any
	for i := 0; i < 20; i++ {
		subBlocks = append(subBlocks, map[string]any{"type": "text", "text": fmt.Sprintf("leaf value %d with real-target-%d.example inside", i, i)})
	}
	deepBody, err := json.Marshal(map[string]any{
		"messages": []any{map[string]any{
			"role":    "user",
			"content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": subBlocks}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bodies["many_text_subblocks"] = deepBody

	// Escaped control characters and quotes inside VALUES.
	bodies["escaped_value_content"] = []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"line1\nline2\ttabbed \"quoted\" back\\slash done"}]}]}`)

	// Multi-byte Unicode in VALUES.
	bodies["unicode_values"] = []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"🔥東京émoji-café-🎉 and 东京-value too"}]}]}`)

	// Many separate messages, each its own leaf path -- big enough that a
	// wrong offset anywhere would very likely show up as a diff.
	var manyMessages []map[string]any
	for i := 0; i < 300; i++ {
		manyMessages = append(manyMessages, map[string]any{
			"role":    "user",
			"content": fmt.Sprintf("host-%d.perftest-fixture.local contact admin-%d@perftest-fixture.com", i, i),
		})
	}
	largeBody, err := json.Marshal(map[string]any{"messages": manyMessages})
	if err != nil {
		t.Fatal(err)
	}
	bodies["many_messages"] = largeBody

	for bodyName, raw := range bodies {
		for tfName, tf := range transforms {
			t.Run(bodyName+"/"+tfName, func(t *testing.T) {
				paths, inputPaths, unknownType := collectPaths(raw)
				if unknownType != "" {
					t.Fatalf("unexpected unknown block type: %s", unknownType)
				}
				if len(inputPaths) != 0 {
					t.Fatalf("test body unexpectedly produced inputPaths (this test is scoped to ordinary leaf paths only): %v", inputPaths)
				}

				fast, err := apply(raw, paths, nil, tf)
				if err != nil {
					t.Fatalf("apply (fast path): %v", err)
				}
				slow, err := applyPerPath(raw, paths, nil, tf)
				if err != nil {
					t.Fatalf("applyPerPath (slow path): %v", err)
				}

				if string(fast) != string(slow) {
					t.Fatalf("fast and slow paths disagree:\n  fast: %s\n  slow: %s", fast, slow)
				}
				if !gjson.ValidBytes(fast) {
					t.Fatalf("fast path produced invalid JSON: %s", fast)
				}
			})
		}
	}
}
