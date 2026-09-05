// Package jsonwalk locates and surgically rewrites the content-carrying
// string fields inside an Anthropic Messages API request or response
// body (system prompt, message text, tool_result content, tool_use
// input), leaving every other byte (key order, protocol fields,
// unrelated values) untouched. Byte preservation matters here for a
// concrete reason: reserializing the whole body through a generic
// decode/re-encode (e.g. into map[string]any) does not preserve JSON key
// order, and Claude Code's own prompt-cache breakpoints are a prefix
// match keyed on exact bytes, so an incidental key reordering downstream
// of a redacted field would silently invalidate caching for everything
// after it.
package jsonwalk

import (
	"cmp"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// skipBlockTypes are content block types this walker deliberately never
// touches.
//
//   - thinking / redacted_thinking: the thinking text and its signature
//     together are a cryptographic proof the API validates on replay;
//     any edit invalidates it and the next request 400s.
//   - server_tool_use and the *_tool_result types below it are
//     server-executed: web search/fetch, code execution, and tool
//     search all run on Anthropic's own infrastructure and never touch
//     local real client data, so there's nothing here to protect.
//   - Images and documents are binary/base64 payloads, not text PII.
//
// mcp_tool_use / mcp_tool_result are deliberately NOT here: unlike the
// server-executed tools above, an MCP server is local infrastructure the
// operator controls (a database query tool, an internal API client, a
// custom pentest tool exposed via MCP) and its results are exactly the
// kind of real client data this whole proxy exists to keep off the
// wire. They're routed the same as tool_use/tool_result instead (see
// collectBlockArrayPaths); treating them as "skip" here would mean
// their entire content reaches the model completely unredacted.
var skipBlockTypes = map[string]bool{
	"thinking":                               true,
	"redacted_thinking":                      true,
	"server_tool_use":                        true,
	"web_search_tool_result":                 true,
	"web_fetch_tool_result":                  true,
	"code_execution_tool_result":             true,
	"bash_code_execution_tool_result":        true,
	"text_editor_code_execution_tool_result": true,
	"tool_search_tool_result":                true,
	"image":                                  true,
	"document":                               true,
	"container_upload":                       true,
}

// Tokenize walks raw (a Messages API request body) and replaces every
// content-carrying string with tf(original). Fails closed: if tf errors
// for any string, Tokenize returns that error and no output, and callers
// must not forward a request after an error here, since that could mean
// real PII reaching the model un-redacted.
//
// Also fails closed on raw itself not being valid JSON. gjson (which
// collectPaths and apply are both built on) is a lenient, non-validating
// parser: Get on malformed JSON doesn't error, it just returns a
// zero-value Result, so collectPaths silently finds zero paths and
// apply's loop over those zero paths returns raw byte-for-byte
// unchanged with a nil error. Without this explicit check up front, a
// request body that happens not to be well-formed JSON (a client bug, a
// truncated/corrupted body, a body deliberately crafted to probe this
// exact gap) would sail through this function looking like a completely
// successful, no-op tokenize (the caller has no way to distinguish
// that from "valid JSON containing nothing to redact"), and whatever
// real PII the malformed body actually contained reaches the model
// completely unredacted: a malformed-JSON body containing an
// AWS-key-shaped string would be forwarded upstream byte-for-byte
// identical to the input.
func Tokenize(raw []byte, tf func(string) (string, error)) ([]byte, error) {
	if !gjson.ValidBytes(raw) {
		return nil, fmt.Errorf("request body is not valid JSON")
	}
	// gjson.ValidBytes only checks JSON structure -- it does not reject
	// invalid UTF-8 sitting inside a string value. A detector that
	// slices a byte span straight out of raw (as most do) would then
	// store that invalid byte sequence verbatim as a token's real
	// value, corrupting whatever otherwise-valid-UTF-8 text it later
	// gets substituted back into on detokenize. Blocking here keeps
	// this in the same "can't safely reason about this input" category
	// as the duplicate-key and unrecognized-block-type checks below,
	// rather than silently risking corrupted output.
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("request body contains invalid UTF-8")
	}
	if dup, err := findDuplicateKey(raw); err != nil {
		return nil, fmt.Errorf("checking for duplicate JSON keys: %w", err)
	} else if dup != "" {
		return nil, fmt.Errorf("request body contains a duplicate JSON key %q; blocking rather than risking the redactor and the real API server resolving it to two different values", dup)
	}
	paths, inputPaths, unknownType := collectPaths(raw)
	if unknownType != "" {
		return nil, fmt.Errorf("request body contains an unrecognized content block type %q; blocking rather than risking unredacted content reaching the model", unknownType)
	}
	return apply(raw, paths, inputPaths, protectSystemReminders(tf))
}

// systemReminderPattern matches Claude Code's own harness-injected
// <system-reminder>...</system-reminder> blocks -- the same wrapper
// visible around the environment context (userEmail, currentDate, agent
// listings, etc.) injected into this very conversation's own messages.
// Unlike the top-level "system" field, this content is interleaved
// inline inside message strings that also legitimately carry real
// user/client text, so it can't be excluded at the field level -- it
// needs span-level handling within the string instead.
var systemReminderPattern = regexp.MustCompile(`(?s)<system-reminder>.*?</system-reminder>`)

// knownFixedReminderPrefixes are the openers of reminder shapes verified,
// from a full audit of real production traffic (every distinct
// <system-reminder> shape seen across a live engagement's complete log
// history), to be fixed Claude-Code-authored boilerplate that never
// carries real user/client content -- agent/skill listings, plan-mode
// notices, the token-budget counter. Anything NOT starting with one of
// these -- including a reminder shape Claude Code adds in the future
// that this audit never saw -- is scanned like ordinary text by default.
// That default matters: it's the opposite of, and replaces, this
// function's previous "protect everything, no exceptions" behavior,
// found live to hide a real leak (see the tool-call-replay case below,
// caught by falling through to the scan-by-default path here).
var knownFixedReminderPrefixes = []string{
	"<total_tokens>",
	"Available agent types for the Agent tool:",
	"## Auto Mode Active",
	"The following skills are available for use with the Skill tool:",
	"## Exited Plan Mode",
}

// environmentContextPrefix marks the one reminder shape that bundles
// BOTH fixed harness facts (userEmail, currentDate, ...) AND genuinely
// user-authored content (claudeMd -- the project's own CLAUDE.md file
// contents) in a single block, separated by "# <name>" section headers.
// A real leak found live: this whole block used to be protected as one
// unit, which meant a CLAUDE.md containing real engagement-specific
// notes (methodology, scope, findings-in-progress -- exactly the kind
// of content operators write there) reached the model completely
// unscanned, every single turn, for the life of the conversation.
const environmentContextPrefix = "As you answer the user's questions, you can use the following context:\n"

// scannableContextSections are the named sections within the
// environment-context reminder (see environmentContextPrefix) known to
// carry real, operator-authored content, and so scanned like ordinary
// text. Every OTHER named section -- userEmail, currentDate, and
// anything Claude Code adds to this wrapper in the future -- stays
// protected by default. That's the opposite default from
// knownFixedReminderPrefixes above, deliberately: this wrapper's own
// stated purpose ("the following context") is bundling fixed
// Anthropic-injected identity/environment facts, so an unrecognized
// section here is far more likely to be another fact like userEmail
// than a second source of real file content -- protecting by default is
// the better call specifically within this one wrapper.
var scannableContextSections = map[string]bool{
	"claudeMd": true,
}

var contextSectionHeaderRe = regexp.MustCompile(`(?m)^# (\S+)\n`)

// protectSystemReminders wraps tf so it applies correctly across every
// <system-reminder>...</system-reminder> span found in s: verbatim
// protection for known-fixed boilerplate, selective per-section handling
// for the environment-context wrapper, and full scanning (same as
// ordinary surrounding text) for everything else -- see this file's
// three doc comments above for exactly which shape gets which treatment
// and why.
func protectSystemReminders(tf func(string) (string, error)) func(string) (string, error) {
	return func(s string) (string, error) {
		locs := systemReminderPattern.FindAllStringIndex(s, -1)
		if locs == nil {
			return tf(s)
		}
		transformSegment := func(seg string) (string, error) {
			if seg == "" {
				return "", nil
			}
			return tf(seg)
		}
		var b strings.Builder
		last := 0
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			transformed, err := transformSegment(s[last:start])
			if err != nil {
				return "", err
			}
			b.WriteString(transformed)
			reminder, err := handleSystemReminder(s[start:end], tf)
			if err != nil {
				return "", err
			}
			b.WriteString(reminder)
			last = end
		}
		tail, err := transformSegment(s[last:])
		if err != nil {
			return "", err
		}
		b.WriteString(tail)
		return b.String(), nil
	}
}

// handleSystemReminder decides how to treat ONE <system-reminder>...
// </system-reminder> span (including its own tags) and returns the
// resulting text -- see protectSystemReminders' doc comment for the
// three possible outcomes.
func handleSystemReminder(reminder string, tf func(string) (string, error)) (string, error) {
	body := strings.TrimSuffix(strings.TrimPrefix(reminder, "<system-reminder>"), "</system-reminder>")
	trimmed := strings.TrimLeft(body, "\n")

	for _, prefix := range knownFixedReminderPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return reminder, nil // verbatim -- known fixed boilerplate
		}
	}

	if strings.HasPrefix(trimmed, environmentContextPrefix) {
		scanned, err := scanEnvironmentContext(body, tf)
		if err != nil {
			return "", err
		}
		return "<system-reminder>" + scanned + "</system-reminder>", nil
	}

	// Default: an unrecognized shape (including a tool-call-input/result
	// replay -- see environmentContextPrefix's doc comment for the real
	// leak this covers) is scanned like ordinary text, not protected.
	scanned, err := tf(body)
	if err != nil {
		return "", err
	}
	return "<system-reminder>" + scanned + "</system-reminder>", nil
}

// scanEnvironmentContext splits an environment-context reminder body
// into its "# <name>" sections and scans only the ones in
// scannableContextSections, leaving every other section -- including
// the intro line and anything trailing the last section -- untouched.
func scanEnvironmentContext(body string, tf func(string) (string, error)) (string, error) {
	headers := contextSectionHeaderRe.FindAllStringSubmatchIndex(body, -1)
	if headers == nil {
		return body, nil // no named sections found -- nothing to selectively scan
	}
	var b strings.Builder
	b.WriteString(body[:headers[0][0]]) // intro line before the first "# name" header
	for i, h := range headers {
		headerStart, headerEnd := h[0], h[1]
		name := body[h[2]:h[3]]
		sectionEnd := len(body)
		if i+1 < len(headers) {
			sectionEnd = headers[i+1][0]
		}
		b.WriteString(body[headerStart:headerEnd]) // the "# name\n" header line itself
		content := body[headerEnd:sectionEnd]
		if scannableContextSections[name] {
			scanned, err := tf(content)
			if err != nil {
				return "", err
			}
			b.WriteString(scanned)
		} else {
			b.WriteString(content)
		}
	}
	return b.String(), nil
}

// Detokenize walks raw (a full non-streaming Messages API response body,
// whose content lives in a top-level "content" array rather than
// "messages") and replaces every content-carrying string with
// tf(original). For streaming (SSE) responses, callers reconstruct one
// content block at a time from buffered deltas and should call
// redact.Engine.Detokenize directly on that block's known text/input
// field rather than going through this walker; the block type is
// already known at that point, so a generic walk adds nothing. tf has no
// error return: per
// redact.Engine.Detokenize's fail-open policy, an unrecognized token
// passes through as literal text rather than erroring. If the walk
// itself hits a structural problem (should not happen against
// Anthropic's own response shape), Detokenize returns raw unchanged
// rather than a partially-rewritten body; the safe failure direction on
// this path is "Claude Code sees a token it can't resolve," never a
// corrupted response.
func Detokenize(raw []byte, tf func(string) string) []byte {
	// unrecognized block type deliberately ignored here -- see this
	// function's own doc comment on why the response direction fails
	// open (a token left unresolved), unlike Tokenize's request-direction
	// hard failure on the same signal.
	paths, inputPaths, _ := collectPaths(raw)
	out, err := apply(raw, paths, inputPaths, func(s string) (string, error) {
		return tf(s), nil
	})
	if err != nil {
		return raw
	}
	return out
}

// jsonEncodeString JSON-encodes s exactly the way sjson.SetBytes does
// (see its appendStringify/mustMarshalString in sjson.go): a string
// containing only printable ASCII with no quote, backslash, or control
// character is wrapped in quotes and copied verbatim -- notably NOT
// HTML-escaping "<", ">", or "&" -- while anything else (any non-ASCII
// byte, a quote, a backslash, or a control character) goes through
// encoding/json.Marshal, whose default output (including that same
// HTML-escaping) matches sjson's own fallback exactly. Matching this
// byte-for-byte, rather than calling json.Marshal unconditionally, is
// what keeps apply's fast path and applyPerPath's sjson.SetBytes-based
// slow-path fallback provably interchangeable for the SAME input --
// found to diverge on exactly this point (a changed value containing
// "<", ">", or "&" but nothing else requiring escaping) by
// FuzzApplyFastSlowPathAgreement, the property TestApply_
// FastPathVerifiedAgainstSlowPath already pins by hand.
func jsonEncodeString(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] > 0x7f || s[i] == '"' || s[i] == '\\' {
			return json.Marshal(s)
		}
	}
	buf := make([]byte, 0, len(s)+2)
	buf = append(buf, '"')
	buf = append(buf, s...)
	buf = append(buf, '"')
	return buf, nil
}

// apply reads each path's current value from the ORIGINAL parse of raw,
// transforms it, and splices every changed value back into raw in ONE
// pass, rather than one full-document sjson.SetBytes rewrite per path.
// sjson.Set has to re-scan from the start of the document to locate
// each path, so calling it once per path was effectively O(paths) full-
// document rewrites, quadratic in the number of redacted strings for
// a body whose size grows with that count, which a large but realistic
// tool result (a few thousand hosts in a scan result, say) turns into
// several seconds to tens of seconds of pure redaction latency. Reading
// against the original parse (rather than the progressively-mutated
// output) is safe because every change here is a pure value replacement
// (no array insertion or deletion), so paths, and the byte offsets
// read from the original parse, stay valid throughout.
//
// The splice itself trusts gjson.Result's Index/Raw fields (byte offset
// and exact original text of the matched value) to locate each change
// directly in raw, rather than re-deriving it from the path, and it's reliable
// across nested objects/arrays, escaped characters, and multi-byte
// Unicode content for every path shape this package produces. Index is
// documented as 0 when gjson couldn't report an
// offset; combined with a slice-equality check against Raw, that's
// treated as "don't trust this" rather than "assume 0"; an incorrect
// offset here would silently corrupt a byte range instead of merely
// costing time, a strictly worse failure than falling back to the
// slower-but-unconditionally-correct per-path implementation for the
// whole call. See TestApply_FastPathVerifiedAgainstSlowPath for the
// property this leans on: the two implementations must always agree.
// apply also takes inputPaths, the whole "input" object of every
// tool_use/mcp_tool_use block (see collectPaths), and redacts each ONE
// as a self-contained unit via redactValue (both its object keys and its
// values, recursively), splicing the result in as raw JSON rather than
// as a single re-encoded string leaf.
func apply(raw []byte, paths []string, inputPaths []string, tf func(string) (string, error)) ([]byte, error) {
	root := gjson.ParseBytes(raw)
	type change struct {
		start, end int
		newVal     string
		raw        bool // newVal is already valid JSON text; splice verbatim, don't re-encode as a string
	}
	var changes []change
	for _, p := range paths {
		r := root.Get(p)
		orig := r.String()
		newVal, err := tf(orig)
		if err != nil {
			return nil, fmt.Errorf("transform %s: %w", p, err)
		}
		if newVal == orig {
			continue // skip a no-op write so byte layout stays maximally stable
		}
		start, end := r.Index, r.Index+len(r.Raw)
		if start <= 0 || end > len(raw) || string(raw[start:end]) != r.Raw {
			return applyPerPath(raw, paths, inputPaths, tf)
		}
		changes = append(changes, change{start: start, end: end, newVal: newVal})
	}
	for _, ip := range inputPaths {
		r := root.Get(ip)
		newRaw, err := redactValue(r, tf)
		if err != nil {
			return nil, fmt.Errorf("transform %s: %w", ip, err)
		}
		if newRaw == r.Raw {
			continue // nothing in this input needed redaction -- byte layout stays maximally stable
		}
		start, end := r.Index, r.Index+len(r.Raw)
		if start <= 0 || end > len(raw) || string(raw[start:end]) != r.Raw {
			return applyPerPath(raw, paths, inputPaths, tf)
		}
		changes = append(changes, change{start: start, end: end, newVal: newRaw, raw: true})
	}
	if len(changes) == 0 {
		return raw, nil
	}

	slices.SortFunc(changes, func(a, b change) int { return cmp.Compare(a.start, b.start) })
	out := make([]byte, 0, len(raw)+16*len(changes))
	last := 0
	for _, c := range changes {
		out = append(out, raw[last:c.start]...)
		if c.raw {
			out = append(out, c.newVal...)
		} else {
			encoded, err := jsonEncodeString(c.newVal)
			if err != nil {
				return nil, fmt.Errorf("encode replacement: %w", err)
			}
			out = append(out, encoded...)
		}
		last = c.end
	}
	out = append(out, raw[last:]...)
	return out, nil
}

// applyPerPath is apply's fallback: leaf paths go through the original
// one-sjson.SetBytes-call-per-path implementation, correct regardless of
// whether gjson can report reliable byte offsets for a given path (it
// never reads one); each inputPaths entry falls back to the pre-Finding-
// 12 behavior of redacting only its VALUES (via collectLeafStrings), the
// same limitation this whole change exists to close, rather than risking
// a corrupt splice for an offset apply's fast path couldn't verify;
// see apply's own doc comment for why that path is expected to never
// actually fire against real Messages API bodies.
func applyPerPath(raw []byte, paths []string, inputPaths []string, tf func(string) (string, error)) ([]byte, error) {
	root := gjson.ParseBytes(raw)
	out := raw
	for _, p := range paths {
		orig := root.Get(p).String()
		newVal, err := tf(orig)
		if err != nil {
			return nil, fmt.Errorf("transform %s: %w", p, err)
		}
		if newVal == orig {
			continue // skip a no-op write so byte layout stays maximally stable
		}
		var setErr error
		out, setErr = sjson.SetBytes(out, p, newVal)
		if setErr != nil {
			return nil, fmt.Errorf("set %s: %w", p, setErr)
		}
	}
	for _, ip := range inputPaths {
		var leafPaths []string
		collectLeafStrings(gjson.ParseBytes(out).Get(ip), ip, &leafPaths)
		for _, p := range leafPaths {
			root := gjson.ParseBytes(out)
			orig := root.Get(p).String()
			newVal, err := tf(orig)
			if err != nil {
				return nil, fmt.Errorf("transform %s: %w", p, err)
			}
			if newVal == orig {
				continue
			}
			var setErr error
			out, setErr = sjson.SetBytes(out, p, newVal)
			if setErr != nil {
				return nil, fmt.Errorf("set %s: %w", p, setErr)
			}
		}
	}
	return out, nil
}

// redactValue recursively redacts both object keys and string values
// within v via tf, returning v's own fully-redacted raw JSON text with
// every other byte (number/bool/null formatting, unchanged strings'
// exact original escaping, key order) reproduced from v.Raw verbatim.
// Used only for a tool_use/mcp_tool_use block's "input" object, whose
// schema is per-tool and unknown ahead of time: unlike the rest of the
// body (where object keys are ALWAYS protocol structure like role, type,
// and tool_use.id/name, which must never be tokenized), everything inside
// input is tool-parameter content, and that includes keys a tool
// legitimately uses to carry real data. A published nmap-scanning MCP
// server, for one real example, returns findings keyed by IP address
// ("per_host": {"10.1.2.3": {...}}) rather than as a value, a shape
// this package's own value-only walk had no way to protect.
//
// Processing is bottom-up by construction (a child's redacted text is
// computed, via recursion, before its parent assembles its own), so
// nothing here needs the byte-offset tricks apply's fast path relies on:
// each level builds a brand new string rather than patching the
// original, so there are no stale offsets to invalidate.
//
// Every replacement key or value is re-encoded via jsonEncodeString,
// matching sjson's own string-escaping behavior byte-for-byte -- while
// anything left unchanged is copied from its own v.Raw verbatim, so a
// redaction elsewhere in the same input never touches formatting or
// escaping the rest of it already had.
func redactValue(v gjson.Result, tf func(string) (string, error)) (string, error) {
	switch {
	case v.Type == gjson.String:
		orig := v.String()
		newVal, err := tf(orig)
		if err != nil {
			return "", err
		}
		if newVal == orig {
			return v.Raw, nil
		}
		encoded, err := jsonEncodeString(newVal)
		if err != nil {
			return "", err
		}
		return string(encoded), nil

	case v.IsObject():
		var b strings.Builder
		b.WriteByte('{')
		first := true
		var iterErr error
		v.ForEach(func(key, val gjson.Result) bool {
			childRaw, err := redactValue(val, tf)
			if err != nil {
				iterErr = err
				return false
			}
			newKey, err := tf(key.String())
			if err != nil {
				iterErr = err
				return false
			}
			keyEncoded, err := jsonEncodeString(newKey)
			if err != nil {
				iterErr = err
				return false
			}
			if !first {
				b.WriteByte(',')
			}
			first = false
			b.Write(keyEncoded)
			b.WriteByte(':')
			b.WriteString(childRaw)
			return true
		})
		if iterErr != nil {
			return "", iterErr
		}
		b.WriteByte('}')
		return b.String(), nil

	case v.IsArray():
		var b strings.Builder
		b.WriteByte('[')
		first := true
		var iterErr error
		v.ForEach(func(_, val gjson.Result) bool {
			childRaw, err := redactValue(val, tf)
			if err != nil {
				iterErr = err
				return false
			}
			if !first {
				b.WriteByte(',')
			}
			first = false
			b.WriteString(childRaw)
			return true
		})
		if iterErr != nil {
			return "", iterErr
		}
		b.WriteByte(']')
		return b.String(), nil

	default:
		// number, bool, null -- never content, always passed through
		// verbatim.
		return v.Raw, nil
	}
}

// collectPaths returns every content-carrying string leaf's gjson path,
// PLUS separately (inputPaths) the path of every tool_use/mcp_tool_use
// block's whole "input" object, which needs different handling from
// every other leaf (see redactValue's doc comment: its schema is
// per-tool and unknown ahead of time, so unlike the rest of the body its
// object KEYS can carry real content too, not just its values), plus
// the first unrecognized content block type encountered (empty string if
// none). See collectBlockArrayPaths and Tokenize/Detokenize's own doc
// comments for why an unrecognized type is reported rather than silently
// skipped, and why the two callers deliberately react to it differently.
//
// The top-level "system" field is deliberately NEVER walked: it's
// entirely the harness's own fixed instructions, skill/tool
// descriptions, and boilerplate (any domains appearing there, e.g.
// claude.ai, github.com in tool descriptions or the "/help" feedback
// link, are never client or user-typed content). End users and
// operators don't write into "system"; that's not how the Messages API
// or Claude Code work; real content always lives in "messages".
// Scanning it serves no PII-protection purpose, and doing so
// anyway has real downside: substituting a fake token in place of a
// domain the model's own tool descriptions reference by name degrades
// Claude's understanding of its own capabilities for no protective
// benefit, and rewriting Anthropic's own expected boilerplate risks
// looking like tampering to anything on their side that might validate
// its shape. This is unrelated to a "role":"system" MESSAGE inside the
// "messages" array below (a separate, documented mid-conversation role
// that legitimately can carry real operator-written content); only the
// top-level field is excluded.
func collectPaths(raw []byte) (paths []string, inputPaths []string, unknownType string) {
	root := gjson.ParseBytes(raw)

	if msgs := root.Get("messages"); msgs.IsArray() {
		msgs.ForEach(func(mi, msg gjson.Result) bool {
			base := fmt.Sprintf("messages.%d.content", mi.Int())
			content := msg.Get("content")

			if content.Type == gjson.String {
				paths = append(paths, base)
				return true
			}
			if content.IsArray() {
				if t := collectBlockArrayPaths(content, base, &paths, &inputPaths); t != "" && unknownType == "" {
					unknownType = t
				}
			}
			return true
		})
	}

	// Non-streaming responses are a single Message object with a
	// top-level "content" array (no "messages" wrapper; the response
	// IS the content, unlike a request body).
	if content := root.Get("content"); content.IsArray() {
		if t := collectBlockArrayPaths(content, "content", &paths, &inputPaths); t != "" && unknownType == "" {
			unknownType = t
		}
	}

	return paths, inputPaths, unknownType
}

// collectBlockArrayPaths applies the per-block-type routing rules (text,
// tool_result/mcp_tool_result, tool_use/mcp_tool_use, and the skipped
// types) to a content-block array at basePath, appending every
// content-carrying leaf path it finds (or, for tool_use/mcp_tool_use,
// its whole "input" object's path to inputPaths instead; see
// collectPaths' doc comment). Shared between messages[].content (request
// bodies) and the top-level content array (non-streaming response
// bodies); both are the same content-block-array shape.
//
// Returns the first block (or, for tool_result/mcp_tool_result, nested
// content sub-block) type it doesn't recognize as either routable or
// deliberately skipped. A bare blocklist-plus-fixed-switch with no
// default case would mean any block type this list doesn't yet know
// about (a new Anthropic feature, a provider-specific block, a nested
// tool_result content type other than text/image) silently contributes
// zero paths, so its real content passes through completely unredacted
// with no error and no log line: a block of an unrecognized type
// carrying real text would tokenize zero times and reach the outbound
// request body unchanged.
func collectBlockArrayPaths(blocks gjson.Result, basePath string, paths *[]string, inputPaths *[]string) (unknownType string) {
	blocks.ForEach(func(bi, block gjson.Result) bool {
		blockBase := fmt.Sprintf("%s.%d", basePath, bi.Int())
		typ := block.Get("type").String()
		if skipBlockTypes[typ] {
			return true
		}

		switch typ {
		case "text":
			*paths = append(*paths, blockBase+".text")
		case "tool_result", "mcp_tool_result":
			tc := block.Get("content")
			if tc.Type == gjson.String {
				*paths = append(*paths, blockBase+".content")
			} else if tc.IsArray() {
				tc.ForEach(func(ti, sub gjson.Result) bool {
					subType := sub.Get("type").String()
					switch {
					case subType == "text":
						*paths = append(*paths, fmt.Sprintf("%s.content.%d.text", blockBase, ti.Int()))
					case skipBlockTypes[subType]:
						// intentionally skipped, e.g. an image sub-block
					default:
						if unknownType == "" {
							unknownType = subType
						}
					}
					return true
				})
			}
		case "tool_use", "mcp_tool_use":
			*inputPaths = append(*inputPaths, blockBase+".input")
		default:
			if unknownType == "" {
				unknownType = typ
			}
		}
		return true
	})
	return unknownType
}

// collectLeafStrings recursively finds every string leaf inside an
// arbitrary JSON value. Used only for tool_use.input, whose schema is
// per-tool and unknown ahead of time. Unlike the rest of the body,
// everything inside input is tool-parameter content with no
// protocol/structural fields mixed in, so a fully generic walk is safe
// specifically there (it would NOT be safe at the top level: model,
// role, type, tool_use.id/name, etc. must never be tokenized).
func collectLeafStrings(v gjson.Result, path string, out *[]string) {
	join := func(child string) string {
		if path == "" {
			return child
		}
		return path + "." + child
	}
	switch {
	case v.Type == gjson.String:
		*out = append(*out, path)
	case v.IsObject():
		v.ForEach(func(key, val gjson.Result) bool {
			collectLeafStrings(val, join(escapeGJSONKey(key.String())), out)
			return true
		})
	case v.IsArray():
		i := 0
		v.ForEach(func(_, val gjson.Result) bool {
			collectLeafStrings(val, join(fmt.Sprintf("%d", i)), out)
			i++
			return true
		})
	}
}

// DetokenizeValue walks an arbitrary standalone JSON value (not
// necessarily wrapped in a Messages API envelope) and replaces every
// string leaf AND object key with tf(original) via redactValue,
// preserving all other structure and byte layout. Used for a
// tool_use.input object reconstructed on its own from buffered SSE
// deltas during streaming, where there is no surrounding
// "messages"/"content" wrapper to route through; the same shape
// apply's inputPaths handling covers for the non-streaming case, via
// the same redactValue.
func DetokenizeValue(raw []byte, tf func(string) string) []byte {
	if !gjson.ValidBytes(raw) {
		return raw
	}
	out, err := redactValue(gjson.ParseBytes(raw), func(s string) (string, error) { return tf(s), nil })
	if err != nil {
		return raw
	}
	return []byte(out)
}

// escapeGJSONKey escapes characters that are syntactically significant in
// gjson/sjson dot-paths (., *, ?) so an object key containing one of them
// is treated as a literal path segment rather than a wildcard or a
// spurious path separator.
func escapeGJSONKey(key string) string {
	// gjson.Escape (not a hand-maintained subset) is authoritative here:
	// it escapes every character gjson's path parser treats as special
	// (previously this only covered ".", "*", "?" -- missing "|" and
	// "\", which let an object key containing either silently fail the
	// path lookup below, so the string never reached a detector and went
	// out unredacted). Using the library's own function also stays in
	// sync if a future gjson version reserves another character.
	return gjson.Escape(key)
}
