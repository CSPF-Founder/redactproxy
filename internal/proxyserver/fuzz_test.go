package proxyserver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/tidwall/gjson"

	"github.com/CSPF-Founder/redactproxy/internal/redact"
	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// Covers the SSE streaming path in two layers: FuzzReadSSEFrame and
// FuzzTextFlushBoundary fuzz the two pure-ish, self-contained pieces
// (see sse.go) in isolation; FuzzHandleBlockDelta exercises the
// stateful handleBlockStart/Delta/Stop layer wrapping them -- the
// actual code a live SSE response drives -- against a fake
// http.ResponseWriter+flusher and a real *Server/Engine/store.
// readSSEFrame in particular is real parsing of untrusted external
// network bytes (it reads directly off the live upstream HTTP response
// body), a different risk shape from every other fuzz target in this
// repo, which all parse already-decoded strings or JSON documents, not
// a raw byte stream a parser pulls apart line by line.

// FuzzReadSSEFrame fuzzes readSSEFrame against arbitrary byte streams.
// The most important property for anything sitting in a live proxy's
// streaming path: it must always terminate. readSSEFrame is called in
// a loop by proxySSE until it reports ok == false, so a single input
// shape that made it loop forever without making progress would hang
// every request using that shape -- a live denial-of-service, not just
// a test failure. Enforced here with a hard iteration cap tied to the
// input size (readSSEFrame's own contract is "at least one byte
// consumed per line, or a clean return on EOF/error", so the number of
// frames+lines it can ever produce from N bytes is bounded by N) --
// exceeding the cap fails the fuzz case rather than actually hanging
// the fuzzer.
func FuzzReadSSEFrame(f *testing.F) {
	for _, seed := range sseFuzzSeeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bufio.NewReader(bytes.NewReader(data))
		maxIterations := len(data) + 10
		var frames int
		for i := 0; ; i++ {
			if i > maxIterations {
				t.Fatalf("readSSEFrame did not terminate within %d iterations for a %d-byte input -- possible infinite loop:\n  data: %q", maxIterations, len(data), data)
			}
			_, _, ok, err := readSSEFrame(r)
			if err != nil {
				return // a real I/O error from bytes.Reader is not expected, but not a bug in readSSEFrame itself if it happens
			}
			if !ok {
				return // clean EOF, no partial frame pending -- expected terminal state
			}
			frames++
			if frames > maxIterations {
				t.Fatalf("readSSEFrame returned more frames (%d) than the %d-byte input could possibly contain -- possible infinite loop:\n  data: %q", frames, len(data), data)
			}
		}
	})
}

// FuzzTextFlushBoundary fuzzes textFlushBoundary directly. Its own
// contract (see its doc comment) is simple enough to check exactly: the
// returned index must always be in [0, len(buf)] (so the caller's
// buf[:n]/buf[n:] split can never panic), and it must be internally
// consistent with its own two rules -- either it's the position right
// after the last textBoundaryChars byte in buf, or (if that position
// would leave more than maxHeldTokenRunBytes held back) it's exactly
// len(buf)-maxHeldTokenRunBytes -- walked back to the nearest UTF-8
// rune boundary.
//
// Input is sanitized to valid UTF-8 (strings.ToValidUTF8) before use,
// matching the real precondition textFlushBoundary's only caller
// (handleBlockDelta) actually guarantees: st.textBuf is only ever
// appended to from a JSON-decoded delta string, and encoding/json
// itself already replaces any invalid UTF-8 in the wire payload with
// U+FFFD during decode -- a raw invalid byte (e.g. 0xfa, never a valid
// UTF-8 lead byte under any circumstance) cannot actually reach this
// function in production. Fuzzing arbitrary bytes here found exactly
// that shape flushed as invalid UTF-8 (buf=[]byte{0xfa, ' '}), but it
// doesn't reflect a real input this function is ever actually asked to
// handle, so the fix is scoping the fuzz input to match reality, not
// hardening the function against a precondition its one real caller
// already enforces upstream.
func FuzzTextFlushBoundary(f *testing.F) {
	for _, seed := range sseFuzzSeeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		buf := []byte(strings.ToValidUTF8(string(data), ""))
		n := textFlushBoundary(buf)
		if n < 0 || n > len(buf) {
			t.Fatalf("textFlushBoundary returned out-of-range index %d for a %d-byte buffer:\n  buf: %q", n, len(buf), buf)
		}

		natural := bytes.LastIndexAny(buf, string(textBoundaryChars)) + 1
		held := len(buf) - natural
		want := natural
		if held > maxHeldTokenRunBytes {
			want = len(buf) - maxHeldTokenRunBytes
			for want > 0 && !utf8.RuneStart(buf[want]) {
				want--
			}
		}
		if n != want {
			t.Fatalf("textFlushBoundary disagrees with its own documented rule:\n  buf:  %q\n  got:  %d\n  want: %d", buf, n, want)
		}
		// Only the flushed prefix matters here -- that's the part that
		// actually reaches the client. The held-back remainder is
		// legitimately allowed to be incomplete/invalid on its own (a
		// single truncated multi-byte lead byte, say): more bytes are
		// expected to arrive later and complete it. Asserting BOTH
		// halves independently valid is too strict and produces a false
		// positive on exactly that input shape (e.g. buf = []byte{0xd0},
		// a lone two-byte UTF-8 lead byte with no continuation byte
		// yet): n=0 correctly flushes nothing and holds the whole thing
		// back, which is the right call, not a bug.
		if !utf8.Valid(buf[:n]) {
			t.Fatalf("textFlushBoundary flushed a split multi-byte rune to the client:\n  buf: %q\n  n:   %d", buf, n)
		}
	})
}

// sseFuzzSeeds covers: a well-formed single frame, multiple frames back
// to back, a frame with both event: and data: fields, multi-line data
// (SSE's own continuation convention -- multiple "data:" lines join
// with "\n"), a keep-alive blank line before a real frame, no trailing
// blank line (a frame cut off mid-stream, the real shape of a
// connection dropped mid-response), CRLF line endings, a frame with
// neither event: nor data: (only unrecognized field lines), an empty
// input, a single blank line with nothing else, and lines with no
// trailing newline at all (a stream that ends without ever completing
// its last line).
var sseFuzzSeeds = []string{
	"",
	"\n",
	"data: hello\n\n",
	"event: content_block_delta\ndata: {\"type\":\"text_delta\"}\n\n",
	"data: line one\ndata: line two\n\n",
	"\ndata: after keepalive\n\n",
	"event: a\ndata: 1\n\nevent: b\ndata: 2\n\n",
	"data: no trailing blank line",
	"event: x\r\ndata: y\r\n\r\n",
	"id: 123\ndata: has an id field too\n\n",
	"data:",
	"data: unterminated line with no newline at all",
	":\n\n", // a bare SSE comment line, never matched by either prefix
}

// FuzzHandleBlockDelta drives a single "text" content block through
// handleBlockStart -> many handleBlockDelta calls -> handleBlockStop,
// splitting the fuzzer-provided text into small chunks, then checks:
//   - no panic/hang across the whole sequence.
//   - every frame written to the recorder parses cleanly via
//     readSSEFrame (structural SSE well-formedness).
//   - the store is fresh and empty for every call (no real value was
//     ever minted into it), so Detokenize is a pure identity function
//     on this input regardless of its shape -- meaning the exact
//     concatenation of every emitted text_delta's "text" field must
//     equal the original input byte-for-byte. This is the precise
//     invariant the textFlushBoundary rune-boundary fix exists to
//     satisfy: any split, however finely chunked, must reassemble to
//     the original text with no U+FFFD substitution or dropped bytes.
//
// The input is sanitized to valid UTF-8 (strings.ToValidUTF8) before
// use specifically so any U+FFFD that DOES show up in the output is
// unambiguous: it can only have been introduced by the streaming
// reconstruction itself, never carried over from the input already
// containing one.
func FuzzHandleBlockDelta(f *testing.F) {
	for _, seed := range sseHandlerFuzzSeeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		text := strings.ToValidUTF8(string(data), "")
		if text == "" {
			return
		}

		dir := t.TempDir()
		store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
		if err != nil {
			t.Fatalf("tokenstore.Open: %v", err)
		}
		defer store.Close()
		engine := redact.New(store, redact.DefaultDetectors()...)
		upstreamURL, _ := url.Parse("http://upstream.invalid")
		srv := New(Config{Upstream: upstreamURL, Engine: engine})

		rec := httptest.NewRecorder()
		blocks := map[int]*blockState{}

		srv.handleBlockStart(rec, rec, "content_block_start", `{}`,
			map[string]any{"index": float64(0), "content_block": map[string]any{"type": "text"}},
			blocks)

		// One byte per delta -- the most adversarial chunking for the
		// rune-boundary property, and the exact shape described in
		// handleBlockDelta's own doc comment for the class of bug this
		// buffering exists to catch.
		for i := 0; i < len(text); i++ {
			srv.handleBlockDelta(rec, rec, "content_block_delta", `{}`,
				map[string]any{"index": float64(0), "delta": map[string]any{"type": "text_delta", "text": string([]byte{text[i]})}},
				blocks, "/v1/messages")
		}

		srv.handleBlockStop(rec, rec, "content_block_stop", `{}`,
			map[string]any{"index": float64(0)}, blocks, "/v1/messages")

		got := reconstructTextDeltas(t, rec.Body.Bytes())
		if got != text {
			t.Fatalf("streamed text reconstruction mismatch:\n  in:  %q\n  out: %q", text, got)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("reconstructed text is not valid UTF-8: %q", got)
		}
	})
}

// reconstructTextDeltas parses every SSE frame in body via readSSEFrame
// (the same parser fuzzed independently by FuzzReadSSEFrame, so a
// malformed frame here fails loudly rather than silently), extracts
// each content_block_delta/text_delta's "text" field by unmarshaling
// the frame's data as JSON (matching how a real client parses an SSE
// event), and concatenates them in order.
func reconstructTextDeltas(t *testing.T, body []byte) string {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(body))
	var out strings.Builder
	for {
		_, data, ok, err := readSSEFrame(r)
		if err != nil {
			t.Fatalf("readSSEFrame: %v", err)
		}
		if !ok {
			return out.String()
		}
		var evt struct {
			Type  string `json:"type"`
			Delta struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue // not every frame is a content_block_delta (e.g. content_block_start/stop)
		}
		if evt.Type == "content_block_delta" && evt.Delta.Type == "text_delta" {
			out.WriteString(evt.Delta.Text)
		}
	}
}

// sseHandlerFuzzSeeds covers: plain ASCII prose, a long CJK run past
// the maxHeldTokenRunBytes safety-valve threshold with no ASCII
// punctuation anywhere (the exact shape that reached
// TestTextFlushBoundary_LongUnbrokenRunCapNeverSplitsAMultiByteRune),
// mixed multi-byte scripts and emoji, and a run of 4-byte characters
// (the widest UTF-8 encoding, worth its own boundary coverage
// independent of the 3-byte CJK case).
var sseHandlerFuzzSeeds = [][]byte{
	[]byte("the quick brown fox jumps over the lazy dog"),
	[]byte(strings.Repeat("东", 70)),
	[]byte(strings.Repeat("🔥", 40)),
	[]byte("mixed: 東京タワー は Tokyo Tower です، وهذا نص عربي طويل بدون علامات ترقيم"),
	[]byte(strings.Repeat("a", 200)),
	[]byte(""),
}

// FuzzHandleBlockDelta_TextThenToolUse drives the shape a real agentic
// turn actually streams: Claude explains what it's about to do in a
// text block, then calls a tool -- through the full handleBlockStart/
// Delta/Stop chain for TWO content blocks at different indices, a
// "text" block at index 0 followed by a "tool_use" block at index 1
// whose partial_json arrives in fuzzer-controlled single-byte chunks.
// FuzzDetokenizeValue above fuzzes the function behind the tool_use
// path directly; this exercises the same logic through its actual call
// site in handleBlockStop, together with a second, independent block
// sharing the same blocks map -- checking that per-index state stays
// isolated (the text reconstruction for index 0 is unaffected by
// whatever arrives at index 1) and that a valid-JSON tool input never
// comes out invalid.
func FuzzHandleBlockDelta_TextThenToolUse(f *testing.F) {
	for _, seed := range sseMultiBlockFuzzSeeds {
		f.Add(seed.text, seed.json)
	}

	f.Fuzz(func(t *testing.T, textData []byte, jsonData []byte) {
		text := strings.ToValidUTF8(string(textData), "")

		dir := t.TempDir()
		store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
		if err != nil {
			t.Fatalf("tokenstore.Open: %v", err)
		}
		defer store.Close()
		engine := redact.New(store, redact.DefaultDetectors()...)
		upstreamURL, _ := url.Parse("http://upstream.invalid")
		srv := New(Config{Upstream: upstreamURL, Engine: engine})

		rec := httptest.NewRecorder()
		blocks := map[int]*blockState{}

		srv.handleBlockStart(rec, rec, "content_block_start", `{}`,
			map[string]any{"index": float64(0), "content_block": map[string]any{"type": "text"}},
			blocks)
		for i := 0; i < len(text); i++ {
			srv.handleBlockDelta(rec, rec, "content_block_delta", `{}`,
				map[string]any{"index": float64(0), "delta": map[string]any{"type": "text_delta", "text": string([]byte{text[i]})}},
				blocks, "/v1/messages")
		}
		srv.handleBlockStop(rec, rec, "content_block_stop", `{}`,
			map[string]any{"index": float64(0)}, blocks, "/v1/messages")

		srv.handleBlockStart(rec, rec, "content_block_start", `{}`,
			map[string]any{"index": float64(1), "content_block": map[string]any{"type": "tool_use"}},
			blocks)
		for i := 0; i < len(jsonData); i++ {
			srv.handleBlockDelta(rec, rec, "content_block_delta", `{}`,
				map[string]any{"index": float64(1), "delta": map[string]any{"type": "input_json_delta", "partial_json": string([]byte{jsonData[i]})}},
				blocks, "/v1/messages")
		}
		srv.handleBlockStop(rec, rec, "content_block_stop", `{}`,
			map[string]any{"index": float64(1)}, blocks, "/v1/messages")

		gotText, gotJSON := reconstructMultiBlock(t, rec.Body.Bytes())
		if gotText != text {
			t.Fatalf("text block (index 0) reconstruction mismatch, despite an unrelated tool_use block sharing the same blocks map:\n  in:  %q\n  out: %q", text, gotText)
		}
		if gjson.ValidBytes(jsonData) && !gjson.ValidBytes([]byte(gotJSON)) {
			t.Fatalf("tool_use block (index 1) turned valid JSON into invalid JSON:\n  in:  %s\n  out: %s", jsonData, gotJSON)
		}
	})
}

// reconstructMultiBlock parses every SSE frame in body, returning the
// concatenated text_delta text for index 0 and the input_json_delta
// partial_json emitted for index 1 (handleBlockStop's tool_use case
// emits exactly one, at content_block_stop time, never incrementally).
func reconstructMultiBlock(t *testing.T, body []byte) (text string, toolJSON string) {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(body))
	var textOut strings.Builder
	for {
		_, data, ok, err := readSSEFrame(r)
		if err != nil {
			t.Fatalf("readSSEFrame: %v", err)
		}
		if !ok {
			return textOut.String(), toolJSON
		}
		var evt struct {
			Type  string `json:"type"`
			Index int    `json:"index"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue // not every frame is a content_block_delta (e.g. content_block_start/stop)
		}
		if evt.Type != "content_block_delta" {
			continue
		}
		switch {
		case evt.Index == 0 && evt.Delta.Type == "text_delta":
			textOut.WriteString(evt.Delta.Text)
		case evt.Index == 1 && evt.Delta.Type == "input_json_delta":
			toolJSON = evt.Delta.PartialJSON
		}
	}
}

type multiBlockSeed struct {
	text []byte
	json []byte
}

// sseMultiBlockFuzzSeeds covers the realistic text-then-tool_use shape:
// ordinary explanatory text followed by a well-formed tool input (the
// per-host nmap-MCP shape again), an empty text block (a tool call with
// no preceding explanation), a long CJK text block paired with a tool
// call (stressing both blocks' own edge cases at once), and malformed/
// truncated JSON for the tool_use side (the common real case of a
// stream cut off mid-response).
var sseMultiBlockFuzzSeeds = []multiBlockSeed{
	{[]byte("I'll scan the target now."), []byte(`{"target":"widgetcorp-fixture.com","ports":[22,443]}`)},
	{[]byte(""), []byte(`{"per_host":{"10.1.2.3":{"open_ports":[22]}}}`)},
	{[]byte(strings.Repeat("东", 70)), []byte(`{"query":"select * from widgetcorp-fixture.customers"}`)},
	{[]byte("checking"), []byte(`not valid json`)},
	{[]byte("checking"), []byte(`{"truncated":`)},
	{[]byte(""), []byte("")},
}
