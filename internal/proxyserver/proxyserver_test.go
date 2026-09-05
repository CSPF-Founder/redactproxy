package proxyserver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/CSPF-Founder/redactproxy/internal/debuglog"
	"github.com/CSPF-Founder/redactproxy/internal/redact"
	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

func newTestServer(t *testing.T, upstream *httptest.Server) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	srv := New(Config{Upstream: upstreamURL, Engine: engine})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

func TestProxy_NonStreaming_TokenizesRequestDetokenizesResponse(t *testing.T) {
	var capturedReqBody []byte

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedReqBody = body

		// The upstream (standing in for the real Anthropic API) should
		// NEVER see the real domain, only a token.
		if strings.Contains(string(body), "widgetcorp-fixture.com") {
			t.Errorf("real value reached upstream: %s", body)
		}

		w.Header().Set("Content-Type", "application/json")
		// Echo back whatever token the request used, inside an assistant
		// message, simulating Claude replying using the token it saw.
		var reqJSON map[string]any
		json.Unmarshal(body, &reqJSON)
		messages := reqJSON["messages"].([]any)
		firstMsg := messages[0].(map[string]any)
		tokenText := firstMsg["content"].(string)

		resp := map[string]any{
			"id":   "msg_1",
			"type": "message",
			"role": "assistant",
			"content": []map[string]any{
				{"type": "text", "text": "I will check: " + tokenText},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	ts := newTestServer(t, upstream)

	reqBody := `{"model":"claude-opus-5","messages":[{"role":"user","content":"check headers of widgetcorp-fixture.com"}]}`
	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), "widgetcorp-fixture.com") {
		t.Fatalf("expected detokenized real value in client-facing response, got: %s", respBody)
	}
	if strings.Contains(string(capturedReqBody), "widgetcorp-fixture.com") {
		t.Fatalf("captured upstream request body leaked the real value: %s", capturedReqBody)
	}
}

// TestProxy_MultiTurn_ReTokenizesRealValueEchoedBackInConversationHistory
// proves the core agentic-session loop end to end, not just one request:
// turn 1's real value gets tokenized outbound and detokenized back to the
// client (already covered by the test above) -- but a real multi-turn
// client (Claude Code) then re-sends that ENTIRE conversation, including
// its own previous turn, as part of every subsequent request. Since the
// client only ever sees the DETOKENIZED (real) text, turn 2's outbound
// body contains the real value again, embedded in what looks like
// ordinary conversation history, not fresh user input. This confirms the
// proxy correctly re-tokenizes it there too -- with the SAME token turn 1
// used, not a new one -- rather than only catching real values in an
// obviously-new message.
func TestProxy_MultiTurn_ReTokenizesRealValueEchoedBackInConversationHistory(t *testing.T) {
	var capturedBodies [][]byte

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBodies = append(capturedBodies, body)
		if strings.Contains(string(body), "widgetcorp-fixture.com") {
			t.Errorf("real value reached upstream on turn %d: %s", len(capturedBodies), body)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant",
			"content": []map[string]any{{"type": "text", "text": "acknowledged"}},
		})
	}))
	defer upstream.Close()

	ts := newTestServer(t, upstream)

	turn1 := `{"model":"claude-opus-5","messages":[{"role":"user","content":"check headers of widgetcorp-fixture.com"}]}`
	resp1, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(turn1))
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	if len(capturedBodies) != 1 {
		t.Fatalf("expected 1 captured upstream request after turn 1, got %d", len(capturedBodies))
	}

	tokenRe := regexp.MustCompile(`tok[0-9a-f]{16}`)
	turn1Token := tokenRe.FindString(string(capturedBodies[0]))
	if turn1Token == "" {
		t.Fatalf("expected a domain token in turn 1's upstream body, got: %s", capturedBodies[0])
	}

	// Turn 2: the client's own reconstructed history, using the REAL
	// value (exactly what it was shown, since the proxy detokenized
	// turn 1's response) -- plus a new mention of the same domain.
	turn2 := fmt.Sprintf(`{"model":"claude-opus-5","messages":[` +
		`{"role":"user","content":"check headers of widgetcorp-fixture.com"},` +
		`{"role":"assistant","content":"acknowledged"},` +
		`{"role":"user","content":"now check widgetcorp-fixture.com's mail server too"}` +
		`]}`)
	resp2, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(turn2))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if len(capturedBodies) != 2 {
		t.Fatalf("expected 2 captured upstream requests after turn 2, got %d", len(capturedBodies))
	}

	turn2Body := string(capturedBodies[1])
	matches := tokenRe.FindAllString(turn2Body, -1)
	if len(matches) == 0 {
		t.Fatalf("expected the real value in turn 2's conversation history to be re-tokenized, got: %s", turn2Body)
	}
	for _, m := range matches {
		if m != turn1Token {
			t.Fatalf("turn 2 used a DIFFERENT token (%q) for the same real value turn 1 tokenized as %q -- consistency broken across turns", m, turn1Token)
		}
	}
}

// TestProxy_RequestBodyBoundary_ExactlyAtLimitAccepted_OneByteOverRejected
// pins down the exact off-by-one behavior of MaxBodyBytes on the request
// side, which the existing TestProxy_RequestTooLarge_Rejected doesn't --
// it only checks a body far over the limit, not the boundary itself.
// Content-Type: text/plain isolates this from tokenize/JSON-parsing
// concerns entirely, since looksLikeJSON gates on the header, not body
// validity.
func TestProxy_RequestBodyBoundary_ExactlyAtLimitAccepted_OneByteOverRejected(t *testing.T) {
	const limit = 100

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine, MaxBodyBytes: limit})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	post := func(n int) int {
		resp, err := http.Post(ts.URL+"/v1/messages", "text/plain", strings.NewReader(strings.Repeat("a", n)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := post(limit); code != http.StatusOK {
		t.Errorf("body of exactly %d bytes (the limit): expected 200, got %d", limit, code)
	}
	if code := post(limit + 1); code != http.StatusRequestEntityTooLarge {
		t.Errorf("body of %d bytes (one over the limit): expected 413, got %d", limit+1, code)
	}
}

// TestProxy_ResponseBodyBoundary_ExactlyAtLimitAccepted_OneByteOverRejected
// is the same off-by-one check on the response side, which had no
// coverage at all before this.
func TestProxy_ResponseBodyBoundary_ExactlyAtLimitAccepted_OneByteOverRejected(t *testing.T) {
	const limit = 100
	var respSize int

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("b", respSize)))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine, MaxBodyBytes: limit})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	post := func() int {
		resp, err := http.Post(ts.URL+"/v1/messages", "text/plain", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	respSize = limit
	if code := post(); code != http.StatusOK {
		t.Errorf("response of exactly %d bytes (the limit): expected 200, got %d", limit, code)
	}
	respSize = limit + 1
	if code := post(); code != http.StatusBadGateway {
		t.Errorf("response of %d bytes (one over the limit): expected 502, got %d", limit+1, code)
	}
}

// TestProxy_InvalidUTF8InRequestBody_NoPanicNoCrash confirms a request
// body containing raw invalid UTF-8 bytes inside a JSON string value
// (not valid per the JSON spec, but not something this proxy can assume
// never arrives -- a buggy or adversarial client, or corrupted upstream
// content, could produce it) never panics the handler goroutine.
// Empirically: the invalid bytes get silently normalized to the Unicode
// replacement character (U+FFFD) somewhere in the gjson/sjson pipeline
// this proxy is built on, and detection around the invalid bytes (a real
// domain elsewhere in the same string) still works correctly.
func TestProxy_InvalidUTF8InRequestBody_NoPanicNoCrash(t *testing.T) {
	var capturedBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant",
			"content": []map[string]any{{"type": "text", "text": "ok"}},
		})
	}))
	defer upstream.Close()

	ts := newTestServer(t, upstream)

	invalid := []byte{0x80, 0xC0, 0xAF, 0xFF, 0xFE} // lone continuation byte, overlong/invalid sequences
	body := append([]byte(`{"messages":[{"role":"user","content":"target widgetcorp-fixture.com `), invalid...)
	body = append(body, []byte(`"}]}`)...)

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Fail-closed (blocked) or a successful pass-through are both
	// acceptable outcomes here -- the property under test is "doesn't
	// panic, doesn't crash." Only check the real domain never reached
	// upstream if the request WAS forwarded.
	if resp.StatusCode == http.StatusOK {
		if strings.Contains(string(capturedBody), "widgetcorp-fixture.com") {
			t.Fatalf("real domain reached upstream despite invalid UTF-8 elsewhere in the body: %s", capturedBody)
		}
	}
	t.Logf("status=%d, no panic", resp.StatusCode)
}

func TestProxy_RequestTooLarge_Rejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should never be reached for an oversized request")
	}))
	defer upstream.Close()

	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)

	srv := New(Config{Upstream: upstreamURL, Engine: engine, MaxBodyBytes: 128})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	bigBody := strings.Repeat("a", 1024)
	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(bigBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 413, got %d: %s", resp.StatusCode, body)
	}
}

// failingEngine-equivalent: use a store that will fail by closing it
// before use, forcing GetOrCreateToken (and thus Tokenize) to error, to
// verify the proxy fails closed and never reaches upstream.
func TestProxy_TokenizeFailure_FailsClosedNeverReachesUpstream(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer upstream.Close()

	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	store.Close() // closed before use; any GetOrCreateToken call now errors

	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	reqBody := `{"messages":[{"role":"user","content":"target widgetcorp-fixture.com"}]}`
	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 502 (fail closed), got %d: %s", resp.StatusCode, body)
	}
	if reached {
		t.Fatal("upstream must never be reached when tokenization fails")
	}
}

// TestProxy_TokenizeFailure_MidBody_NoPartialLeakOfAlreadyProcessedValues
// strengthens the fail-closed guarantee above: that test only covers a
// store that's broken from the very first value. This one confirms the
// SAME guarantee holds when the failure happens PARTWAY through a single
// request body -- a first real value that's a cheap in-memory cache hit
// (no store write needed) succeeds, then a second, genuinely new value
// requires an actual store write that fails. jsonwalk.Tokenize's own doc
// comment already claims "returns that error and no output" for exactly
// this case (see apply's `return nil, err`, discarding the
// partially-built body rather than returning it) -- this test verifies
// that claim holds through the real HTTP path, not just by reading the
// code: neither value may reach upstream, not even the one that was
// already successfully processed before the failure.
func TestProxy_TokenizeFailure_MidBody_NoPartialLeakOfAlreadyProcessedValues(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer upstream.Close()

	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	// Pre-warm the FIRST value into the in-memory cache with a real,
	// successful write -- so encountering it again in the actual request
	// is a cheap LookupToken hit, needing no store write at all.
	if _, err := store.GetOrCreateToken("widgetcorp-fixture.com", tokenstore.EntityDomain); err != nil {
		t.Fatal(err)
	}
	store.Close() // NOW break it -- any value that still needs a fresh write will fail

	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// First value is a cache hit (pre-warmed above); second is genuinely
	// new and requires a write that will now fail.
	reqBody := `{"messages":[{"role":"user","content":"widgetcorp-fixture.com and also othercorp-fixture.com"}]}`
	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 502 (fail closed), got %d: %s", resp.StatusCode, body)
	}
	if reached {
		t.Fatal("upstream must never be reached when ANY value in the body fails to tokenize, even if others already succeeded")
	}
}

// --- streaming (SSE) --------------------------------------------------

// TestProxy_Streaming_UpstreamConnectionDropsMidStream simulates a real
// network failure, not a clean end-of-stream: the upstream sends a
// partial, valid response (headers, a content_block_start, and some
// text) and then the raw TCP connection dies abruptly -- no
// content_block_stop, no message_stop, nothing. Confirms the proxy
// doesn't panic or hang; it should simply stop forwarding and let the
// client's connection end too, the same way any reverse proxy handles an
// upstream that vanishes mid-response.
func TestProxy_Streaming_UpstreamConnectionDropsMidStream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		fmt.Fprint(w, sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`))
		fmt.Fprint(w, sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial response before the connection dies"}}`))
		flusher.Flush()

		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("httptest ResponseWriter does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		conn.Close() // abrupt raw TCP close -- no clean SSE termination at all
	}))
	defer upstream.Close()

	ts := newTestServer(t, upstream)

	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
		if err != nil {
			// Also an acceptable outcome for a genuinely dropped upstream
			// connection -- the key property under test is "doesn't hang."
			return
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("request hung after the upstream connection dropped mid-stream")
	}
}

// TestProxy_Streaming_UnknownBlockIndexDoesNotPanic simulates a
// malformed/out-of-protocol upstream: a content_block_delta referencing
// an index that was never opened with content_block_start. Confirms the
// existing "unknown index -- forward raw, don't touch it" path (see
// handleBlockDelta's nil blockState check) doesn't panic on a nil map
// entry.
func TestProxy_Streaming_UnknownBlockIndexDoesNotPanic(t *testing.T) {
	frames := []string{
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":7,"delta":{"type":"text_delta","text":"never started"}}`),
		sseFrame("message_stop", `{"type":"message_stop"}`),
	}
	upstream := sseUpstream(t, frames)
	defer upstream.Close()

	ts := newTestServer(t, upstream)

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "never started") {
		t.Fatalf("expected the unrecognized-index delta to be forwarded unmodified, got: %s", body)
	}
}

func sseUpstream(t *testing.T, frames []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for _, f := range frames {
			fmt.Fprint(w, f)
			flusher.Flush()
		}
	}))
}

func readAllSSEDeltaText(t *testing.T, body io.Reader) (texts []string, inputJSONs []string) {
	t.Helper()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
		var evt map[string]any
		if err := json.Unmarshal([]byte(payload), &evt); err != nil {
			continue
		}
		if evt["type"] != "content_block_delta" {
			continue
		}
		delta, _ := evt["delta"].(map[string]any)
		switch delta["type"] {
		case "text_delta":
			texts = append(texts, delta["text"].(string))
		case "input_json_delta":
			inputJSONs = append(inputJSONs, delta["partial_json"].(string))
		}
	}
	return texts, inputJSONs
}

func TestTextFlushBoundary_HoldsBackTrailingWordNoBoundaryYet(t *testing.T) {
	got := textFlushBoundary([]byte("Primary root: `tok8a7a"))
	want := len("Primary root: `") // right after the backtick, the last boundary char
	if got != want {
		t.Fatalf("textFlushBoundary = %d, want %d (should hold back the in-progress backtick-wrapped run)", got, want)
	}
}

func TestTextFlushBoundary_FlushesEverythingAfterACompleteWord(t *testing.T) {
	got := textFlushBoundary([]byte("the quick brown "))
	if got != len("the quick brown ") {
		t.Fatalf("textFlushBoundary = %d, want %d (trailing space is itself a boundary, nothing held back)", got, len("the quick brown "))
	}
}

func TestTextFlushBoundary_NoBoundaryAtAllHoldsEntireBuffer(t *testing.T) {
	got := textFlushBoundary([]byte("tok8a7a4cc"))
	if got != 0 {
		t.Fatalf("textFlushBoundary = %d, want 0 (no boundary character anywhere yet)", got)
	}
}

func TestTextFlushBoundary_CapsHoldbackForLongUnbrokenRun(t *testing.T) {
	long := strings.Repeat("a", maxHeldTokenRunBytes+50) // no boundary chars at all
	got := textFlushBoundary([]byte(long))
	want := len(long) - maxHeldTokenRunBytes
	if got != want {
		t.Fatalf("textFlushBoundary = %d, want %d (should force-flush down to the cap rather than hold back indefinitely)", got, want)
	}
}

func TestTextFlushBoundary_LongUnbrokenRunCapNeverSplitsAMultiByteRune(t *testing.T) {
	// A long CJK/emoji passage with no ASCII punctuation anywhere hits
	// the same maxHeldTokenRunBytes safety valve as
	// TestTextFlushBoundary_CapsHoldbackForLongUnbrokenRun. The cut
	// there is raw byte-count arithmetic (len(buf)-maxHeldTokenRunBytes)
	// with no notion of where a multi-byte UTF-8 rune starts, so without
	// the rune-boundary walk-back in textFlushBoundary it can land
	// mid-character -- e.g. one byte into the 28th character of 70
	// repetitions of "东" (3 bytes each, 210 bytes total). Splitting a
	// rune there matters because emitTextDelta's json.Marshal call
	// doesn't error on an invalid UTF-8 tail, it silently replaces it
	// with U+FFFD, so the client would see a visibly garbled character
	// instead of a decode failure.
	for _, tc := range []struct {
		name string
		rune string
		n    int
	}{
		{"3-byte CJK", "东", 70},
		{"4-byte emoji", "🔥", 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := []byte(strings.Repeat(tc.rune, tc.n))
			got := textFlushBoundary(buf)
			if got == 0 {
				t.Fatalf("textFlushBoundary = 0, want the safety valve to still force SOME progress on a %d-byte unbroken run", len(buf))
			}
			if !utf8.Valid(buf[:got]) {
				t.Fatalf("textFlushBoundary = %d splits a multi-byte rune: flushed prefix %q is not valid UTF-8", got, buf[:got])
			}
			if !utf8.Valid(buf[got:]) {
				t.Fatalf("textFlushBoundary = %d splits a multi-byte rune: held-back remainder %q is not valid UTF-8", got, buf[got:])
			}
		})
	}
}

func TestTextFlushBoundary_DoesNotTreatTokenInternalPunctuationAsABoundary(t *testing.T) {
	// Hyphens and dots appear WITHIN real token shapes (tok-blocked-,
	// the domain token's own tok<hex>.<suffix> shape) -- this pins that
	// they're deliberately excluded from textBoundaryChars, not just
	// omitted by oversight.
	for _, c := range []byte("-.:+$_") {
		if bytes.IndexByte(textBoundaryChars, c) != -1 {
			t.Errorf("textBoundaryChars must not include %q -- it appears inside a real token shape", string(c))
		}
	}
}

func TestProxy_Streaming_DetokenizesTextAcrossSplitDeltas(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Mint via Engine.Tokenize, not store.GetOrCreateToken directly: the
	// wire span SafeFlushPoint protects is whatever Tokenize actually
	// substitutes (token + preserved real TLD suffix for a domain, e.g.
	// "tok...xyz.com"), registered as a side effect of THIS call. Minting
	// the bare store key alone would leave that span unregistered, which
	// doesn't reflect any real production path; nothing ever reaches
	// the wire without going through Tokenize first.
	engine := redact.New(store, redact.DefaultDetectors()...)
	tokenizedIn, err := engine.Tokenize("visiting widgetcorp-fixture.com now")
	if err != nil {
		t.Fatal(err)
	}
	composite := strings.TrimSuffix(strings.TrimPrefix(tokenizedIn, "visiting "), " now")
	token, ok := store.LookupToken("widgetcorp-fixture.com")
	if !ok {
		t.Fatal("expected domain token to already be minted by Tokenize above")
	}

	// Split the composite span itself across two text_delta events, to
	// prove the flush point catches a pattern that straddles a chunk
	// boundary rather than emitting it split and unmatched.
	half := len(composite) / 2
	part1 := "visiting " + composite[:half]
	part2 := composite[half:] + " now"

	frames := []string{
		sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`),
		sseFrame("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}`, part1)),
		sseFrame("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}`, part2)),
		sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
		sseFrame("message_stop", `{"type":"message_stop"}`),
	}
	upstream := sseUpstream(t, frames)
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	texts, _ := readAllSSEDeltaText(t, resp.Body)
	full := strings.Join(texts, "")
	if !strings.Contains(full, "widgetcorp-fixture.com") {
		t.Fatalf("expected the split token to be detokenized back to the real value once reassembled, got: %q (chunks: %v)", full, texts)
	}
	if strings.Contains(full, token) {
		t.Fatalf("token leaked through un-detokenized: %q", full)
	}
}

// TestProxy_Streaming_TokenSplitAcrossManySmallDeltas confirms a token
// surrounded by a long run of unrelated text, streamed in many small
// (3-byte) deltas, never gets split across flush events; every flush
// backs off to before any run that still looks like a growing token
// rather than cutting through it, regardless of how many tiny deltas
// its surrounding text arrives across.
func TestProxy_Streaming_TokenSplitAcrossManySmallDeltas(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Mint via Engine.Tokenize (not store.GetOrCreateToken directly) so
	// the actual wire span gets registered; see the identical comment
	// in TestProxy_Streaming_DetokenizesTextAcrossSplitDeltas above.
	engine := redact.New(store, redact.DefaultDetectors()...)
	if _, err := engine.Tokenize("widgetcorp-fixture.com"); err != nil {
		t.Fatal(err)
	}
	token, ok := store.LookupToken("widgetcorp-fixture.com")
	if !ok {
		t.Fatal("expected domain token to already be minted by Tokenize above")
	}

	// Realistic prose filler, not repeated single characters: "a" and "b"
	// are themselves valid hex digits, which (with no punctuation
	// boundary before the trailing filler) makes the token's own
	// detokenize regex unable to match regardless of how it's flushed --
	// an artifact of the filler choice, not a real streaming scenario.
	before := strings.Repeat("the quick brown fox jumps over lazy dogs while ", 7)
	after := " " + strings.Repeat("meanwhile the reporter kept typing notes quietly ", 13)

	chunk3 := func(s string, add func(string)) {
		for i := 0; i < len(s); i += 3 {
			end := min(i+3, len(s))
			add(s[i:end])
		}
	}

	var frames []string
	addDelta := func(text string) {
		frames = append(frames, sseFrame("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}`, text)))
	}
	frames = append(frames, sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`))
	chunk3(before, addDelta)
	chunk3(token, addDelta)
	chunk3(after, addDelta)
	frames = append(frames, sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`))
	frames = append(frames, sseFrame("message_stop", `{"type":"message_stop"}`))

	upstream := sseUpstream(t, frames)
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	texts, _ := readAllSSEDeltaText(t, resp.Body)
	full := strings.Join(texts, "")

	if strings.Contains(full, token) {
		t.Fatalf("raw token leaked through un-detokenized (split across small deltas): found %q in %q", token, full)
	}
	if !strings.Contains(full, "widgetcorp-fixture.com") {
		t.Fatalf("real domain never appears -- token was split and neither fragment matched detokenize: %q", full)
	}
}

// TestProxy_Streaming_BareUnregisteredTokenSplitAcrossTinyDeltas is a
// regression test for a real leak found live in production: a bare
// org-level domain token (no subdomain prefix) got streamed by the
// upstream model in per-subword fragments as small as 1-3 bytes each
// (confirmed from a real captured debug log), and leaked through
// completely un-detokenized.
//
// This is deliberately a DIFFERENT scenario from
// TestProxy_Streaming_TokenSplitAcrossManySmallDeltas above: that test
// uses a ".com" domain tokenized BARE, which means the bare span itself
// ("tok<hex>.com") gets registered by Tokenize and is already protected
// by engine.SafeFlushPoint on its own. The real leak involved a ".in"
// domain, which (see looksLikeBareFilename in internal/redact) is
// EXCLUDED from tokenization entirely when bare with no subdomain, so
// it can only ever get minted via a subdomain-prefixed occurrence (e.g.
// "www.widgetcorp-fixture.in"), which registers "www.tok<hex>.in" but
// never independently registers the bare "tok<hex>.in" anywhere. When
// the model later writes just the bare org token on its own (a very
// plausible thing to do when summarizing/grouping by root domain), no
// registered span protects it; only textFlushBoundary's generic
// shape-based protection does, which is exactly what this test proves.
func TestProxy_Streaming_BareUnregisteredTokenSplitAcrossTinyDeltas(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	engine := redact.New(store, redact.DefaultDetectors()...)
	// Establish the org token via a SUBDOMAIN occurrence only -- ".in"
	// is in filenameCollisionTLDs, so a bare mention would never
	// tokenize at all (see looksLikeBareFilename), matching exactly how
	// the real leak's token came to exist.
	if _, err := engine.Tokenize("seen: www.widgetcorp-fixture.in"); err != nil {
		t.Fatal(err)
	}
	bareKey, ok := store.LookupToken("widgetcorp-fixture.in")
	if !ok {
		t.Fatal("expected the registrable domain's token to already be minted via the subdomain occurrence above")
	}
	// LookupToken returns the bare stored key alone (e.g. "tok<16hex>")
	// -- the real TLD suffix is reconstructed dynamically at
	// detokenize-time (see detokenizeDomainTokens), not stored as part
	// of the key. The actual wire-visible bare span a model would write
	// is the key plus that echoed suffix.
	registrableToken := bareKey + ".in"

	// Stream the bare token, backtick-wrapped exactly like the real
	// capture ("Primary root: `tok...`"), in 1-3 byte fragments -- the
	// real per-subword granularity observed live, not an artificially
	// convenient chunking.
	before := "Primary root: `"
	after := "` -- 25 subdomains"

	chunkSmall := func(s string, add func(string)) {
		sizes := []int{1, 2, 3} // cycles through, mirroring the real capture's mix of 1-3 byte fragments
		i := 0
		n := 0
		for i < len(s) {
			sz := sizes[n%len(sizes)]
			end := min(i+sz, len(s))
			add(s[i:end])
			i = end
			n++
		}
	}

	var frames []string
	addDelta := func(text string) {
		frames = append(frames, sseFrame("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}`, text)))
	}
	frames = append(frames, sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`))
	addDelta(before)
	chunkSmall(registrableToken, addDelta)
	addDelta(after)
	frames = append(frames, sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`))
	frames = append(frames, sseFrame("message_stop", `{"type":"message_stop"}`))

	upstream := sseUpstream(t, frames)
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	texts, _ := readAllSSEDeltaText(t, resp.Body)
	full := strings.Join(texts, "")

	if strings.Contains(full, registrableToken) {
		t.Fatalf("LEAK: bare unregistered token survived tiny-delta streaming un-detokenized: %q", full)
	}
	if !strings.Contains(full, "widgetcorp-fixture.in") {
		t.Fatalf("real domain never appears -- token was split and neither fragment matched detokenize: %q", full)
	}
}

func TestProxy_Streaming_ToolUseInputBufferedAndDetokenized(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	token, err := store.GetOrCreateToken("widgetcorp-fixture.com", tokenstore.EntityDomain)
	if err != nil {
		t.Fatal(err)
	}

	inputJSON := fmt.Sprintf(`{"command":"curl %s"}`, token)
	// Split the partial_json fragment mid-way, matching how the real API
	// actually splits fragments: arbitrarily, including mid-token.
	splitAt := len(inputJSON) / 2

	frames := []string{
		sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}`),
		sseFrame("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%q}}`, inputJSON[:splitAt])),
		sseFrame("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%q}}`, inputJSON[splitAt:])),
		sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
	}
	upstream := sseUpstream(t, frames)
	defer upstream.Close()

	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	_, inputJSONs := readAllSSEDeltaText(t, resp.Body)
	full := strings.Join(inputJSONs, "")
	if !strings.Contains(full, "widgetcorp-fixture.com") {
		t.Fatalf("expected tool_use input to be detokenized once reassembled, got: %q", full)
	}
	if !json.Valid([]byte(full)) {
		t.Fatalf("reassembled tool_use input is not valid JSON: %q", full)
	}
}

// TestProxy_Streaming_MCPToolUseInputBufferedAndDetokenized is the
// streaming-path counterpart to the mcp_tool_use fix in jsonwalk (the
// buffered request/response path): Anthropic's server-side MCP
// connector feature streams mcp_tool_use blocks the same shape as
// ordinary tool_use, and they need the identical buffer-until-stop-
// then-detokenize treatment so a real MCP tool call actually receives
// the real value it needs to execute against, not a token. Local/stdio
// MCP servers (the common Claude Code case) are unaffected either way;
// those appear as plain tool_use blocks, already covered by the
// sibling test above.
func TestProxy_Streaming_MCPToolUseInputBufferedAndDetokenized(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	token, err := store.GetOrCreateToken("widgetcorp-fixture.com", tokenstore.EntityDomain)
	if err != nil {
		t.Fatal(err)
	}

	inputJSON := fmt.Sprintf(`{"query":"records for %s"}`, token)
	splitAt := len(inputJSON) / 2

	frames := []string{
		sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"mcp_tool_use","id":"mcptoolu_1","name":"query","server_name":"internal-db","input":{}}}`),
		sseFrame("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%q}}`, inputJSON[:splitAt])),
		sseFrame("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%q}}`, inputJSON[splitAt:])),
		sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
	}
	upstream := sseUpstream(t, frames)
	defer upstream.Close()

	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	_, inputJSONs := readAllSSEDeltaText(t, resp.Body)
	full := strings.Join(inputJSONs, "")
	if !strings.Contains(full, "widgetcorp-fixture.com") {
		t.Fatalf("expected mcp_tool_use input to be detokenized once reassembled, got: %q", full)
	}
	if !json.Valid([]byte(full)) {
		t.Fatalf("reassembled mcp_tool_use input is not valid JSON: %q", full)
	}
}

// TestTokenShapes_FitWithinMaxHeldTokenRunBytes checks the size
// maxHeldTokenRunBytes assumes against the generator that actually
// produces the tokens, rather than against a figure written into a
// comment and never rechecked.
//
// The bound is not load-bearing for a minted token, which is a
// registered wire span SafeFlushPoint holds back exactly whatever its
// length (handleBlockDelta takes the minimum of the two). It IS
// load-bearing for the generic bare-shape protection textFlushBoundary
// adds on top, so a future entity type whose token outgrows this window
// should be a deliberate decision, not a silent one.
func TestTokenShapes_FitWithinMaxHeldTokenRunBytes(t *testing.T) {
	store, err := tokenstore.Open(filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	isBoundary := func(r rune) bool { return strings.ContainsRune(string(textBoundaryChars), r) }
	for i, et := range tokenstore.AllEntityTypes() {
		token, err := store.GetOrCreateToken(fmt.Sprintf("real-%d-%s", i, et), et)
		if err != nil {
			t.Fatal(err)
		}
		// Per unbroken run, not per whole token: a run ends at any
		// textBoundaryChars byte, which is exactly where
		// textFlushBoundary is willing to flush. The PEM block is the
		// only shape long enough for the distinction to matter, and it
		// is full of spaces and newlines.
		for _, run := range strings.FieldsFunc(token, isBoundary) {
			if len(run) > maxHeldTokenRunBytes {
				t.Errorf("%s mints a %d-byte unbroken run (%q), past the %d-byte maxHeldTokenRunBytes flush window",
					et, len(run), run, maxHeldTokenRunBytes)
			}
		}
	}
}

// TestProxy_Streaming_OversizedToolUseInputIsCappedAndForwardedVerbatim
// covers the one genuinely unbounded buffer on the streaming path. A
// tool_use input has no safe partial-flush point, so it accumulates in
// full until content_block_stop -- and the concurrency slot that bounds
// aggregate memory elsewhere is released before streaming even starts,
// so nothing else caps it. Past MaxBodyBytes the block switches to
// pass-through: memory stays bounded, the client still reassembles the
// exact bytes the upstream sent (valid JSON, so the tool call is still
// well-formed), and the only cost is that this one oversized input
// keeps its tokens instead of having them restored -- the same
// fail-open direction Engine.Detokenize takes for an unresolvable token.
func TestProxy_Streaming_OversizedToolUseInputIsCappedAndForwardedVerbatim(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	token, err := store.GetOrCreateToken("widgetcorp-fixture.com", tokenstore.EntityDomain)
	if err != nil {
		t.Fatal(err)
	}

	const limit = 512
	// Comfortably past the cap, with the token at the very end so a
	// truncating (rather than pass-through) implementation would visibly
	// lose it rather than merely leave it untokenized.
	inputJSON := fmt.Sprintf(`{"pad":%q,"command":"curl %s"}`, strings.Repeat("x", 4*limit), token)

	var frames []string
	frames = append(frames, sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}`))
	for chunk := range slices.Chunk([]byte(inputJSON), 64) {
		frames = append(frames, sseFrame("content_block_delta",
			fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%q}}`, chunk)))
	}
	frames = append(frames, sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`))

	upstream := sseUpstream(t, frames)
	defer upstream.Close()

	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine, MaxBodyBytes: limit})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	_, inputJSONs := readAllSSEDeltaText(t, resp.Body)
	full := strings.Join(inputJSONs, "")
	if full != inputJSON {
		t.Fatalf("an over-cap tool_use input must reach the client byte-for-byte as the upstream sent it\n  got  (%d bytes): %.120q...\n  want (%d bytes): %.120q...", len(full), full, len(inputJSON), inputJSON)
	}
	if !json.Valid([]byte(full)) {
		t.Fatalf("reassembled tool_use input is not valid JSON: %.200q", full)
	}
}

// TestProxy_Streaming_ToolUseInputAtCapIsStillDetokenized is the other
// half of the cap: an input that fits must still get the normal
// buffer-until-stop-then-detokenize treatment, so the cap above can't
// silently degrade ordinary tool calls.
func TestProxy_Streaming_ToolUseInputAtCapIsStillDetokenized(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	token, err := store.GetOrCreateToken("widgetcorp-fixture.com", tokenstore.EntityDomain)
	if err != nil {
		t.Fatal(err)
	}

	inputJSON := fmt.Sprintf(`{"command":"curl %s"}`, token)
	frames := []string{
		sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}`),
		sseFrame("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%q}}`, inputJSON)),
		sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
	}
	upstream := sseUpstream(t, frames)
	defer upstream.Close()

	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)
	// A cap only just above this input's size: still buffered normally.
	srv := New(Config{Upstream: upstreamURL, Engine: engine, MaxBodyBytes: int64(len(inputJSON)) + 1})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	_, inputJSONs := readAllSSEDeltaText(t, resp.Body)
	full := strings.Join(inputJSONs, "")
	if !strings.Contains(full, "widgetcorp-fixture.com") {
		t.Fatalf("an input within the cap must still be detokenized, got: %q", full)
	}
}

func TestProxy_Streaming_ThinkingBlockNeverModified(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	token, err := store.GetOrCreateToken("widgetcorp-fixture.com", tokenstore.EntityDomain)
	if err != nil {
		t.Fatal(err)
	}

	// A thinking block containing a token-looking substring must pass
	// through completely untouched: never buffered, never rewritten,
	// since any edit would invalidate its signature on replay.
	thinkingText := "considering " + token
	frames := []string{
		sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`),
		sseFrame("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":%q}}`, thinkingText)),
		sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
	}
	upstream := sseUpstream(t, frames)
	defer upstream.Close()

	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), thinkingText) {
		t.Fatalf("thinking block content was modified; expected byte-identical passthrough of %q, got: %s", thinkingText, raw)
	}
}

// TestServer_StreamingReleasesSemaphoreBeforeStreamEnds confirms the
// concurrency semaphore only bounds body-buffering, not the full SSE
// streaming duration: with MaxConcurrent set well below the number of
// SIMULTANEOUSLY OPEN streams, every stream still succeeds, because each
// releases its slot as soon as streaming begins rather than holding it
// for the connection's lifetime.
func TestServer_StreamingReleasesSemaphoreBeforeStreamEnds(t *testing.T) {
	const maxConcurrent = 3
	const firstWave = maxConcurrent // fills the semaphore exactly
	const secondWave = 5            // must ALSO succeed if the fix works

	release := make(chan struct{})
	started := make(chan struct{}, firstWave+secondWave)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		fmt.Fprint(w, sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`))
		flusher.Flush()
		started <- struct{}{} // signal AFTER headers are flushed, so the client's Do() has definitely returned
		<-release             // stay open (streaming) until the test says everything has been observed
		fmt.Fprint(w, sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`))
		fmt.Fprint(w, sseFrame("message_stop", `{"type":"message_stop"}`))
		flusher.Flush()
	}))
	defer upstream.Close()

	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine, MaxConcurrent: maxConcurrent})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// postWithRetry retries a couple of times on 503: the semaphore
	// rejection is immediate and non-blocking (no queueing), so firing
	// exactly maxConcurrent requests at once can have one lose a
	// scheduling race for a slot another releases microseconds later.
	// That's real, correct behavior for the "no queueing" design, not
	// what this test is checking; it's checking whether an ALREADY-
	// STREAMING wave holds its slots, so a quick retry past the initial
	// acquire race is the right way to isolate that.
	postWithRetry := func() (*http.Response, error) {
		var resp *http.Response
		var err error
		for attempt := 0; attempt < 20; attempt++ {
			resp, err = http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
			if err != nil {
				return nil, err
			}
			if resp.StatusCode != http.StatusServiceUnavailable {
				return resp, nil
			}
			resp.Body.Close()
			time.Sleep(5 * time.Millisecond)
		}
		return resp, nil
	}

	fire := func(n int, statuses []int, wg *sync.WaitGroup) {
		for i := range n {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				resp, err := postWithRetry()
				if err != nil {
					t.Errorf("request %d: %v", i, err)
					return
				}
				defer resp.Body.Close()
				statuses[i] = resp.StatusCode
				io.Copy(io.Discard, resp.Body) // drain so the handler can finish after release fires
			}(i)
		}
	}

	var wg1 sync.WaitGroup
	wave1 := make([]int, firstWave)
	fire(firstWave, wave1, &wg1)

	// Wait for exactly maxConcurrent streams to genuinely be active
	// (headers flushed, client Do() returned) before proceeding.
	for range firstWave {
		<-started
	}

	// A second wave arriving NOW, while the first wave is still actively
	// streaming (blocked on <-release, nowhere near done), must still
	// succeed if streaming correctly released its slots already.
	var wg2 sync.WaitGroup
	wave2 := make([]int, secondWave)
	fire(secondWave, wave2, &wg2)
	for range secondWave {
		<-started
	}

	close(release)
	wg1.Wait()
	wg2.Wait()

	for i, code := range wave1 {
		if code != http.StatusOK {
			t.Errorf("wave1 stream %d: expected 200, got %d", i, code)
		}
	}
	for i, code := range wave2 {
		if code != http.StatusOK {
			t.Errorf("wave2 stream %d: expected 200, got %d -- a second wave of streams should not be blocked by an already-streaming first wave still holding MaxConcurrent=%d slots", i, code, maxConcurrent)
		}
	}
}

// TestServer_BufferedResponsesStillGatedBySemaphore confirms the other
// half of the same fix didn't overcorrect: non-streaming responses still
// hold the concurrency slot for their full buffering duration, since
// that phase genuinely buffers up to maxBodyBytes in memory and still
// needs the OOM guard.
func TestServer_BufferedResponsesStillGatedBySemaphore(t *testing.T) {
	const maxConcurrent = 2
	const numRequests = 8

	release := make(chan struct{})
	inFlight := make(chan struct{}, numRequests)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inFlight <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"msg_test","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}]}`)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := redact.New(store, redact.DefaultDetectors()...)
	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine, MaxConcurrent: maxConcurrent})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	statuses := make([]int, numRequests)
	var wg sync.WaitGroup
	for i := range numRequests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"messages":[]}`))
			if err != nil {
				t.Errorf("request %d: %v", i, err)
				return
			}
			defer resp.Body.Close()
			statuses[i] = resp.StatusCode
			io.Copy(io.Discard, resp.Body)
		}(i)
	}

	time.Sleep(200 * time.Millisecond) // let the semaphore-holders reach upstream and pile up
	close(release)
	wg.Wait()

	overloaded := 0
	for _, code := range statuses {
		if code == http.StatusServiceUnavailable {
			overloaded++
		}
	}
	if overloaded == 0 {
		t.Fatalf("expected at least some of %d concurrent buffered requests to be rejected with MaxConcurrent=%d, got none", numRequests, maxConcurrent)
	}
}

func sseFrame(event, data string) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "event: %s\ndata: %s\n\n", event, data)
	return b.String()
}

// --- debug logging ------------------------------------------------------

func newTestServerWithDebug(t *testing.T, upstream *httptest.Server, level debuglog.Level) (*httptest.Server, *bytes.Buffer, *redact.Engine) {
	t.Helper()
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	var buf bytes.Buffer
	dbg := debuglog.New(level, &buf)

	engine := redact.New(store, redact.DefaultDetectors()...)
	engine.SetDebugLogger(dbg)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	srv := New(Config{Upstream: upstreamURL, Engine: engine, DebugLogger: dbg})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, &buf, engine
}

func TestServer_DebugFull_LogsRealAndTokenizedBuffered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant",
			"content": []map[string]any{{"type": "text", "text": "echo: " + gjsonContent(body)}},
		})
	}))
	defer upstream.Close()

	ts, buf, _ := newTestServerWithDebug(t, upstream, debuglog.Full)

	reqBody := `{"messages":[{"role":"user","content":"check widgetcorp-fixture.com"}]}`
	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	out := buf.String()
	if !strings.Contains(out, `"event":"full_body"`) {
		t.Fatalf("expected full_body events, got: %s", out)
	}
	if !strings.Contains(out, "widgetcorp-fixture.com") {
		t.Fatalf("expected the real value logged somewhere (request or response leg), got: %s", out)
	}
	if !strings.Contains(out, `"direction":"request"`) || !strings.Contains(out, `"direction":"response"`) {
		t.Fatalf("expected both a request and a response full_body event, got: %s", out)
	}
}

// gjsonContent pulls the first message's content out of a request body
// for the fake upstream's echo handler above, without pulling in gjson
// just for a test helper.
func gjsonContent(body []byte) string {
	var req map[string]any
	json.Unmarshal(body, &req)
	msgs, _ := req["messages"].([]any)
	if len(msgs) == 0 {
		return ""
	}
	m, _ := msgs[0].(map[string]any)
	c, _ := m["content"].(string)
	return c
}

func TestServer_DebugOff_NoDebugLoggerConfigured_LogsNothing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant",
			"content": []map[string]any{{"type": "text", "text": "ok"}},
		})
	}))
	defer upstream.Close()

	// No debug logger in Config at all -- the zero value nil case, not
	// just level=Off with a logger present.
	ts := newTestServer(t, upstream)
	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"widgetcorp-fixture.com"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	// Reaching here without a panic on a nil *debuglog.Logger is the
	// actual assertion -- s.debug.FullBody(...) etc. must be nil-safe.
}

func TestServer_DebugNewValues_OnlyLogsFirstOccurrenceAcrossRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant",
			"content": []map[string]any{{"type": "text", "text": "ok"}},
		})
	}))
	defer upstream.Close()

	ts, buf, _ := newTestServerWithDebug(t, upstream, debuglog.NewValues)

	body := `{"messages":[{"role":"user","content":"widgetcorp-fixture.com"}]}`
	for range 3 {
		resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	out := buf.String()
	if n := strings.Count(out, `"event":"new_value"`); n != 1 {
		t.Fatalf("expected exactly 1 new_value event across 3 requests mentioning the same value, got %d: %s", n, out)
	}
	// At the NewValues tier specifically (not Replacements), replacement
	// events must NOT appear -- that's the next tier up. Cumulative
	// verbosity is checked separately in TestLogger_CumulativeVerbosity
	// and the Full-tier tests above, which DO expect replacement/full_body
	// events to appear alongside new_value ones.
	if n := strings.Count(out, `"event":"replacement"`); n != 0 {
		t.Fatalf("expected 0 replacement events at the NewValues tier, got %d: %s", n, out)
	}
}

// TestServer_DebugNewValues_LogsEveryDistinctValueNotJustTheFirstEver
// covers a different case than the "repeat" test above: distinct real
// values discovered ACROSS the life of the run, not the same one seen
// again. A version of this tier that only fired once ever (rather than
// once per distinct value) would be useless; this pins that down.
func TestServer_DebugNewValues_LogsEveryDistinctValueNotJustTheFirstEver(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant",
			"content": []map[string]any{{"type": "text", "text": "ok"}},
		})
	}))
	defer upstream.Close()

	ts, buf, _ := newTestServerWithDebug(t, upstream, debuglog.NewValues)

	values := []string{"xyz-example-corp-fixture.com", "widgetcorp-fixture.com", "globex-fixture.com"}
	for _, v := range values {
		body := `{"messages":[{"role":"user","content":"target ` + v + `"}]}`
		resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	out := buf.String()
	if n := strings.Count(out, `"event":"new_value"`); n != len(values) {
		t.Fatalf("expected %d new_value events (one per distinct value), got %d: %s", len(values), n, out)
	}
	for _, v := range values {
		if !strings.Contains(out, `"real":"`+v+`"`) {
			t.Errorf("missing new_value entry for %q: %s", v, out)
		}
	}
	if n := strings.Count(out, `"token":"tok`); n != len(values) {
		t.Errorf("expected each new_value entry to also carry a token, got %d token fields: %s", n, out)
	}
}

func TestServer_DebugFull_StreamingLogsUpstreamAndClientFrames(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	token, err := store.GetOrCreateToken("widgetcorp-fixture.com", tokenstore.EntityDomain)
	if err != nil {
		t.Fatal(err)
	}

	frames := []string{
		sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`),
		sseFrame("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}`, "visiting "+token)),
		sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`),
		sseFrame("message_stop", `{"type":"message_stop"}`),
	}
	upstream := sseUpstream(t, frames)
	defer upstream.Close()

	var buf bytes.Buffer
	dbg := debuglog.New(debuglog.Full, &buf)
	engine := redact.New(store, redact.DefaultDetectors()...)
	engine.SetDebugLogger(dbg)
	upstreamURL, _ := url.Parse(upstream.URL)
	srv := New(Config{Upstream: upstreamURL, Engine: engine, DebugLogger: dbg})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	out := buf.String()
	if !strings.Contains(out, `"side":"upstream"`) {
		t.Fatalf("expected upstream-side SSE frame logging, got: %s", out)
	}
	if !strings.Contains(out, `"side":"client"`) {
		t.Fatalf("expected client-side (reconstructed) SSE frame logging, got: %s", out)
	}
	if !strings.Contains(out, "widgetcorp-fixture.com") {
		t.Fatalf("expected the real domain to appear in the client-side logged frame, got: %s", out)
	}
	if !strings.Contains(out, token) {
		t.Fatalf("expected the token to appear in the upstream-side logged frame, got: %s", out)
	}
}

// TestSSEFrame_MultiLineDataSurvivesPassThrough pins the round trip for
// an SSE frame whose data field spans several lines. The SSE wire format
// carries that as one "data:" line per line, and readSSEFrame joins them
// with "\n"; writeSSEFrame has to split them back apart. Writing the
// joined value as a single "data: a\nb" line instead looks right in the
// raw bytes but is not: the "b" line has no field name, so a conforming
// parser discards it, and the frame this proxy promised to forward
// unmodified arrives truncated to its first line.
func TestSSEFrame_MultiLineDataSurvivesPassThrough(t *testing.T) {
	const wantEvent, wantData = "ping", "line one\nline two\nline three"

	var wire bytes.Buffer
	writeSSEFrame(&wire, wantEvent, wantData)

	gotEvent, gotData, ok, err := readSSEFrame(bufio.NewReader(&wire))
	if err != nil || !ok {
		t.Fatalf("re-reading the emitted frame: ok=%v err=%v", ok, err)
	}
	if gotEvent != wantEvent {
		t.Errorf("event: got %q, want %q", gotEvent, wantEvent)
	}
	if gotData != wantData {
		t.Errorf("data: got %q, want %q", gotData, wantData)
	}
}
