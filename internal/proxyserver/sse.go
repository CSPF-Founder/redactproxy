package proxyserver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/CSPF-Founder/redactproxy/internal/jsonwalk"
)

// bufferedBlockTypes are the content_block types this proxy knows how to
// safely buffer and rewrite. Everything else (thinking,
// redacted_thinking, server-executed tool results, and any future block
// type this proxy doesn't yet recognize) is passed through completely
// unmodified. This is deliberately an allowlist, not a blocklist: an
// unrecognized block type defaults to "never touch it" rather than
// "assume it's safe to buffer," which is the safer failure direction for
// a type this code doesn't understand.
//
// mcp_tool_use is included alongside tool_use, not skipped: it's the
// block type Anthropic's server-side MCP connector feature uses (a
// request with a top-level mcp_servers parameter, distinct from the
// ordinary local/stdio MCP servers most Claude Code sessions use, which
// appear as completely normal tool_use/tool_result blocks and were
// already handled). Its input can reference a token the same way any
// other tool_use input can, and needs the identical
// buffer-until-content_block_stop-then-detokenize treatment (see
// handleBlockStop's matching case), so an MCP tool call actually
// receives the real value it needs to execute against, not a
// token-shaped string that would just fail.
var bufferedBlockTypes = map[string]bool{
	"text":         true,
	"tool_use":     true,
	"mcp_tool_use": true,
}

// sseDebugTrace mirrors every SSE frame, in and out, to stderr. Read
// once at startup rather than per frame: writeSSEFrame runs on every
// frame of every streamed response, and os.Getenv is a linear scan of
// the process environment, not a free lookup.
var sseDebugTrace = os.Getenv("REDACTPROXY_DEBUG_SSE") != ""

// blockState tracks in-flight buffering for one content_block index
// across the SSE stream.
type blockState struct {
	blockType string
	textBuf   []byte          // text_delta: held back until SafeFlushPoint AND textFlushBoundary both clear it
	jsonBuf   strings.Builder // input_json_delta: full buffer until content_block_stop
	// jsonOverflowed records that jsonBuf hit the size cap and everything
	// for this block, buffered and subsequent, has already been forwarded
	// verbatim; see handleBlockDelta's input_json_delta case.
	jsonOverflowed bool
}

// textBoundaryChars are characters that never appear WITHIN any token
// shape this proxy mints (see internal/tokenstore/generator.go's
// Token*Prefix constants and their generators), deliberately a small,
// curated allowlist of unambiguous natural-language separators, NOT
// "everything except letters and digits". Several of this tool's own
// token shapes use punctuation internally: hyphens ("tok-blocked-",
// "user-"), dots (a domain token's own "tok<hex>.<suffix>" shape,
// echoing the real TLD), colons (the IPv6 network token), a bare "+"
// (the international phone token), so treating any of those as a safe
// split point would just relocate the same splitting bug to a
// different byte offset inside the token instead of closing it.
var textBoundaryChars = []byte(" \t\n\r`\"',;()[]{}|")

// maxHeldTokenRunBytes bounds how long a trailing run since the last
// boundary character is held back before a flush is forced anyway,
// regardless of whether a natural boundary has arrived yet: 128 bytes,
// above the longest unbroken token this proxy currently mints (108
// bytes: the Vault token, tokenstore.TokenVaultPrefix + randomHex(50),
// i.e. "hvs.FAKE" plus 100 hex characters). The one longer shape, the
// 120-byte PEM block, contains spaces and newlines, so it is never one
// unbroken run in this sense. This is a safety valve, not the normal
// path: it exists so a long unbroken run of ordinary non-token text (a
// URL, a base64 blob) can't stall indefinitely waiting for a boundary
// that might not arrive for a while.
//
// The margin above 108 is comfort, not the correctness guarantee.
// handleBlockDelta takes the MINIMUM of this and the engine's own
// SafeFlushPoint, so this can only ever make a flush more conservative,
// never less: an actually-minted token is a registered wire span, and
// SafeFlushPoint holds it back exactly, whatever its length. See
// TestTokenShapes_FitWithinMaxHeldTokenRunBytes.
const maxHeldTokenRunBytes = 128

// textFlushBoundary returns how far into buf is safe to flush based on
// natural-language structure alone: the position right after the last
// textBoundaryChars byte, or 0 if none has arrived yet (nothing safe to
// flush on this basis, hold the whole buffer). This is independent of,
// and combined with (via the caller taking the minimum of both), the
// engine's own SafeFlushPoint; see handleBlockDelta's text_delta case
// for why both are needed: SafeFlushPoint only protects spans already
// registered for a specific prior occurrence, this protects the generic
// shape of any of this tool's token prefixes even before one has ever
// been seen whole.
func textFlushBoundary(buf []byte) int {
	safe := bytes.LastIndexAny(buf, string(textBoundaryChars)) + 1 // -1+1=0 if none found
	if held := len(buf) - safe; held > maxHeldTokenRunBytes {
		safe = len(buf) - maxHeldTokenRunBytes
		// The natural-boundary case above always lands right after an
		// ASCII textBoundaryChars byte, which is inherently a valid rune
		// boundary. This arithmetic cut isn't: buf[safe] can land inside
		// a multi-byte UTF-8 character, which a long CJK/Arabic/emoji run
		// with no ASCII punctuation for 128+ bytes does produce. Emitting
		// a string cut mid-rune doesn't error -- encoding/json.Marshal
		// silently replaces the broken tail with U+FFFD -- so the client
		// would see a visibly garbled character instead of a decode
		// failure. Walk back to the start
		// of whatever rune buf[safe] is a continuation byte of; a
		// continuation run is at most 3 bytes (the longest UTF-8
		// encoding is 4 bytes total), so this holds back a few more
		// bytes at most and never crosses back before the natural
		// boundary computed above (that position is itself always a
		// valid rune start, being either 0 or immediately after a
		// complete 1-byte ASCII character).
		for safe > 0 && !utf8.RuneStart(buf[safe]) {
			safe--
		}
	}
	return safe
}

// proxySSE streams an upstream SSE response to w, detokenizing text and
// tool_use content as it goes. Buffered block types (see
// bufferedBlockTypes) are held back per handleBlockDelta's per-type
// logic; everything else passes through frame-for-frame, unmodified, as
// it arrives.
func (s *Server) proxySSE(w http.ResponseWriter, resp *http.Response, path string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Should never happen on the stdlib HTTP server this proxy runs
		// on, but fail loudly rather than silently buffer-then-dump if
		// it ever does.
		s.logger.Error("response writer does not support flushing; cannot stream SSE")
		writeAPIError(w, http.StatusInternalServerError, "api_error", "proxy cannot stream this response")
		return
	}

	copyHeader(w.Header(), resp.Header)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(resp.StatusCode)
	flusher.Flush()

	reader := bufio.NewReader(resp.Body)
	blocks := make(map[int]*blockState)

	for {
		event, data, ok, err := readSSEFrame(reader)
		if err != nil {
			s.logger.Error("sse read error", "err", err)
			return
		}
		if !ok {
			return // clean EOF
		}
		if sseDebugTrace {
			fmt.Fprintf(os.Stderr, "DEBUG-IN event=%q data=%q\n", event, data)
		}
		s.debug.FullSSEFrame(path, "upstream", event, data)
		if data == "" {
			writeSSEFrame(w, event, data)
			flusher.Flush()
			continue
		}

		var evt map[string]any
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			// Not a shape we understand; forward raw rather than drop,
			// so an unexpected event never silently vanishes.
			writeSSEFrame(w, event, data)
			flusher.Flush()
			continue
		}

		typ, _ := evt["type"].(string)
		switch typ {
		case "content_block_start":
			s.handleBlockStart(w, flusher, event, data, evt, blocks)
		case "content_block_delta":
			s.handleBlockDelta(w, flusher, event, data, evt, blocks, path)
		case "content_block_stop":
			s.handleBlockStop(w, flusher, event, data, evt, blocks, path)
		default:
			// message_start, message_delta, message_stop, ping, and
			// anything else: none carry redactable content.
			writeSSEFrame(w, event, data)
			flusher.Flush()
		}
	}
}

func (s *Server) handleBlockStart(w http.ResponseWriter, flusher http.Flusher, event, data string, evt map[string]any, blocks map[int]*blockState) {
	idx := indexOf(evt)
	cb, _ := evt["content_block"].(map[string]any)
	cbType, _ := cb["type"].(string)
	blocks[idx] = &blockState{blockType: cbType}

	// The initial content_block is always empty ("text":"" / "input":{})
	// per the API's own streaming contract: nothing to redact yet, and
	// id/name/type fields on it are protocol metadata, never touched.
	writeSSEFrame(w, event, data)
	flusher.Flush()
}

func (s *Server) handleBlockDelta(w http.ResponseWriter, flusher http.Flusher, event, data string, evt map[string]any, blocks map[int]*blockState, path string) {
	idx := indexOf(evt)
	st := blocks[idx]
	if st == nil || !bufferedBlockTypes[st.blockType] {
		// Unknown index, or a block type we deliberately never buffer
		// (thinking/redacted_thinking and anything else outside v1
		// scope); forward immediately, unmodified.
		writeSSEFrame(w, event, data)
		flusher.Flush()
		return
	}

	delta, _ := evt["delta"].(map[string]any)
	deltaType, _ := delta["type"].(string)

	switch deltaType {
	case "text_delta":
		text, _ := delta["text"].(string)
		st.textBuf = append(st.textBuf, text...)
		// Checked on every delta, however small: engine.SafeFlushPoint is
		// an exact match against the specific credentials this engine
		// actually minted (see tokenstore.spanTrie), not a byte-count
		// guess, so as long as a genuine partial match is in progress it
		// keeps returning the SAME starting index on every call (the
		// whole partial span stays one contiguous held-back block no
		// matter how many tiny deltas it arrives across), and flushes
		// everything immediately the instant nothing risky is pending,
		// which is most of a typical response.
		flushLen := s.engine.SafeFlushPoint(st.textBuf)
		// SafeFlushPoint alone only protects spans already minted for a
		// SPECIFIC prior occurrence (e.g. "www.tok<hex>.in", registered
		// the moment that exact subdomain form was tokenized). It has
		// no notion of the GENERIC bare shape ("tok<hex>", with no
		// subdomain) at all, since that shape was never registered
		// anywhere. A real leak found live: an upstream model streaming
		// a bare org-level token in tiny per-subword fragments (as
		// little as 1-3 bytes each) got each fragment flushed and
		// checked individually before the next arrived, so the complete
		// 16-hex-character token never existed in one buffer at
		// check-time and was never caught. See
		// TestHandleBlockDelta_BareTokenSplitAcrossManyTinyDeltas_StillDetokenized
		// for the exact reproduction.
		//
		// textFlushBoundary closes this independent of SafeFlushPoint,
		// on general principle rather than by registering every
		// possible bare form: hold back whatever's arrived since the
		// last unambiguous natural-language separator, so a complete
		// token, any of this tool's token shapes, not just domains,
		// always accumulates in one buffer before it's ever checked,
		// regardless of how finely upstream chunks its own output.
		if boundary := textFlushBoundary(st.textBuf); boundary < flushLen {
			flushLen = boundary
		}
		if flushLen > 0 {
			toFlush := string(st.textBuf[:flushLen])
			// Shift the unflushed tail down in place rather than
			// allocating a fresh backing array on every delta: the
			// held-back remainder is bounded by maxHeldTokenRunBytes,
			// so the buffer never grows without limit anyway.
			st.textBuf = append(st.textBuf[:0], st.textBuf[flushLen:]...)
			s.emitTextDelta(w, flusher, idx, s.engine.Detokenize(toFlush), path)
		}

	case "input_json_delta":
		if st.jsonOverflowed {
			// Past the cap: this block is in pass-through mode for the
			// rest of its life, so the client still reassembles complete,
			// valid JSON out of the same bytes the upstream sent.
			writeSSEFrame(w, event, data)
			flusher.Flush()
			return
		}
		pj, _ := delta["partial_json"].(string)
		st.jsonBuf.WriteString(pj)
		// Fully buffered until content_block_stop: partial_json fragments
		// can split mid-key/mid-value, so there is no safe partial-flush
		// point for JSON the way there is for plain text.
		//
		// Which makes this the one genuinely unbounded buffer on the
		// streaming path, and the reason it needs a cap: unlike textBuf
		// (bounded by SafeFlushPoint/maxHeldTokenRunBytes, so it drains
		// continuously), a tool_use input accumulates in full, and the
		// concurrency slot that bounds aggregate memory elsewhere was
		// already released before streaming began (see ServeHTTP). Held
		// to the same MaxBodyBytes ceiling as a buffered request or
		// response body, since it's the same question -- how much of one
		// message is this proxy willing to hold in memory -- and the same
		// operator-facing knob should answer it.
		//
		// Fails OPEN rather than killing the stream, matching
		// redact.Engine.Detokenize's own policy on this direction: emit
		// what's buffered verbatim (still-tokenized) and forward the rest
		// as it arrives. The cost is an oversized tool input whose tokens
		// don't get restored, which is visibly wrong to the operator; the
		// alternative, dropping a response mid-tool-call, is worse, and
		// neither risks real PII reaching the model, which already
		// happened (or didn't) on the request leg.
		if int64(st.jsonBuf.Len()) > s.maxBodyBytes {
			s.logger.Error("tool_use input exceeded the proxy's size limit mid-stream; forwarding it without detokenizing",
				"max", s.maxBodyBytes, "index", idx, "path", path)
			st.jsonOverflowed = true
			s.emitInputJSONDelta(w, flusher, idx, st.jsonBuf.String(), path)
			st.jsonBuf.Reset()
		}

	default:
		writeSSEFrame(w, event, data)
		flusher.Flush()
	}
}

func (s *Server) handleBlockStop(w http.ResponseWriter, flusher http.Flusher, event, data string, evt map[string]any, blocks map[int]*blockState, path string) {
	idx := indexOf(evt)
	if st := blocks[idx]; st != nil {
		switch st.blockType {
		case "text":
			if len(st.textBuf) > 0 {
				s.emitTextDelta(w, flusher, idx, s.engine.Detokenize(string(st.textBuf)), path)
			}
		case "tool_use", "mcp_tool_use":
			// Empty for an overflowed block (see handleBlockDelta's
			// input_json_delta case: the buffer was emitted verbatim and
			// reset, and every delta since went straight through), so
			// nothing extra is emitted here and the client's reassembled
			// JSON stays exactly what the upstream sent.
			if raw := st.jsonBuf.String(); raw != "" {
				detok := jsonwalk.DetokenizeValue([]byte(raw), s.engine.Detokenize)
				s.emitInputJSONDelta(w, flusher, idx, string(detok), path)
			}
		}
		delete(blocks, idx)
	}
	writeSSEFrame(w, event, data)
	flusher.Flush()
}

func (s *Server) emitTextDelta(w io.Writer, flusher http.Flusher, index int, text string, path string) {
	payload, err := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
	if err != nil {
		s.logger.Error("marshal reconstructed text_delta", "err", err)
		return
	}
	s.debug.FullSSEFrame(path, "client", "content_block_delta", string(payload))
	writeSSEFrame(w, "content_block_delta", string(payload))
	flusher.Flush()
}

func (s *Server) emitInputJSONDelta(w io.Writer, flusher http.Flusher, index int, partialJSON string, path string) {
	payload, err := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{"type": "input_json_delta", "partial_json": partialJSON},
	})
	if err != nil {
		s.logger.Error("marshal reconstructed input_json_delta", "err", err)
		return
	}
	s.debug.FullSSEFrame(path, "client", "content_block_delta", string(payload))
	writeSSEFrame(w, "content_block_delta", string(payload))
	flusher.Flush()
}

func indexOf(evt map[string]any) int {
	if f, ok := evt["index"].(float64); ok {
		return int(f)
	}
	return -1
}

// readSSEFrame reads one SSE frame (a run of "event:"/"data:" lines
// terminated by a blank line) from r. ok is false only on a clean EOF
// with no partial frame pending.
func readSSEFrame(r *bufio.Reader) (event, data string, ok bool, err error) {
	var dataLines []string
	sawAnyField := false

	for {
		line, rerr := r.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "event:"):
				event = strings.TrimPrefix(strings.TrimPrefix(line, "event:"), " ")
				sawAnyField = true
			case strings.HasPrefix(line, "data:"):
				dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
				sawAnyField = true
			case line == "":
				if sawAnyField {
					return event, strings.Join(dataLines, "\n"), true, nil
				}
				// blank line with nothing accumulated yet (e.g. a
				// keep-alive newline); keep reading for the next frame
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				if sawAnyField {
					return event, strings.Join(dataLines, "\n"), true, nil
				}
				return "", "", false, nil
			}
			return "", "", false, rerr
		}
	}
}

// writeSSEFrame emits one SSE frame. data is re-split on "\n" and each
// line gets its own "data:" field, the inverse of readSSEFrame's join:
// the SSE wire format has no way to carry a newline WITHIN one data
// field, so writing a multi-line value as a single "data: a\nb" line
// makes everything after the first line parse as a separate (and, since
// it has no field name, silently ignored) field. Anthropic's own frames
// are single-line JSON, so this only matters on the pass-through path
// for an unrecognized frame, which is exactly where "forward it
// unmodified rather than drop it" is the whole point.
//
// Write errors are discarded rather than returned. w is the client's
// http.ResponseWriter, so the only realistic failure is the client having
// gone away mid-stream, which no single frame can do anything about: the
// remedy is to stop pumping the stream, and that is already driven by the
// request context and the upstream read loop, not by one frame's return
// value. Threading an error out of here would put a failure check at all
// ten call sites inside the streaming state machine while changing
// nothing about when the stream actually ends.
func writeSSEFrame(w io.Writer, event, data string) {
	if sseDebugTrace {
		_, _ = fmt.Fprintf(os.Stderr, "DEBUG-OUT event=%q data=%q\n", event, data)
	}
	if event != "" {
		_, _ = fmt.Fprintf(w, "event: %s\n", event)
	}
	for line := range strings.SplitSeq(data, "\n") {
		_, _ = fmt.Fprintf(w, "data: %s\n", line)
	}
	_, _ = fmt.Fprint(w, "\n")
}
