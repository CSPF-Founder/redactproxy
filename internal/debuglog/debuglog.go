// Package debuglog provides opt-in, leveled diagnostic logging for
// redactproxy, entirely separate from the normal operational log
// (startup, rules reload, errors) that always goes to stderr.
//
// It deliberately includes REAL (pre-tokenize/post-detokenize) values.
// A log that only ever showed tokens would be useless for the one thing
// it exists for: manually verifying that real client PII is actually
// being caught and replaced correctly.
//
// That means real client data sitting on disk, so three rules apply. It
// is opt-in only (off by default, enabled via -debug-level). The file it
// writes to must live outside any directory a Claude Code session
// running through the proxy would have reason to read (see
// cmd/redactproxy's placement, and its warning if -data-dir points
// inside the working directory). And it should be deleted once it has
// served its debugging purpose.
package debuglog

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Level is a verbosity tier. Higher levels include everything lower
// levels log, plus more, the conventional cumulative verbosity
// contract, so turning it up never loses a signal a lower level showed.
type Level int

const (
	// Off disables debug logging entirely (the default).
	Off Level = iota
	// NewValues logs only the first time a real value is seen, i.e.
	// when a token is actually minted, not when an already-known value
	// is looked up again. The lowest non-off tier: "what new PII is
	// showing up in this engagement, and what did it become."
	NewValues
	// Replacements additionally logs every substitution (tokenize or
	// detokenize), not just first-time discoveries: "what's actually
	// being redacted, request by request."
	Replacements
	// Full additionally logs the entire body of every request and
	// response, both the real and the tokenized form side by side,
	// the most direct way to manually confirm redaction is correct.
	Full
)

// ParseLevel parses a level name (case-insensitive): "off", "new",
// "replacements", or "full".
func ParseLevel(s string) (Level, error) {
	switch s {
	case "", "off":
		return Off, nil
	case "new":
		return NewValues, nil
	case "replacements":
		return Replacements, nil
	case "full":
		return Full, nil
	default:
		return Off, fmt.Errorf("unknown debug level %q (want off, new, replacements, or full)", s)
	}
}

// Logger writes leveled debug events as line-delimited JSON to an
// underlying writer. Safe for concurrent use.
type Logger struct {
	level Level
	w     io.Writer
	mu    sync.Mutex
	// enc is built once and reused under mu, not constructed per event:
	// at "full" level this writes once per SSE frame, and there can be
	// hundreds of those in a single streamed response.
	enc *json.Encoder
}

// New builds a Logger. w is typically a file dedicated to this purpose;
// see cmd/redactproxy for where that file lives and the access-control
// reasoning behind its placement, since real values will be written
// here.
func New(level Level, w io.Writer) *Logger {
	l := &Logger{level: level, w: w}
	if w != nil {
		l.enc = json.NewEncoder(w)
	}
	return l
}

// Enabled reports whether lvl would actually produce output; lets a
// caller skip building an event (e.g. serializing a full body) when
// nothing would use it.
func (l *Logger) Enabled(lvl Level) bool {
	return l != nil && l.level >= lvl
}

// rotator is implemented by writers that support an explicit,
// boundary-aligned rotation check, currently only RotatingWriter. Kept
// as a small unexported interface rather than a dependency on that
// concrete type, so BeginRoundTrip works with any io.Writer, including
// a plain bytes.Buffer in tests, where the type assertion below just
// fails and this becomes a no-op.
type rotator interface {
	MaybeRotate()
}

// BeginRoundTrip marks the start of one request/response round trip;
// call it before logging any event for that round trip (see
// proxyserver.Server.ServeHTTP). If the underlying writer supports
// boundary-aligned rotation, this is where that check happens: doing it
// here, before the first event of a new round trip rather than
// reactively after whichever write happens to cross the size
// threshold, keeps a full round trip (the request's full_body entry,
// every replacement/new_value event, and every full_sse_frame of a
// streamed response) from landing split across two rotated files in
// the common case where the round trip as a whole is smaller than the
// rotation threshold. A single round trip LARGER than the threshold on
// its own can still get cut mid-stream by the writer's own reactive
// check; there's no way to know a round trip's total size in advance
// without buffering it, which is exactly what streaming exists to
// avoid.
func (l *Logger) BeginRoundTrip() {
	if l == nil || l.w == nil {
		return
	}
	if r, ok := l.w.(rotator); ok {
		r.MaybeRotate()
	}
}

func (l *Logger) write(event map[string]any) {
	if l == nil || l.enc == nil {
		return
	}
	event["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(event) // best-effort: a debug sink failing must never affect request handling
}

// NewValue logs that a real value of entityType was seen for the first
// time and minted as token, the bare stored key, i.e. the token
// store's canonical identity for this value (stable for the life of the
// engagement, independent of any particular occurrence). wireValue is
// the actual substituted text this specific occurrence produced on the
// wire (e.g. a domain token plus its preserved real suffix), what
// you'd actually grep for in a Full-tier body dump to find this mint
// event's own substitution. For a detection combining multiple lookups
// (e.g. an email's local part and domain), wireValue is the whole
// combined substitution, not isolated to just this one lookup.
func (l *Logger) NewValue(entityType, real, token, wireValue string) {
	if !l.Enabled(NewValues) {
		return
	}
	l.write(map[string]any{
		"event": "new_value", "entity_type": entityType, "real": real, "token": token, "wire_value": wireValue,
	})
}

// Replacement logs one substitution. direction is "tokenize" (real seen,
// token substituted, outbound) or "detokenize" (token seen, real
// substituted back, inbound).
func (l *Logger) Replacement(direction, entityType, real, token string) {
	if !l.Enabled(Replacements) {
		return
	}
	l.write(map[string]any{
		"event": "replacement", "direction": direction, "entity_type": entityType, "real": real, "token": token,
	})
}

// FullBody logs one leg of a request/response with BOTH its real and
// tokenized forms side by side; direction is "request" or "response",
// path is the HTTP path.
func (l *Logger) FullBody(direction, path string, real, tokenized []byte) {
	if !l.Enabled(Full) {
		return
	}
	l.write(map[string]any{
		"event": "full_body", "direction": direction, "path": path,
		"real": string(real), "tokenized": string(tokenized),
	})
}

// FullSSEFrame logs one SSE frame of a streaming response. side is
// "upstream" (the tokenized wire frame as received from Anthropic,
// logged as-is before any detokenization) or "client" (what was actually
// emitted to Claude Code, real values substituted back in). These are
// logged independently rather than paired 1:1, since the flush logic
// that decides frame boundaries (see proxyserver/sse.go's
// SafeFlushPoint-driven buffering) can reshape client-emitted frames
// relative to the upstream frames they were built from. Reading the
// two directions as separate chronological streams is still fully
// sufficient to manually compare what came in against what went out.
func (l *Logger) FullSSEFrame(path, side, eventType, data string) {
	if !l.Enabled(Full) {
		return
	}
	l.write(map[string]any{
		"event": "full_sse_frame", "path": path, "side": side, "sse_event": eventType, "data": data,
	})
}
