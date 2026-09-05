// Package proxyserver implements the HTTP proxy that sits between Claude
// Code (pointed here via ANTHROPIC_BASE_URL) and the real Anthropic API.
// It tokenizes real values out of every outbound request body and
// detokenizes them back into every inbound response body, so real PII
// never reaches Anthropic's servers while Claude Code's own tool
// execution, permission dialogs, and UI stay completely native. This
// proxy only ever works at the network layer.
package proxyserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CSPF-Founder/redactproxy/internal/debuglog"
	"github.com/CSPF-Founder/redactproxy/internal/jsonwalk"
	"github.com/CSPF-Founder/redactproxy/internal/redact"
)

const (
	// DefaultMaxBodyBytes bounds how large a single request or
	// non-streaming response body this proxy will buffer in memory. This
	// is the OOM guard: without it, a large tool_result (e.g. reading a
	// big log file) combined with enough concurrent requests could grow
	// memory usage without bound. Streaming responses are bounded
	// per-content-block instead (see the SSE handler), since a stream's
	// total size isn't meaningfully capped by this constant.
	DefaultMaxBodyBytes int64 = 64 << 20 // 64 MiB

	// DefaultMaxConcurrent bounds how many requests may be actively
	// buffering a body at once, the other half of the OOM guard, since
	// the byte cap alone doesn't bound (concurrent requests × cap).
	// Streaming (SSE) responses release their slot as soon as streaming
	// begins (see ServeHTTP) rather than holding it for the connection's
	// full lifetime, because holding it would cap concurrent agentic
	// turns (including parallel subagents sharing one proxy) far below
	// what memory alone would justify. Only the genuinely bounded-but-
	// unbounded-in-aggregate phases (reading+tokenizing a request body,
	// and buffering+detokenizing a non-streaming response body) hold
	// this slot for their duration.
	//
	// What a released slot costs is bounded per stream, not zero. A text
	// block holds back only what SafeFlushPoint/textFlushBoundary are
	// still resolving, a small constant; a tool_use block genuinely
	// accumulates its whole input until content_block_stop, and is capped
	// at MaxBodyBytes for exactly that reason (see handleBlockDelta's
	// input_json_delta case). So per-connection streaming memory is
	// bounded by that cap rather than by this counter.
	DefaultMaxConcurrent = 16
)

// Server is the reverse proxy. Safe for concurrent use: one Server
// serves all requests via its ServeHTTP method.
type Server struct {
	upstream     *url.URL
	client       *http.Client
	engine       *redact.Engine
	maxBodyBytes int64
	sem          chan struct{}
	logger       *slog.Logger
	debug        *debuglog.Logger
}

// Config configures a new Server. Upstream and Engine are required;
// everything else has a sane default.
type Config struct {
	Upstream      *url.URL
	Engine        *redact.Engine
	MaxBodyBytes  int64 // 0 => DefaultMaxBodyBytes
	MaxConcurrent int   // 0 => DefaultMaxConcurrent
	Logger        *slog.Logger
	// DebugLogger, if set, receives the "full" tier's request/response
	// body logging; see package debuglog. Nil (the default) disables
	// this entirely at effectively zero per-request cost.
	DebugLogger *debuglog.Logger
}

func New(cfg Config) *Server {
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrent
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Clone the stdlib default transport rather than hand-building one:
	// keeps its sane dial/TLS timeouts and only overrides what this
	// proxy specifically needs. ResponseHeaderTimeout is deliberately
	// left unset (no cap): a hard agentic turn can legitimately take
	// several minutes to produce its first token, and this proxy must
	// never be the reason a slow-but-healthy request gets killed.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = maxConcurrent
	transport.IdleConnTimeout = 90 * time.Second

	return &Server{
		upstream:     cfg.Upstream,
		engine:       cfg.Engine,
		maxBodyBytes: maxBody,
		sem:          make(chan struct{}, maxConcurrent),
		logger:       logger,
		debug:        cfg.DebugLogger,
		client:       &http.Client{Transport: transport},
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Before anything else for this request, including the tokenize
	// call below, whose new_value/replacement events (at "full" debug
	// level) are the first debug-log events of this round trip, so a
	// rotating debug log (see debuglog.Logger.BeginRoundTrip) checks and
	// rotates, if needed, at this exact boundary rather than reactively
	// mid-round-trip.
	s.debug.BeginRoundTrip()

	select {
	case s.sem <- struct{}{}:
	default:
		writeAPIError(w, http.StatusServiceUnavailable, "overloaded_error", "proxy at capacity, retry shortly")
		return
	}
	// release is called explicitly once streaming begins (see below) and
	// via this defer on every other exit path (buffered response, or any
	// early return before that point); the released bool makes it safe
	// to call twice, so the defer is a pure safety net, never a double
	// release. Deliberately NOT held for the whole request lifetime: see
	// the early release below for why.
	released := false
	release := func() {
		if !released {
			released = true
			<-s.sem
		}
	}
	defer release()

	r.Body = http.MaxBytesReader(w, r.Body, s.maxBodyBytes)
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Warn("request body too large or unreadable", "err", err, "path", r.URL.Path)
		writeAPIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the proxy's size limit")
		return
	}

	outBody := reqBody
	if len(reqBody) > 0 && looksLikeJSON(r.Header.Get("Content-Type")) {
		tokenized, err := jsonwalk.Tokenize(reqBody, s.engine.Tokenize)
		if err != nil {
			// Fail closed: a redaction failure must never result in the
			// original (possibly real-PII-bearing) body being forwarded.
			s.logger.Error("tokenize request body; blocking request", "err", err, "path", r.URL.Path)
			writeAPIError(w, http.StatusBadGateway, "api_error", "redaction failed; request blocked by the local proxy")
			return
		}
		outBody = tokenized
	}
	s.debug.FullBody("request", r.URL.Path, reqBody, outBody)

	upstreamReq, err := s.buildUpstreamRequest(r, outBody)
	if err != nil {
		s.logger.Error("build upstream request", "err", err)
		writeAPIError(w, http.StatusInternalServerError, "api_error", "failed to construct upstream request")
		return
	}

	resp, err := s.client.Do(upstreamReq)
	if err != nil {
		s.logger.Error("upstream request failed", "err", err, "path", r.URL.Path)
		writeAPIError(w, http.StatusBadGateway, "api_error", "request to provider failed")
		return
	}
	defer func() { _ = resp.Body.Close() }() // read side; nothing to flush

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		// Release the concurrency slot now, before streaming, not at the
		// end of ServeHTTP. That slot exists to bound MEMORY from
		// buffering a body (see DefaultMaxConcurrent's doc comment),
		// but an SSE stream's per-connection memory footprint stays small
		// regardless of how long it runs or how much text flows through
		// it: each content block only ever holds back text
		// engine.SafeFlushPoint is still resolving a genuine partial
		// match against a known credential span, not the whole response,
		// so per-block buffering is bounded by the longest currently-
		// registered span, not by total response size. Holding the slot
		// for the full streaming duration doesn't protect anything memory-
		// related; it only caps how many concurrent agentic turns can
		// be in flight, and since Claude Code's own subagents (Task
		// tool) share this same proxy and pool, a single busy session
		// running a few parallel subagents could exhaust
		// DefaultMaxConcurrent on its own well before any real memory
		// pressure existed. Buffered (non-streaming) responses still
		// hold the slot through proxyBuffered below, via the deferred
		// release; that path genuinely buffers up to maxBodyBytes and
		// still needs the guard.
		release()
		s.proxySSE(w, resp, r.URL.Path)
		return
	}
	s.proxyBuffered(w, resp, r.URL.Path)
}

func (s *Server) buildUpstreamRequest(r *http.Request, body []byte) (*http.Request, error) {
	dst := *s.upstream
	dst.Path = singleJoiningSlash(s.upstream.Path, r.URL.Path)
	dst.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, dst.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = r.Header.Clone()
	req.Header.Del("Host")
	// Let the Transport negotiate its own Accept-Encoding and
	// transparently decompress the response: if the client's own
	// Accept-Encoding header were forwarded as-is, Go's http.Transport
	// disables its automatic gzip handling (per its own documented
	// behavior: it only auto-decompresses when IT set the header), and
	// every downstream read of resp.Body here assumes plain-text JSON.
	req.Header.Del("Accept-Encoding")
	req.ContentLength = int64(len(body))
	req.Host = s.upstream.Host
	return req, nil
}

// proxyBuffered handles a non-streaming response: buffer (bounded),
// detokenize if JSON, forward.
func (s *Server) proxyBuffered(w http.ResponseWriter, resp *http.Response, path string) {
	limited := io.LimitReader(resp.Body, s.maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		s.logger.Error("read upstream response", "err", err)
		writeAPIError(w, http.StatusBadGateway, "api_error", "failed reading upstream response")
		return
	}
	if int64(len(body)) > s.maxBodyBytes {
		s.logger.Error("upstream response exceeded max body size", "max", s.maxBodyBytes)
		writeAPIError(w, http.StatusBadGateway, "api_error", "upstream response exceeded the proxy's size limit")
		return
	}

	outBody := body
	if len(body) > 0 && looksLikeJSON(resp.Header.Get("Content-Type")) {
		outBody = jsonwalk.Detokenize(body, s.engine.Detokenize)
	}
	s.debug.FullBody("response", path, outBody, body) // (real, tokenized) -- detokenize direction, so real is the OUTPUT here

	copyHeader(w.Header(), resp.Header)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(outBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(outBody)
}

func looksLikeJSON(contentType string) bool {
	return strings.HasPrefix(strings.TrimSpace(contentType), "application/json")
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
	// Content-Length is recomputed by the caller after any body
	// rewriting, and Content-Encoding would desync from a rewritten body
	// (upstream compression, if any, was already transparently decoded
	// by the Go HTTP client's Transport before we ever see resp.Body).
	dst.Del("Content-Length")
	dst.Del("Content-Encoding")
}

func writeAPIError(w http.ResponseWriter, status int, errType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "error",
		"error": map[string]string{
			"type":    errType,
			"message": message,
		},
	})
}

// singleJoiningSlash joins a base path and a request path with exactly
// one slash between them, matching the join behavior of
// net/http/httputil.ReverseProxy's own director.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
