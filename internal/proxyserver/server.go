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
	"net"
	"net/http"
	"net/netip"
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
	allowedHosts map[string]bool
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
	// AllowedHosts are extra DNS names clients may address this proxy by,
	// on top of "localhost" and any IP literal, which are always
	// accepted; see Server.browserOriginProblem.
	AllowedHosts []string
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

	allowedHosts := make(map[string]bool, len(cfg.AllowedHosts))
	for _, h := range cfg.AllowedHosts {
		allowedHosts[normalizeHost(h)] = true
	}

	return &Server{
		allowedHosts: allowedHosts,
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

	if problem := s.browserOriginProblem(r); problem != "" {
		s.logger.Warn("request refused: "+problem, "host", r.Host, "origin", r.Header.Get("Origin"), "path", r.URL.Path)
		writeAPIError(w, http.StatusForbidden, "permission_error", "refused by the local proxy: "+problem)
		return
	}

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
	// Scanned on what the body looks like, not only on what the header
	// claims: a JSON body sent as "text/plain" or with no Content-Type at
	// all can still be parsed as JSON upstream, so trusting the header
	// alone forwarded it with every real value intact.
	if len(reqBody) > 0 && (looksLikeJSON(r.Header.Get("Content-Type")) || startsLikeJSON(reqBody)) {
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

// browserOriginProblem reports why r looks like it was sent by a web
// page rather than by a client pointed at this proxy on purpose, or ""
// if it doesn't.
//
// The proxy has no authentication and detokenizes every response, and it
// listens on a well-known local port, which makes it a target for any
// page open in the operator's browser. Some placeholders are cheap to
// enumerate (a fake IPv4 is a small counter plus the real host octet), so
// a page that can read responses can recover real addresses with an API
// key of its own. Two routes get it there, and both show up in headers
// the page cannot forge:
//
//   - DNS rebinding: the page's own hostname is re-pointed at this
//     machine, so its requests are same-origin and readable. They arrive
//     with that hostname in Host. A client configured with an IP or
//     "localhost" never sends a DNS name there, so only "localhost", IP
//     literals and names the operator listed are accepted.
//   - A cross-origin request straight at the IP: Host is fine, but the
//     browser attaches Origin (and Sec-Fetch-Site) naming the page.
//
// An IP-literal Host is accepted whatever the address, so a proxy bound
// to 0.0.0.0 keeps working for clients that reach it by LAN IP.
func (s *Server) browserOriginProblem(r *http.Request) string {
	if !s.hostAllowed(r.Host) {
		return "Host is not an IP address, localhost, or a name given with --allow-host"
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || !s.hostAllowed(u.Host) {
			return "cross-origin browser request"
		}
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return "cross-site browser request"
	}
	return ""
}

func (s *Server) hostAllowed(hostport string) bool {
	host := normalizeHost(hostport)
	if host == "localhost" || s.allowedHosts[host] {
		return true
	}
	_, err := netip.ParseAddr(host)
	return err == nil
}

// normalizeHost reduces a Host header or --allow-host value to a bare
// lowercase hostname or IP: no port, no IPv6 brackets or zone, no
// trailing dot.
func normalizeHost(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if i := strings.IndexByte(host, '%'); i != -1 {
		host = host[:i]
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
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
	switch ct := resp.Header.Get("Content-Type"); {
	case len(body) == 0:
	case looksLikeJSON(ct):
		outBody = jsonwalk.Detokenize(body, s.engine.Detokenize)
	case looksLikeJSONLines(ct):
		// A batch's results: one JSON document per line, each wrapping
		// an ordinary response message (see jsonwalk.collectPaths).
		lines := bytes.Split(body, []byte("\n"))
		for i, line := range lines {
			if len(bytes.TrimSpace(line)) > 0 {
				lines[i] = jsonwalk.Detokenize(line, s.engine.Detokenize)
			}
		}
		outBody = bytes.Join(lines, []byte("\n"))
	}
	s.debug.FullBody("response", path, outBody, body) // (real, tokenized) -- detokenize direction, so real is the OUTPUT here

	copyHeader(w.Header(), resp.Header)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(outBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(outBody)
}

// looksLikeJSON reports whether a Content-Type header declares JSON:
// application/json or any "+json" structured-syntax type, with or
// without parameters. Media types are case-insensitive (RFC 9110).
func looksLikeJSON(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

// looksLikeJSONLines reports whether a Content-Type header declares
// newline-delimited JSON, which is how the API serves batch results.
func looksLikeJSONLines(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	switch strings.ToLower(strings.TrimSpace(mediaType)) {
	case "application/x-jsonl", "application/jsonl", "application/x-ndjson", "application/jsonlines":
		return true
	}
	return false
}

// startsLikeJSON reports whether body opens a JSON object or array,
// whatever its Content-Type says. Deliberately not a validity check: a
// body that starts like JSON but is malformed or truncated still carries
// its real values, and routing it to jsonwalk.Tokenize gets it blocked
// there instead of forwarded. A bare JSON scalar doesn't count: no API
// request body is one, and it would make plain text like "123" qualify.
func startsLikeJSON(body []byte) bool {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
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
