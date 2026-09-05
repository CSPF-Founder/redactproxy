# Contributing

Thanks for taking a look. New detectors, false-positive reports, and
blind spots nobody has written down yet are all welcome.

Suspected redaction leaks belong in the issue tracker like any other
bug. The proxy is loopback-only and the value went to the provider you
were already talking to, so there is nothing to embargo and a public
report is the one other people can find. [SECURITY.md](SECURITY.md)
covers the narrower set of things to report privately instead.

## Getting set up

You need [Go](https://go.dev/dl/) 1.26.6 or newer. There are no other
dependencies, and nothing to install beyond the module cache.

```bash
git clone https://github.com/CSPF-Founder/redactproxy.git
cd redactproxy
make build            # bin/redactproxy
make check            # vet + race
```

## Where things live

```
cmd/redactproxy/       the CLI: proxy startup, wizard, rules/tokens/memory subcommands
internal/redact/       detection + tokenize/detokenize engine (the core logic)
internal/tokenstore/   persistent real<->token mapping, backed by bbolt
internal/jsonwalk/     finds/rewrites just the content-carrying strings in a Messages API body
internal/proxyserver/  the HTTP proxy itself (net/http handler, SSE streaming)
internal/rules/        per-engagement config: enabled categories, custom block/allow entries
internal/debuglog/     opt-in diagnostic logging (contains real values; see its doc comment)
```

Package doc comments carry the design rationale and are the
authoritative explanation; this guide only points at them. Start with
`internal/redact/detector.go` for how detection is structured, and
`Engine.SafeFlushPoint` (`internal/redact/engine.go`) plus `spanTrie`
(`internal/tokenstore/spans.go`) before touching anything to do with
streaming, where the hard correctness constraints are.

## Before opening a pull request

First, the three that need nothing installed:

```bash
gofmt -l .                     # must print nothing
go vet ./...
go test -race -count=1 ./...
```

`make check` is a shortcut for the last two, and uses nothing beyond the
Go distribution.

CI runs two more jobs that need a tool installed separately, so they
are not part of `make check`:

```bash
make lint                      # golangci-lint, config in .golangci.yml
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

The lint config is golangci-lint's default (`standard`) linter set plus
one exemption of our own: `errcheck` is off in `_test.go`, because a test
HTTP handler writing a response body has nowhere useful to send the
error. The baseline is clean, so anything `make lint` reports is
something you added.

Production code gets no exemption, including the default ones
golangci-lint would otherwise apply on its own (see the comment in
`.golangci.yml`). An error you genuinely cannot act on is discarded
explicitly, `_ = f.Close()`, with a short reason. Writing the reason out
is what separates "closing this read handle can't tell me anything" from
"this Close is where a failed write would have surfaced". Prefer checking it when a buffer is involved, since that
is where the second case hides.

Install golangci-lint with the same toolchain this module targets:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
```

golangci-lint embeds a Go type-checker at build time and refuses to run
against a module targeting a newer Go than it was built with, so a
binary from a distro package or an older tarball can fail outright where
this one works. CI pins the same version.

govulncheck fails on a vulnerable *toolchain*, not just a vulnerable
dependency, which is why `go.mod` pins a patch-level Go version rather
than a bare `1.26`. This proxy terminates TLS to the upstream and parses
whatever a scan happens to return, so a reachable CVE in `net/http` or
`crypto/tls` is a finding about this tool.

## Fuzzing

`go test` already runs every `Fuzz*` target over its seed corpus and any
previously-found failing inputs, so the commands above cover the
regression half and nothing extra is needed for a PR. The open-ended
mutation search is a separate, opt-in step, worth running when you
touch parsing, streaming, or detection:

```bash
make fuzz                      # every target, 60s each
make fuzz FUZZTIME=300s        # every target, 5m each
make fuzz FUZZ=FuzzSpanTrie    # one target
```

Targets live in each package's `fuzz_test.go` and are discovered with
`go test -list`, so adding a `Fuzz*` function is the whole of adding a
target. If a run fails, Go writes the offending input to that package's
`testdata/fuzz/<FuzzName>/`. Commit that file along with the fix: it
then runs on every `go test` from then on, as a named regression case
for the exact bug it found.

## Conventions

### Errors

Wrap with `%w` and enough context to locate the failure. Match with
`errors.Is`/`errors.As`, never on message text. Never return
`nil, nil`.

### Fail closed

Anything on the request path that cannot finish its job must return an
error rather than pass bytes through. An unredacted forward is the one
outcome this project treats as worse than a broken request, and several
functions carry doc comments explaining where that line sits. Keep that
reasoning intact when you change them.

### Tests

Table-driven, and run under `-race`. Unit tests sit next to the code
they test. Two suites are worth knowing about.
`internal/redact/invariants_test.go` sweeps every registered detector
against five first-principles invariants (fires, idempotent, stable,
round-trips, no false collisions) from one shared table, and
`internal/redact/pentest_corpus_test.go` holds realistic tool output
(nmap, whois, dig, gobuster, Metasploit) next to a false-positive trap
corpus. Fixtures use synthetic data shaped like the real thing:
`widgetcorp-fixture.com` rather than `example.com`, which is itself in
the reserved-values exclusion list the suite has to test past.

A credential fixture must never be written as a single string literal.
Build it from a prefix constant in
`internal/redact/credprefix_test.go` plus a body, or from a helper like
`strings.Repeat`, so the assembled value exists only at run time. These
fixtures have to carry the exact byte shape of a real vendor
credential, which is also what secret scanners match on: a literal
`xoxb-...` in a test file is enough for GitHub push protection to
reject the push and for a contributor's pre-commit scanner to report
the tree as leaking. Go folds the concatenation at compile time, so the
value under test is unchanged.

### Comments

Doc comments on exported items and on anything non-obvious, explaining
*why* rather than restating the code. This codebase leans heavily on
that, particularly where a detector deliberately does not fire. If you
change such a decision, update the comment that justified it in the
same commit.

## Adding a detector

1. Add an `EntityType` constant and token prefix in
   `internal/tokenstore/store.go` and `generator.go`.
2. Implement `Detector` in `internal/redact/detector.go`.
3. Register it in `DefaultCategorizedDetectors()`
   (`internal/redact/categories.go`), which is also what gives it a
   category name users can `rules disable`.
4. Add it to `invariantCases()` in
   `internal/redact/invariants_test.go`. That alone gets you the
   five-invariant sweep and streaming-safety coverage, since both are
   driven off the actual `Tokenize` path.

A detector that fires on real-looking-but-innocent text costs users more
than one that misses an edge case, so a new detector should come with
false-positive cases in `internal/redact/pentest_corpus_test.go`
alongside the positive ones.

Two things nobody has built yet, if you want somewhere to start: a
local NER model for prose-shaped PII (names, org references, anything
without a regex shape), and more Windows/AD artifacts (UNC paths,
`domain\username`, LDAP DN components). Open an issue to claim either.

## Adding a provider

`--upstream` is a plain URL flag with no Anthropic-specific logic beyond
its default, and every client header is forwarded untouched, so any
Anthropic-Messages-API-compatible provider already works with no code
changes. What the wizard offers is deliberately narrower: real Claude,
z.ai, or a placeholder skeleton you fill in yourself. A wrong guess at,
say, which auth header some provider expects fails silently rather than
loudly. Adding another fully-supported provider means a new
`offerXSettings` function in `cmd/redactproxy/wizard.go` following the
same shape, not a config option.

## Commit messages

Short imperative subject, and a body explaining why when it is not
obvious from the diff. No particular format is enforced.
