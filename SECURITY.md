# Security Policy

## Where to report what

Most things, including a value that should have been redacted and
wasn't, belong in the public [issue
tracker](https://github.com/CSPF-Founder/redactproxy/issues).

redactproxy binds to loopback on your own machine and refuses to bind
anywhere else. A redaction miss means client data
reached the model provider you were already sending traffic to, not an
unrelated third party. That is worth fixing, and under an NDA it is
usually an obligation rather than a preference, but it is not a hole
somebody can reach in anyone else's deployment. Nothing is exposed by
the issue sitting open, and a public issue is the version the next
person can search for, confirm, and send a patch against. Detector gaps
get closed faster in the open.

## Report privately instead when the proxy itself is the way in

- **Code execution or memory unsafety** reachable from a request body or
  an upstream response. The proxy parses JSON and SSE it did not write.
- **Anything that escapes loopback or the engagement directory.** A way
  around the `--listen` loopback check, a path traversal in a rules or
  store path, files created with permissions wider than `0600`.
- **A way for another local process to read real values without reading
  the store file.** Anything on the machine can send requests through
  the proxy, and the inbound path detokenizes. It should not be usable
  as a detokenization oracle by a process that has no access to the
  store.
- **Traffic reaching a host you did not configure.** A rewritten
  upstream URL, credentials attached to the wrong destination.
- **Anything in the release path**, such as a tampered artifact or a
  compromised dependency in the built binary.

Not sure which side of the line something falls on? Report it privately.
Moving it to a public issue afterwards is easy; the reverse isn't.

## Reporting privately

GitHub's [private vulnerability
reporting](https://github.com/CSPF-Founder/redactproxy/security/advisories/new)
opens a draft advisory only the maintainers can see. If that isn't
available to you, email
[founder@cysecurity.org](mailto:founder@cysecurity.org). Please give us a
reasonable window to ship a fix before disclosing publicly, and attach
any patch to the advisory rather than opening a public pull request
against an unfixed vulnerability.

## What to include, either way

- **No client data.** Describe the kind of value that leaked (domain,
  credential, email, and so on), not the value itself. Hand-redact any
  log output you attach, or reproduce against synthetic data shaped like
  the real thing. A leak report should not itself be a leak.
- Whether it was the outbound (tokenize) or inbound (detokenize)
  direction, and whether streaming (SSE) was involved.
- A minimal reproduction.
  `internal/redact/pentest_corpus_test.go` shows the style of fixture
  this project uses for exactly that reason.
- The output of `redactproxy version`.
- A patch, if you have one. Welcome, not expected.

## Scope

This tool inspects and rewrites Anthropic Messages API request and
response *bodies*. It cannot protect data reaching the model through a
channel it never sees, and the known gaps there are listed under ["What
this doesn't protect"](README.md#what-this-doesnt-protect) in the
README. A gap that isn't already on that list is worth an issue.

## Supported versions

There are no long-term support branches. Fixes land on `main` and go out
in the next tagged release, so please confirm against the latest release
before reporting.

## What happens after a report

A confirmed leak gets root-caused, fixed, and pinned with a regression
test. This is a small project, so that may not be the same day.
