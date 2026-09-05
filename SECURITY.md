# Security Policy

## Reporting a vulnerability

Please do not open a public GitHub issue for a suspected redaction leak
or other security-relevant bug.

Report it privately instead. GitHub's [private vulnerability
reporting](https://github.com/CSPF-Founder/redactproxy/security/advisories/new)
opens a draft advisory only the maintainers can see. If that isn't
available to you, email
[founder@cysecurity.org](mailto:founder@cysecurity.org).

Please give us a reasonable window to ship a fix before disclosing
publicly.

Include, if possible:

- The kind of value that leaked (domain, credential, email, and so on).
  No need to send the actual value.
- Whether it was the outbound (tokenize) or inbound (detokenize)
  direction, and whether streaming (SSE) was involved.
- A minimal reproduction, ideally with synthetic data shaped like the
  real case. `internal/redact/pentest_corpus_test.go` shows the style of
  fixture this project uses for exactly that reason.
- A patch, if you have one. Welcome, not expected. Attach it to the
  advisory rather than opening a public pull request against an unfixed
  vulnerability.

## Scope

This tool inspects and rewrites Anthropic Messages API request and
response *bodies*. It cannot protect data reaching the model through a
channel it never sees, and the known gaps there are listed under ["What
this doesn't protect"](README.md#what-this-doesnt-protect) in the
README. A gap that isn't already on that list is exactly what this
policy is for.

A leak here means client data reaching the model provider the operator
was already sending traffic to, not an unrelated third party. That is
still worth reporting: keeping client data off that provider is the
whole reason this tool exists, and for anyone working under an NDA it is
usually an obligation rather than a preference.

## Supported versions

There are no long-term support branches. Fixes land on `main` and go out
in the next tagged release, so please confirm against the latest release
before reporting.

## What happens after a report

A confirmed leak gets root-caused, fixed, and pinned with a regression
test. This is a small project, so that may not be the same day, but a
confirmed leak is treated as a real bug rather than a wishlist item.
