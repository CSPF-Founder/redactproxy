# Threat model

This page states what redactproxy is designed to do, against what, and
under which assumptions. Read it with [Known gaps](./gaps.md), which is
the same subject from the other direction.

## What it defends against

**One adversary: the model provider seeing client data it has no need
to see.** Not an attacker on your network, not a malicious client, not a
compromised host. A tester using an AI coding agent on a live engagement
produces API traffic full of client-identifying material that has no
reason to leave the machine, and the model does not need any of it to be
useful.

Concretely, redactproxy is designed to keep these off the wire:

| Category | Examples |
|---|---|
| Client identity | company names, trading names, product names, codenames |
| Network identity | domains, hostnames, IPv4/IPv6 addresses, MAC addresses |
| People | email addresses, phone numbers |
| Credentials | API keys for 25+ vendors, JWTs, bearer tokens, connection strings, private keys, password hashes |
| Regional PII | Indian Aadhaar and PAN numbers |
| AD artifacts | machine account names, GPP `cpassword` values |

The full list is in [Detector categories](../reference/categories.md).

## What it does not defend against

It is **not** a data loss prevention system, a network control, or a
sandbox. It has no opinion about what Claude does, no tool restrictions,
and no added prompts. It edits API traffic and nothing else.

It is also not a defense against you. Anyone who can run the binary can
read `tokens.db` and see every mapping. The point is to control what
reaches a third party, not to withhold anything from the operator.

## Assumptions it makes

1. **The host is trusted.** Real values live on it, in `tokens.db` and
   in Claude Code's own transcripts. Compromise of the host defeats
   everything here.
2. **Loopback is trusted.** The proxy binds loopback only and refuses to
   start on any other address, including the bare `:8787` shorthand. Any
   local process that can reach the port can send it traffic.
3. **The upstream connection is TLS.** The proxy terminates TLS to the
   upstream. A vulnerability in Go's `net/http` or `crypto/tls` is
   treated as a finding about this tool, which is why `go.mod` pins a
   patch-level Go version and CI runs `govulncheck`.
4. **Detection is regex-based, so coverage is shape-based.** Anything
   without a recognizable shape is not detected. This is the single
   largest assumption and the source of most entries in
   [Known gaps](./gaps.md).

## Design properties you can rely on

**Fail closed.** Anything on the request path that cannot finish its job
returns an error rather than passing bytes through. A malformed body, a
detector that errors, a token store that cannot commit: all fail the
request. An unredacted forward is the one outcome this project treats as
worse than a broken request.

That extends to inputs designed to slip past. A body that is not valid
JSON is rejected rather than forwarded untouched, because a lenient
parser would otherwise report "nothing to redact" for a body that was
never parsed. Invalid UTF-8 inside a string is rejected for a related
reason: a real value sliced out of it would corrupt whatever it was
later substituted back into.

**Tokens cannot be confused with real values.** Every placeholder shape
is structurally guaranteed never to collide with something real: the
fake IPv4 range is RFC 2544 benchmarking space, phone placeholders use
the reserved 555-01XX exchange, Aadhaar placeholders start with a digit
UIDAI never issues, and credential placeholders embed `FAKE` in a
position where a real value can only carry hex. See
[Placeholder shapes](../reference/placeholders.md).

**Tokens carry no information about the value.** They are drawn from
`crypto/rand`, not derived from the real value. There is nothing in a
placeholder to reverse, and nothing that leaks through the mapping
itself. This is also why removing a mapping and re-encountering the same
value mints a different placeholder.

**No network, no telemetry, no persistence beyond the engagement
directory.** Detection is local regex matching with no model in the
loop. The proxy talks to exactly one upstream, the one you configured.

**Nothing else in the request changes.** The rewrite is surgical: only
matched spans change, and every other byte including JSON key order is
preserved, so Claude Code's prompt caching is unaffected.

## Scope boundaries

Three things sit outside the proxy entirely and are worth naming
explicitly, because they look like they should be covered:

- **Claude Code's other traffic.** Feature flags, token refresh, and the
  `WebFetch` preflight do not go through `ANTHROPIC_BASE_URL` at all.
  What configuration can close, the wizard closes. See
  [Configuring Claude Code](../claude-code.md).
- **HTTP headers.** Forwarded verbatim, never inspected. This is what
  makes credential passthrough work; it also means anything you put in a
  header is not redacted.
- **Local files.** The proxy inspects API traffic. It never reads or
  writes anything in your working directory except the engagement
  marker, and only the wizard touches `CLAUDE.md` and
  `.claude/settings.local.json`.

## Reporting a leak

"This real value reached the model unredacted" is a bug in a detector.
It goes in the public [issue
tracker](https://github.com/CSPF-Founder/redactproxy/issues), described
by the shape of the value rather than the value itself.
[SECURITY.md](https://github.com/CSPF-Founder/redactproxy/blob/main/SECURITY.md)
lists what to report privately instead: findings where the proxy itself
is the way in, such as code execution from a body it parses, an escape
from the loopback bind, or another local process reading real values
back out of it.
