# Introduction

### Claude does the work. The client's data stays home.

redactproxy is a local, two-way redaction proxy for
[Claude Code](https://claude.com/claude-code), or anything else that
speaks the Anthropic Messages API. It sits between the client and the
real API: on the way out it replaces real client data (domains, IPs,
emails, credentials, and more) with stable fake values, and on the way
back it puts the real ones in again. Claude only ever sees the fakes.
Your tool calls still run against real infrastructure.

It rewrites API traffic and nothing else. No added prompts, no tool
restrictions, no change to how Claude Code behaves. It listens on
loopback and refuses to start on any other address. There is no
telemetry, no sync, and no backup: everything it stores stays on the
machine you run it on.

## Who this manual is for

Pentest and consulting teams who want to use an AI coding agent on a
live engagement without that client's data reaching the model provider.

**Getting started** takes you from install to a working engagement.
**Running an engagement** covers the day-to-day: adding rules, fixing a
bad mapping mid-session, pointing an engagement at a different provider.
**Security** is the part worth reading before you point this at real
client data: what it protects, what it does not, and why the debug log
is dangerous. **Reference** holds the command line, the detector
categories, the placeholder shapes, and the troubleshooting list.

If you just want it running, start with [Install](./install.md).

## Background

Point an AI coding agent at a live engagement and everything ends up in
the model: client domains, internal hostnames, credentials out of a
config dump, employee emails, the client's own name. Almost none of it
has any reason to leave your machine. The model doesn't need the real
hostname to reason about a finding. It needs one that stays the same
every time it sees it.

That stability is the whole design. A given real value always maps to
the same fake one for the life of an **engagement** (one client
project), so Claude can still work out that two hosts belong to the same
organization without ever seeing which organization. Each engagement
keeps its own storage and shares nothing with the others.

The redaction is two-way and it happens in the right order. Real values
go out as placeholders, and the placeholders in Claude's reply are
swapped back to real values before the reply reaches Claude Code. So a
`Bash` command Claude writes against a placeholder hostname runs against
the real one, every time it runs, not just the first.

> [!WARNING]
> **Authorised testing only.** This is a tool for testers working under
> an engagement. It reduces what a model provider sees; it does not
> grant permission to test anything. You remain responsible for the
> scope you work in and for the data you handle.

## What "token" and "engagement" mean here

"Token" throughout this manual means a redaction placeholder, not the
unit an LLM's context window is measured in. An **engagement** is one
client project, with its own token store, its own rules, and its own
choice of upstream provider.

## Disclaimer

Examples here use synthetic values chosen so they can never collide with
anything real. `XYZCorp` is not a real customer, and
`xyzcorp-fixture.internal` can never be registered by anyone: `.internal`
is permanently reserved for private use and will never be delegated as a
public TLD. Client addresses come from RFC 1918 private space, which is
never publicly routable, and the placeholders they are replaced with come
from the RFC 2544 benchmarking range redactproxy mints its own IPv4
tokens in.

Note that the reserved-for-documentation names, `example.com` and the
[RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) address ranges, are
deliberately **not** used here. redactproxy excludes them from
redaction on purpose (see
[Detector categories](./reference/categories.md#what-is-deliberately-not-detected)),
so an example built on them would show a redaction that never happens.

Nothing in this documentation describes a real target or a real
engagement.
