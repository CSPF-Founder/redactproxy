# Configuring Claude Code

The proxy only sees what Claude Code sends to `/v1/messages`. Two pieces
of Claude Code configuration matter: pointing it at the proxy, and
closing the channels that never go through the proxy at all. The wizard
writes both. This page explains what it wrote and why, so you can audit
it or do it by hand.

## Pointing Claude Code at the proxy

Claude Code reads `ANTHROPIC_BASE_URL` to decide where to send its
traffic. Either set it per shell:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

or, better, put it in the folder's `.claude/settings.local.json`, which
is what the wizard does:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787"
  }
}
```

`settings.local.json` specifically, not `settings.json`: it is the file
meant for personal, machine-local settings that never get committed or
shared, which is exactly what a local proxy port is.

The env-var form only applies to the shell you set it in. Close that
terminal when the engagement is done, or `unset` it, so an unrelated
session later doesn't route through the same proxy by accident. The
settings-file form has no such problem, since it is scoped to the
folder.

## The hardening the wizard adds

This is the full file the wizard writes for a fresh folder:

```json
{
  "disableRemoteControl": true,
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787",
    "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_FEEDBACK_COMMAND": "1",
    "DISABLE_TELEMETRY": "1"
  },
  "permissions": {
    "deny": [
      "Read(//home/you/.redactproxy/engagements/eng-2026-014/debug.log)",
      "Artifact",
      "RemoteTrigger",
      "PushNotification",
      "SendUserFile"
    ]
  },
  "skipWebFetchPreflight": true
}
```

Each entry closes a specific path that bypasses `ANTHROPIC_BASE_URL`.

### The denied tools

`Artifact` is a confirmed leak path: a report published through it goes
straight to a hosted claude.ai URL, entirely unredacted, via a separate
service call rather than a Messages API request. Nothing this proxy does
can touch it.

`RemoteTrigger`, `PushNotification` and `SendUserFile` share the same
Remote-Control-adjacent architecture and are denied for the same reason,
as cheap defense in depth.

A **bare tool name** in a deny rule removes the tool from Claude's
context entirely, rather than prompting for permission each time. That
distinction is the point: a permission prompt can still be approved by
habit, but a tool that was never offered cannot leak anything.

### `disableRemoteControl`

Remote Control's session transcript carries real messages, responses and
tool activity over a channel this proxy never sees.

Claude Code already disables Remote Control on its own whenever
`ANTHROPIC_BASE_URL` points somewhere other than `api.anthropic.com`, so
under today's behavior this is redundant. It is set anyway, as a second
guarantee that does not depend on that auto-detection surviving into a
future version.

### `skipWebFetchPreflight`

`WebFetch`'s safety check sends the **target hostname** to Anthropic
directly, as a preflight, before the actual fetch. A domain being
reconned is precisely the kind of value this tool exists to keep off any
channel that bypasses tokenization.

This check runs regardless of which model provider you use. So for an
engagement pointed at a non-Anthropic provider, leaving it on means the
target hostname still goes to Anthropic, a company otherwise not even in
the loop for that engagement.

### The debug log deny rule

`Read(//path/to/debug.log)` keeps a session from loading the debug log
into its own context by accident and burning tokens on a file nobody
asked it to read. Claude Code's `Read` deny also covers `cat`, `head`,
`tail` and `sed` on that path via `Bash`.

It is not meant to stop you from deliberately analyzing that log. Loosen
the rule, or point a separate unrestricted session at the file.

### The quiet env vars

Telemetry, error reporting, and feedback/survey prompts. None of these
are as high-stakes as the above: usage metrics and crash reports, not
report content. They are disabled because it costs nothing and keeps
every optional channel to non-proxied infrastructure closed by default.

Worth knowing: a plain custom `ANTHROPIC_BASE_URL` override, which is
what every engagement here uses, does **not** get these auto-disabled
the way recognized integrations like Bedrock or Vertex do. It is treated
as ordinary Claude API use, with telemetry and error reporting
defaulting on. This block is doing real suppression, not redundant
caution.

## The startup warning

If any of the above is missing from the folder's settings, the proxy
says so at startup and lists exactly what is absent:

```text
WARNING: this folder's Claude Code isn't fully hardened against channels that
bypass this proxy entirely. The Artifact tool, for example, publishes straight
to claude.ai, completely unredacted. Run `redactproxy wizard` here to fix that
automatically, or add the following to .claude/settings.local.json by hand:
  - disableRemoteControl: true
  - permissions.deny: "Artifact"
  ...
```

Re-running `redactproxy wizard` in the folder fixes it. The wizard
merges into an existing file rather than overwriting it, prints what is
there, lists exactly what it would change, and asks before writing.

## The CLAUDE.md note

```bash
redactproxy memory                        # print it
redactproxy memory --write ./CLAUDE.md    # append it
```

Without this note, a session sees placeholder values with no explanation
and behaves accordingly: treating them as typos to correct, hesitating
to use them in tool calls, or reconstructing them from memory slightly
wrong. The note tells Claude what the shapes mean and that they are
stable identifiers to reproduce verbatim.

It also covers several failure modes worth knowing about yourself:

- **Never retype a placeholder from memory.** Copy it from its most
  recent literal appearance. A fragmented or approximated token means an
  `Edit`'s `old_string` won't match the real file, or a report line
  traces back to nothing.
- **A fake IP is not test data.** The placeholder IPv4 range looks like
  documentation space because it is reserved benchmarking space, chosen
  so it can never collide with a real target. It stands in for a real,
  sensitive address and should be reasoned about as one.
- **An unfamiliar-looking token is not a bug.** It is either a token
  doing its job or an over-redaction of something merely domain-shaped.
  Either way the real value is substituted before execution, so the
  command runs correctly. Verify against the real filesystem with
  `Bash`/`Read` rather than guessing around the token.
- **Decode encoded content locally, not inline.** Base64 or hex decoded
  by Claude into its own output arrives completely unprotected, since
  the encoded form passed through unredacted. Decoding it to a file with
  `Bash` and reading the file back gives that content a normal pass
  through redaction.

Put it in the engagement's project-level `./CLAUDE.md`, not the
user-level `~/.claude/CLAUDE.md`. The user-level one loads for every
session on the machine, including sessions with no proxy in front of
them.

Appending is idempotent. Re-running the wizard or `memory --write`
detects the existing note and leaves the file unchanged.
