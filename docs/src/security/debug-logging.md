# Debug logging

> [!WARNING]
> **Every level above `off` writes real client values to `debug.log` in
> plaintext.** Leave it off unless you are actively debugging, never
> share the file, and delete it when you are done. Treat it exactly like
> the engagement data itself.

A log that showed only placeholders would be useless for the thing it
exists for: working out why a real value was or was not detected. The
safety has to come from handling instead.

## Levels

`--debug-level` is `off` by default. Levels are cumulative: each one
includes everything the level before it logs.

| Level | Logs |
|---|---|
| `off` (default) | nothing |
| `new` | the real value the first time each one is seen |
| `replacements` | every substitution, every time |
| `full` | entire request/response bodies, real and tokenized |

```bash
redactproxy --debug-level new
```

## Where it goes

`debug.log` in the engagement's own directory, alongside `tokens.db`:

```text
$HOME/.redactproxy/engagements/eng-2026-014/debug.log
```

That location is chosen deliberately. It defaults to `$HOME`, outside
any project working directory, so a Claude Code session browsing its own
folder cannot stumble into it.

If you point `--data-dir` somewhere inside the current working
directory and turn on debug logging, the proxy warns:

```text
level=WARN msg="debug.log will contain real client values, and --data-dir
resolves inside the current working directory. If Claude Code runs from here,
it may be able to read this file"
```

The wizard also adds a `permissions.deny` rule for the file's exact
path, so Claude Code will not read it via `Read` or via `cat`/`head`/
`tail`/`sed` in `Bash`. That rule is about stopping an accidental
context load, not about stopping you: loosen it, or point a separate
unrestricted session at the file, if you actually want a session to
analyze the log.

## Rotation

`full` grows fast, because every logged request body is the whole
conversation history so far. The log is gzipped into a timestamped part
and restarted once it passes `--debug-log-max-mb`, 10 MiB by default:

```bash
redactproxy --debug-level full --debug-log-max-mb 50
```

Rotated parts are named `debug.log.<when>.gz` and sit in the same
directory. They contain the same real values the live log does, so they
need the same handling and the same deletion.

## Choosing a level

- **`new`** answers "was this value ever detected at all?" It is the
  right level for a suspected miss, and by far the smallest.
- **`replacements`** answers "is this value being substituted
  consistently?" Use it when a mapping looks unstable.
- **`full`** answers "what exactly went over the wire?" Use it when
  reporting a suspected leak, and only for as long as it takes to
  reproduce.

Before reaching for any of them, try `redactproxy tokens show` or the
console's `show`. It tells you what has been mapped without writing
anything new to disk.

## Cleaning up

```bash
rm -f ~/.redactproxy/engagements/eng-2026-014/debug.log*
```

Deleting the whole engagement directory at the end of an engagement
covers this too. See
[Engagements and storage](../engagements.md#retiring-an-engagement).

## Reporting a leak with it

If you are attaching log output to a report, redact the client values by
hand first, or reproduce against synthetic data shaped like the real
thing. Leak reports are public issues (see
[SECURITY.md](https://github.com/CSPF-Founder/redactproxy/blob/main/SECURITY.md)),
and a leak report should not itself be a leak.
