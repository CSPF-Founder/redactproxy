# Command line

```text
redactproxy [flags]             start the proxy
redactproxy wizard [flags]      interactive engagement setup, start here
redactproxy rules <subcommand>  show | validate | enable | disable | block | allow | remove
redactproxy tokens <subcommand> show | remove, against already-minted tokens
redactproxy memory [--write P]  print (or append) the CLAUDE.md placeholder note
redactproxy version             print the build this binary was made from
```

Every subcommand takes `-h`.

> [!IMPORTANT]
> **Subcommands come before flags, and flags come before values.** Go's
> flag parser stops at the first non-flag argument, so
> `redactproxy --engagement foo rules show` would start a live proxy
> rather than run a read-only command, and
> `rules block xyzcorp-fixture.internal --domain` would treat
> `--domain` as a second positional argument. Both are caught and
> explained rather than silently doing the wrong thing, but the ordering
> rule is worth internalizing:
> `redactproxy rules block --domain xyzcorp-fixture.internal`.

## Shared flags

`--engagement` and `--data-dir` are accepted by the proxy, `wizard`, and
every `rules` and `tokens` subcommand.

| Flag | Default | Meaning |
|---|---|---|
| `--engagement` | from `.redactproxy-engagement` | engagement name; remembered per-folder after the first explicit use |
| `--data-dir` | `$HOME/.redactproxy` | base directory for engagement data |

## `redactproxy` (start the proxy)

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:8787` | address to listen on; loopback only |
| `--upstream` | `upstream.txt`, else `https://api.anthropic.com` | the API base URL to proxy to |
| `--disable` | none | comma-separated categories to disable for this run only |
| `--debug-level` | `off` | `off`, `new`, `replacements`, `full`; see [Debug logging](../security/debug-logging.md) |
| `--debug-log-max-mb` | `10` | size at which `debug.log` is gzipped and restarted |
| `--max-body-mb` | `64` | maximum request/response body this proxy will buffer |
| `--max-concurrent` | `16` | maximum requests actively buffering a body at once |

`--listen` is validated as loopback at startup. `127.0.0.1`, `::1` and
`localhost` are accepted; the bare `:8787` shorthand is **refused**,
because it genuinely binds every interface.

`--upstream` must be absolute and use `http` or `https`. An explicit
value wins over the engagement's persisted one for that run only.

`--disable` merges with `rules.json`'s own disabled list rather than
replacing it, and stays in effect across rule reloads for the life of
the process. For a persisted change use `rules disable`.

Ctrl-C or `SIGTERM` shuts down gracefully, with a 10 second window for
in-flight requests.

While it runs, the terminal is also a console: see
[Tokens and the live console](../tokens.md#the-live-console).

## `redactproxy wizard`

```bash
redactproxy wizard [--engagement NAME] [--data-dir DIR] [--listen ADDR]
```

Interactive setup. Collects customer names and domains, asks which API
provider the engagement talks to, offers to append the `CLAUDE.md` note,
and offers to write `.claude/settings.local.json`.

`--listen` here does not start anything. It is the address written into
the settings file, so it must match what you actually start the proxy
with.

With no `--engagement` and no folder marker, the wizard offers a picker
over existing engagements rather than erroring the way non-interactive
commands do. Typing a name that already exists asks for confirmation
first, since accidental reuse is how two clients end up in one token
store.

Safe to re-run at any time, including against a running engagement.

## `redactproxy rules`

```bash
redactproxy rules show     [--engagement NAME] [--data-dir DIR]
redactproxy rules validate [--engagement NAME] [--data-dir DIR]
redactproxy rules enable   [flags] <category>
redactproxy rules disable  [flags] <category>
redactproxy rules block    [flags] [--regex] [--domain] [--note "..."] <value>
redactproxy rules allow    [flags] [--regex] [--note "..."] <value>
redactproxy rules remove   [flags] <value>
```

| Flag | Applies to | Meaning |
|---|---|---|
| `--regex` | `block`, `allow` | treat the value as a regular expression |
| `--domain` | `block` | value is a base domain; give it structure-preserving treatment everywhere it appears |
| `--note` | `block`, `allow` | note explaining why the entry exists |

`block` matches case-insensitively as a substring. `allow` matches the
exact value only. An allow entry always overrides a block entry for the
same value, so adding a value already in the other list is refused.

`enable`/`disable` take a category (`cloud.aws`) or a bare category
prefix (`cloud`, which toggles every subcategory under it).

Changes reach a running proxy within about two seconds. Full detail in
[Rules](../rules.md).

## `redactproxy tokens`

```bash
redactproxy tokens show   [--engagement NAME] [--data-dir DIR]
redactproxy tokens remove [--engagement NAME] [--data-dir DIR] <real-value>
```

Operates on already-minted mappings. `remove` takes the **real** value,
not the placeholder, and only forgets that one mapping: it does not stop
future redaction.

Both need the proxy **not** running for that engagement, since only one
process can hold `tokens.db` open. Type `show` or `remove <value>` into
the running proxy's own terminal instead. See
[Tokens](../tokens.md).

## `redactproxy memory`

```bash
redactproxy memory                       # print the snippet
redactproxy memory --write ./CLAUDE.md   # append it to a file
```

Prints the note explaining placeholder shapes to a Claude Code session.
`--write` appends, creating the file if needed, and is idempotent: a
file that already has the note is left unchanged.

Put it in the engagement's project-level `./CLAUDE.md`, not the
user-level `~/.claude/CLAUDE.md`. See
[Configuring Claude Code](../claude-code.md#the-claudemd-note).

## `redactproxy version`

```bash
redactproxy version
```

Prints the build the binary was made from, and works from any directory
without an engagement being resolvable. Include it in bug reports.

## Build targets

From a clone:

```bash
make build   # bin/redactproxy for the current platform
make test    # go test ./...
make race    # go test -race -count=1 ./...
make vet     # go vet ./...
make lint    # golangci-lint (installed separately)
make check   # vet + race, run this before calling anything done
make fuzz    # exploratory fuzzing, 60s per target
make dist    # cross-compiled binaries (linux/darwin/windows, amd64/arm64)
make install # build into $(go env GOPATH)/bin
```

Requires Go 1.26.6 or newer. See CONTRIBUTING.md to work on the code.
