# Engagements and storage

An **engagement** is one client project. It owns a token store, a rule
set, and a choice of upstream provider, and it shares none of them with
any other engagement.

Engagement names are 1 to 64 characters of letters, digits, underscore
and hyphen. No dots, no slashes: an engagement name becomes a directory
name, and anything that could climb out of the data directory is
rejected rather than sanitized.

## Where the data lives

Each engagement is a self-contained directory under a base data
directory, `$HOME/.redactproxy` by default or wherever `--data-dir`
points:

```text
$HOME/.redactproxy/
└── engagements/
    └── eng-2026-014/
        ├── tokens.db      # real <-> fake mapping (bbolt), persists across runs
        ├── rules.json     # enabled categories, custom block/allow entries
        ├── upstream.txt   # this engagement's API provider, if not Anthropic
        └── debug.log      # opt-in only, contains REAL values when enabled
```

The directory is created with mode `0700` and the files inside it with
`0600`.

None of this is sent anywhere. There is no telemetry, no sync, no
backup. Deleting the directory deletes the engagement, and the next run
under that name starts from nothing.

> [!WARNING]
> `tokens.db` maps real client values to placeholders in plaintext, and
> `debug.log` contains real values whenever debug logging is on. Treat
> the whole data directory as client data: it belongs under the same
> handling and retention rules as your scan output and your report
> drafts.

Note that this directory defaults to `$HOME`, deliberately outside any
project working folder, so a Claude Code session browsing its own
working directory can't stumble into it.

## The folder marker

Passing `--engagement` also drops a `.redactproxy-engagement` file in
the working directory. Later commands run from that folder read the name
from it, so you only type it once:

```bash
cd ~/engagements/eng-2026-014
redactproxy --engagement eng-2026-014   # first time
redactproxy                                  # every time after
redactproxy rules show                       # and for subcommands
```

Passing a different name overwrites the marker. There is no default
engagement name and no fallback: a command run in a folder with no
marker and no `--engagement` fails rather than guessing, because a
shared default is exactly how two clients end up in one token store.

## Crash safety

`tokens.db` is crash-consistent. A value committed to disk survives an
abrupt kill, not just a clean shutdown. A request in flight when the
process dies fails or times out like any other network interruption;
nothing ends up corrupted or silently mismapped.

This is also why minting a large batch of new values is slower than
re-sending the same content: each value is its own committed write.

## One process per engagement

bbolt lets only one process hold `tokens.db` open at a time. Two
consequences:

- You cannot run two proxies for the same engagement. The second exits
  immediately with a lock error.
- `redactproxy tokens show` and `tokens remove` cannot run while the
  proxy is up for that engagement. Use the proxy's own console instead;
  see [Tokens and the live console](./tokens.md).

`rules.json` is not lock-held that way. It is a plain file, polled every
two seconds, so `rules` commands work fine from another terminal against
a running proxy.

## Running several engagements at once

Start one `redactproxy` per engagement, each on its own `--listen`
address, and point each Claude Code session at the matching port:

```bash
# terminal 1
cd ~/engagements/eng-2026-014 && redactproxy --listen 127.0.0.1:8787

# terminal 2
cd ~/engagements/other-client && redactproxy --listen 127.0.0.1:8788
```

One process serves exactly one engagement. If you use a non-default port
in a folder the wizard configured, re-run the wizard with the matching
`--listen` so the settings file agrees, or the folder's Claude Code will
keep pointing at the old port.

`--listen` must be a loopback address. `127.0.0.1`, `::1` and
`localhost` are accepted; anything else, including the bare `:8787`
shorthand that binds every interface, is refused at startup. This proxy
handles real client data in transit and must never be reachable from the
network.

## Retiring an engagement

There is no "close engagement" command. When the work is done:

```bash
rm -rf ~/.redactproxy/engagements/eng-2026-014
```

That removes the mappings, the rules, and the debug log if there is one.
Also clean up the working folder's `.redactproxy-engagement`,
`CLAUDE.md` note and `.claude/settings.local.json` if the folder itself
is being kept for anything else, and remember that Claude Code's own
transcripts still hold the real values you saw on screen.
