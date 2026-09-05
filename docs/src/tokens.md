# Tokens and the live console

Rules decide what gets tokenized on **future** requests. The token store
holds the mappings **already** minted. They are separate commands
because they answer separate questions.

## Seeing what has been mapped

```bash
redactproxy tokens show
```

```text
tokens for engagement "eng-2026-014"
/home/you/.redactproxy/engagements/eng-2026-014/tokens.db

aws_key (1):
  AKIAIOSFODNN7EXAMPLE                     -> AKIAFAKEA7F002EFA477  (first seen 2026-09-05 11:20:14 IST)
conn_string (1):
  appuser:s3cr3tpw@db.xyzcorp-fixture.internal:5432 -> REDACTED-CREDS-26d467f58e4caccccca3eda7  (first seen 2026-09-05 11:20:14 IST)
domain (1):
  xyzcorp-fixture.internal                 -> tok5198ede8bdbb1ada  (first seen 2026-09-05 11:20:14 IST)
email_local (1):
  rahul.menon@xyzcorp-fixture.internal     -> user-428791a054d2  (first seen 2026-09-05 11:20:14 IST)
ip_network (1):
  10.42.7                                  -> 198.18.0  (first seen 2026-09-05 11:20:14 IST)
mac (1):
  00:1b:44:11:3a:b7                        -> 02:00:00:aa:14:b7  (first seen 2026-09-05 11:20:14 IST)

6 total
```

Entries are grouped by entity type, and what's stored is the part that
actually varies. A domain's entry is the registrable domain and its
org placeholder, with the real public suffix appended outside the
mapping. An IPv4 entry is a /24 network, not a host address, which is
why one entry covers every host you touched on that subnet.

This is the cheapest way to see what the model has actually been shown,
and it needs no debug logging, so nothing gets written to disk in
plaintext beyond what `tokens.db` already holds.

## Undoing one mapping

```bash
redactproxy tokens remove "xyzcorp-fixture.internal"
```

Takes the **real** value, not the placeholder.

> [!IMPORTANT]
> Removing a mapping only forgets that one past mapping. It does not
> stop future redaction. If the value shows up again it gets caught and
> tokenized again, as a **new, different** placeholder, because tokens
> are random rather than derived from the value.
>
> To stop a value being redacted at all, use `rules allow` instead, or
> as well.

The pair that usually makes sense together, for a false positive you
want gone for good:

```bash
redactproxy rules allow "mylab.internal"      # stop redacting it
redactproxy tokens remove "mylab.internal"    # drop the mapping already minted
```

## The lock, and why the console exists

bbolt lets only one process hold `tokens.db` open at a time. So the two
commands above fail while the proxy is running for that engagement:

```text
open token store: the proxy is already running for this engagement, and only one
process can hold tokens.db open at a time; type "show" directly into that
proxy's own terminal instead
```

Stopping the proxy to fix a mapping would drop whatever Claude Code
request is in flight and force it to time out. So the proxy reads
commands from its own stdin instead, operating on the store it already
has open.

## The live console

The terminal running `redactproxy` is interactive. It says so at
startup:

```text
Type here any time without stopping the proxy: "show", "remove <value>", "rules ...", "help".
```

Commands:

```text
show                      every mapping in the store (same as `tokens show`)
remove <real-value>       drop one mapping (same as `tokens remove`)
rules show
rules enable <category>
rules disable <category>
rules block <value>
rules allow <value>
rules remove <value>
help
```

The `rules` commands here call exactly the same code as the standalone
CLI, so they behave identically. Two differences worth knowing:

- The console's `block`/`allow` are the simplified form. Everything
  after the verb is one literal value, so `rules block XYZ Another Corp`
  works without quoting, but there is no `--regex`, `--domain` or
  `--note`. Use the standalone CLI in a second terminal for those.
- `rules` commands would work from another terminal anyway, since
  `rules.json` is not lock-held. They are here for parity. The token
  commands are the ones that genuinely need the console.

The console only activates when stdin is a real terminal. A
`nohup`/systemd/background launch never treats redirected or piped stdin
as commands.

## Reading the log lines

The proxy logs to stderr. Warnings and errors are printed in red when
stderr is a terminal, because the ones that matter are easy to miss
otherwise. The ones worth reacting to:

- `current directory matches a block-list pattern and WILL be sent to
  the upstream API unredacted`: your folder is named after the client.
  See [Known gaps](./security/gaps.md).
- `detection category disabled: real values in this category will NOT be
  redacted`: a detector is off, either from `rules.json` or `--disable`.
- `allowlist category disabled: values normally exempted by this
  allowlist will now be redacted instead`: the inverted case, more gets
  redacted rather than less.
- `rules.json reload failed; keeping previous rules active`: your edit
  is invalid. Run `redactproxy rules validate` to see why. The proxy is
  still running on the last good ruleset.
- `block entry marked "is_domain" doesn't look like a real domain`: a
  hand edit set `is_domain` on something that isn't one. It has fallen
  back to an ordinary literal block entry.
