# Troubleshooting

Each heading below is a symptom. Find the one that matches what you are
seeing and work from there.

## `redactproxy: command not found`

`$GOPATH/bin` is not on your `PATH`. Either add it:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

or build locally and use the path directly:

```bash
make build
./bin/redactproxy -h
```

## `no --engagement given, and no .redactproxy-engagement marker found`

You are in a folder that has never been set up. There is deliberately no
default engagement name, because a shared default is how two clients end
up in one token store.

```bash
redactproxy wizard --engagement eng-2026-014   # or
redactproxy --engagement eng-2026-014          # remembered from now on
```

## `invalid engagement name`

Names are 1 to 64 characters of letters, digits, underscore and hyphen.
No dots and no slashes, because the name becomes a directory name.

If a hand-edited `.redactproxy-engagement` file caused this, fix or
delete that file.

## `another redactproxy process is already running for this engagement`

Only one process can hold `tokens.db` open. Either a proxy is already up
for this engagement, or one exited without releasing the lock.

```bash
pgrep -af redactproxy
```

To run two engagements at once, give each its own `--listen` address.
See [Engagements and storage](../engagements.md#running-several-engagements-at-once).

## `tokens show` / `tokens remove` fails with a lock error

Same lock, and expected while the proxy is running. Type the command
into the proxy's own terminal instead:

```text
show
remove xyzcorp-fixture.internal
```

Stopping the proxy would drop whatever Claude Code request is in flight.
See [Tokens and the live console](../tokens.md#the-live-console).

## `--listen is not a loopback address; refusing to bind`

Only `127.0.0.1`, `::1` and `localhost` are accepted. The bare `:8787`
shorthand is refused on purpose: it genuinely binds every interface, and
this proxy handles real client data in transit.

## Claude Code isn't going through the proxy

The proxy prints no traffic and Claude Code behaves normally. Check, in
order:

1. Is the folder's settings file pointing at the right port?
   ```bash
   grep ANTHROPIC_BASE_URL .claude/settings.local.json
   ```
   It must match the address the proxy actually bound, including a
   non-default `--listen`.
2. Is `ANTHROPIC_BASE_URL` set in the shell to something else? A shell
   export overrides nothing here, but a stale one from another
   engagement points you at the wrong proxy. `echo $ANTHROPIC_BASE_URL`.
3. Did you start `claude` from the same folder? The settings file is
   per-folder.

Re-running `redactproxy wizard --listen <addr>` in the folder fixes a
port mismatch.

## The proxy warns that this folder isn't hardened

```text
WARNING: this folder's Claude Code isn't fully hardened against channels that
bypass this proxy entirely...
```

Settings the wizard normally writes are missing, usually because you set
`ANTHROPIC_BASE_URL` by hand or copied an older settings file. The
warning lists exactly what is absent. Run `redactproxy wizard` in the
folder to fix it, or add them by hand from
[Configuring Claude Code](../claude-code.md).

## The proxy warns that my folder name will leak

```text
level=WARN msg="current directory matches a block-list pattern and WILL be sent
to the upstream API unredacted..."
```

Your working directory is named after the client. Claude Code puts its
working directory into a part of every request the proxy deliberately
never scans, so that name reaches the model on every request regardless
of your rules.

There is no fix in the tool. Rename the folder to an engagement code and
work from there. This is the most important entry in
[Known gaps](../security/gaps.md).

## Claude keeps "correcting" the placeholder values

The `CLAUDE.md` note is missing, so the session has no idea what those
strings are.

```bash
redactproxy memory --write ./CLAUDE.md
```

Then start a fresh session. See
[the CLAUDE.md note](../claude-code.md#the-claudemd-note).

## A real value reached the model unredacted

First establish which kind of gap it is:

- **No detectable shape** (a client name, a codename, a project name):
  expected. Add it with `rules block`.
- **Encoded** (base64, hex, an `xxd` dump): expected. Decode locally
  first.
- **A bare apex domain on a `.do`/`.ai`/`.rs`/`.sh` TLD**: expected.
  Use `rules block --domain`.
- **Your folder name**: see above.
- **Anything else**: this is a bug. Open an
  [issue](https://github.com/CSPF-Founder/redactproxy/issues), and
  describe the shape of the value rather than the value itself.

Then, regardless: a value that already reached the model stays in that
conversation, and can be restated permanently in a `thinking` block that
cannot be rewritten. **Start a new conversation.**

## Something innocent is being redacted

Over-redaction. The proxy inspects text with no notion of code
structure, so something merely domain-shaped (`table.style`) can get
tokenized.

It costs nothing operationally, since the real value is substituted back
before anything executes. To stop it:

```bash
redactproxy rules allow "table.style"       # stop redacting it
redactproxy tokens remove "table.style"     # drop the mapping already minted
```

## A rule I added isn't doing anything

Three usual causes:

1. **It only applies going forward.** A value that already reached the
   model earlier in the same conversation is not scrubbed
   retroactively. Start a fresh conversation.
2. **An allow entry is shadowing it.** An allow entry always overrides a
   block entry for the same value. `rules show` flags the pair.
3. **The file didn't reload.** Check the proxy's output for
   `rules.json reload failed; keeping previous rules active`, then run
   `redactproxy rules validate`.

## `rules.json is invalid` on startup

The proxy refuses to start on a broken ruleset rather than running with
less protection than you configured.

```bash
redactproxy rules validate
```

It names the bad entry. A common cause is an invalid regex; remember
that a backslash in a JSON string is written `\\`.

## A category I disabled came back, or one I added disappeared

Category names are reconciled against the running build every time the
file is written, and names it does not recognize are dropped with a note
on stderr. Case matters: `Cloud.AWS` is not `cloud.aws`.

Run `redactproxy rules show` for the exact current names.

## Disabling an `allowlist.*` category made things worse

Working as intended, and the reason those four carry a warning.
Disabling an allowlist category makes **more** get redacted, not less,
so Claude starts seeing tokens where it used to recognize GitHub or a
CDN host. Re-enable it:

```bash
redactproxy rules enable allowlist.wellknown_platforms
```

See [The allowlist categories](./categories.md#the-allowlist-categories).

## The first big scan is slow

Expected. A body that mints hundreds of new values at once, a
full-subnet `nmap` being the obvious case, pays one committed write per
value, which is what makes the store crash-safe. Sending the same output
again costs nothing, because scan results are cached by content hash.

## A request failed instead of going through

By design. Anything on the request path that cannot finish redacting
returns an error rather than forwarding bytes. An unredacted forward is
the one outcome this project treats as worse than a broken request.

Check the proxy's output for the specific reason. A body over
`--max-body-mb` (64 MiB by default) is a common one.

## `--upstream must be an absolute URL` / `must use http or https`

Caught at startup rather than surfacing later as a generic provider
failure. Check `upstream.txt` for the engagement, or the `--upstream`
value you passed. A `REPLACE-ME.example.com` here means the wizard wrote
a manual-provider skeleton you have not filled in yet; see
[Other API providers](../providers.md).

## Increasing verbosity

```bash
redactproxy --debug-level new
```

> [!WARNING]
> Every level above `off` writes real client values to `debug.log` in
> plaintext. Read
> [Debug logging](../security/debug-logging.md) before turning it on,
> and delete the file afterwards.

Try `redactproxy tokens show` first. It answers "what has the model
seen?" without writing anything new to disk.

## Reporting a bug

Include `redactproxy version`. Bug reports, including suspected
redaction leaks, go to the [issue
tracker](https://github.com/CSPF-Founder/redactproxy/issues), and should
not themselves contain client data.
[SECURITY.md](https://github.com/CSPF-Founder/redactproxy/blob/main/SECURITY.md)
lists what to report privately instead.
