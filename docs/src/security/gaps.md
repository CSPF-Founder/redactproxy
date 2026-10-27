# Known gaps

Detection is regex-based and only ever sees request and response bodies.
These are the gaps that follow from that, written down so they are
decisions you make rather than surprises you discover.

If you find one that isn't here, please open an
[issue](https://github.com/CSPF-Founder/redactproxy/issues). See
[SECURITY.md](https://github.com/CSPF-Founder/redactproxy/blob/main/SECURITY.md)
for the smaller set of findings that go through private reporting
instead.

## Your folder name

**The most important one, and the one redaction cannot fix.**

Claude Code sends your working directory with every request, in more
than one place:

- **The environment details in `messages`**, and, in auto mode, the
  `safeguards` field. Both are scanned, so the path there is redacted
  wherever it matches a detector or one of your `rules block` entries.
- **The project-memory directory name in the `system` field.** Claude
  Code builds it from the path with every `/` and `.` turned into `-`,
  so `~/clients/acme-bank-pentest` becomes
  `-home-you-clients-acme-bank-pentest`. That field is deliberately never
  scanned: it is Anthropic's own prompt boilerplate, and blanket-scanning
  it does more harm than good.

So a folder called `acme-bank-pentest` sends "acme bank" to the model on
every single request, bypassing every block and allow rule no matter how
thorough `rules.json` is. A `rules block` entry covers the copies in
`messages` and `safeguards`, but not the one in `system`, and turning
dots into dashes keeps even a domain-named folder like `acme-bank.com`
from looking like a domain there.

A domain inside a path is also not detected on its own: in
`/home/you/acme-bank.com/notes` it is redacted only once the proxy has
seen `acme-bank.com` somewhere else, in the same request or earlier, or
it is on your block list.

There is no fix in the tool for the `system` copy. **Name engagement
folders after an engagement code, never after the client.**

redactproxy checks for this. If your working directory matches one of
your own block entries, the wizard warns when you set up and the proxy
warns at startup and on every rule reload:

```text
level=WARN msg="current directory matches a block-list pattern and WILL be sent
to the upstream API unredacted..." cwd=/home/you/acme-bank-pentest
```

That check only fires when the folder name matches a rule you already
added. It cannot catch a client name you never told it about.

## Encoded data

A config file piped through `base64`, an `xxd` dump, Terraform state, a
gzipped blob: all of it goes straight through. Encoded text does not
look like a domain, an email, or a credential to a regex.

Decode it locally and look at it first. The `CLAUDE.md` note tells
Claude to decode to a file with `Bash` and read the file back, so the
decoded content gets a normal pass through redaction instead of arriving
unprotected in Claude's own output. See
[Configuring Claude Code](../claude-code.md#the-claudemd-note).

## Names and prose

Only recognizable shapes get detected. Client names, trading names,
product names, codenames, employee names in prose: none of them have a
shape. Add them with `rules block`, which is what the wizard's first
prompt is for.

This is the gap with the widest blast radius after the folder name,
because a company name appears in URL paths, ticket references, code
comments, commit messages and file names, none of which any detector can
recognize.

## Bare apex domains on file-extension TLDs

`.do`, `.ai`, `.rs`, `.sh`, `.py` and friends are not detected as bare
apex domains, because `main.rs` and `logo.ai` are far more often
filenames, and a detector that fires on those costs more than one that
misses an edge case.

Add the client's apex domain with `rules block --domain` when it sits on
one of those. Subdomains and URLs on such a TLD are still detected
normally; it is specifically the bare apex form that is excluded.

## `thinking` blocks

Thinking content is signed by the API. The text and its signature
together are a cryptographic proof the API validates on replay, so any
edit invalidates it and the next request fails.

That means thinking blocks pass through unmodified in both directions.
If a real value reaches the model some other way, the model can restate
it in a thinking block, and that restatement is permanent for the life
of the conversation. **Start a new conversation** if that happens.

## HTTP headers

Forwarded verbatim, never inspected. This is what makes credential
passthrough work, and it means anything carried in a header is not
redacted.

## Claude Code's transcripts and your scrollback

Claude Code stores the real values you saw on screen, because
detokenization happens before the response reaches it. Same for terminal
scrollback. The proxy controls what reaches the provider, not what stays
on your machine.

Handle those under the same rules as the rest of the engagement data.

## Claude Code's non-proxied traffic

Feature flags, token refresh, and several tools do not go through
`ANTHROPIC_BASE_URL` at all. The wizard's settings hardening closes what
configuration can close: the `Artifact` tool (a confirmed leak path
publishing unredacted to claude.ai), Remote Control, and the `WebFetch`
preflight that sends target hostnames to Anthropic directly.

If you didn't run the wizard, the proxy warns at startup and lists
exactly what is missing. See
[Configuring Claude Code](../claude-code.md).

## Over-redaction

The opposite failure, and mostly harmless. The proxy inspects text with
no notion of code structure, so something merely domain-shaped
(`config.live`, where `.live` is a real suffix) can get tokenized.

Two common code shapes are handled: names that look like filenames on a
colliding TLD (`main.rs`, `server.py`, `table.style`), and method calls
whose name is also a TLD (`datetime.now()`, `subprocess.run(...)`,
`m.group(1)`), recognized by the `(` that follows. Plain attribute
access (`config.live`, `user.email`) has no such signal and can still be
tokenized.

Operationally this costs nothing: the real value is substituted back
before anything executes, on every response rather than just the first,
so commands run correctly regardless. Fix it permanently with `rules
allow`, and drop the mapping already minted with `tokens remove`.

## Detection is best-effort, not a guarantee

The detector set covers the shapes that show up in pentest work and is
tested against a realistic corpus (nmap, whois, dig, gobuster,
Metasploit output) plus a false-positive trap corpus. It is not a proof
of coverage.

Two things nobody has built yet, if you want the gaps closed: a local
NER model for prose-shaped PII, and more Windows/AD artifacts (UNC
paths, `domain\username`, LDAP DN components). See CONTRIBUTING.md.

## Where rules do and don't reach back

Claude Code resends the whole conversation on every request, with the
real values in it, and the proxy redacts all of it each time. So a rule
change applies to every request from then on, earlier turns included:

- **Adding a block rule** scrubs the value from every later request,
  earlier turns included. It cannot recall the requests that already
  carried it. Start a fresh conversation if that matters.
- **Disabling a category, or adding an allow entry, un-redacts.** The
  next request sends the matching values from earlier turns in the
  clear, even though earlier requests carried them tokenized. Make
  these changes before a conversation starts, not in the middle of one.
  Placeholders already minted keep detokenizing correctly either way.

Any of these changes also rewrites earlier turns, which the API sees as
an edited history. That costs one prompt-cache miss, and on models that
bind thinking blocks to the conversation (Claude Opus 5.5 and Fable 5.1,
for example) the API may drop or reject the earlier thinking blocks. If
requests start failing after a rule change, start a fresh conversation.
Upgrading redactproxy in the middle of a conversation has the same
effect whenever the new version detects more, or less, than the old one.
