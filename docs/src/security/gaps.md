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

Claude Code puts its working directory, and a project-memory directory
name derived from it, into the `system` field of every request. That
field is deliberately never scanned: it is Anthropic's own prompt
boilerplate, and blanket-scanning it does more harm than good.

So a folder called `acme-bank-pentest` sends "acme bank" to the model on
every single request, bypassing every block and allow rule no matter how
thorough `rules.json` is. The redaction engine never sees that text.

There is no fix in the tool. There is nothing to tokenize against,
because the path is not part of the body the proxy edits. **Name
engagement folders after an engagement code, never after the client.**

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
(`table.style`, where `.style` is a real suffix) can get tokenized.

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

Rule changes only affect text tokenized from that point on. Adding a
block rule does not scrub a value that already reached the model earlier
in the same conversation. Start a fresh conversation if that matters.

Disabling a category likewise only gates future detection. Anything
already tokenized keeps detokenizing correctly.
