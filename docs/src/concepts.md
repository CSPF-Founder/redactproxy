# How redaction works

## The round trip

```mermaid
sequenceDiagram
    participant CC as Claude Code
    participant RP as redactproxy
    participant API as api.anthropic.com

    CC->>RP: request (real PII)
    Note over RP: find text fields, tokenize:<br/>real value -> stable fake
    RP->>API: request (tokens only)
    API-->>RP: response (tokens)
    Note over RP: detokenize:<br/>fake -> real
    RP-->>CC: response (real PII)
```

Two directions, and the order is what makes it usable:

**Outbound.** The proxy parses the request body, finds the strings that
carry content, runs the detectors over them, and replaces every real
value it recognizes with a placeholder. The upstream API sees only
placeholders.

**Inbound.** Every placeholder in the reply is swapped back to its real
value before the reply reaches Claude Code. So when Claude writes a
`Bash` command against a placeholder hostname, Claude Code receives the
real hostname and runs against real infrastructure.

That substitution happens on **every** response, not just the first. A
command Claude re-issues ten turns later still resolves correctly, and
Claude never has to have seen the real value to write a command that
works against it.

## A worked example

Some `nmap` and config-dump output, as Claude Code would send it:

```text
Nmap scan report for mail.xyzcorp-fixture.internal (10.42.7.19)
Host is up (0.021s latency).
443/tcp open  ssl/http nginx
Found admin contact: rahul.menon@xyzcorp-fixture.internal
MAC Address: 00:1b:44:11:3a:b7 (Dell)
Recovered from the app config file:
  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
  DATABASE_URL=postgres://appuser:s3cr3tpw@db.xyzcorp-fixture.internal:5432/prod
Reference doc: https://github.com/xyzcorp/deploy-notes
```

What the model actually receives:

```text
Nmap scan report for mail.tok5198ede8bdbb1ada.internal (198.18.0.19)
Host is up (0.021s latency).
443/tcp open  ssl/http nginx
Found admin contact: user-428791a054d2@tok5198ede8bdbb1ada.internal
MAC Address: 02:00:00:aa:14:b7 (Dell)
Recovered from the app config file:
  AWS_ACCESS_KEY_ID=AKIAFAKEA7F002EFA477
  DATABASE_URL=postgres://REDACTED-CREDS-26d467f58e4caccccca3eda7/prod
Reference doc: https://github.com/xyzcorp/deploy-notes
```

Read that side by side, because nearly every design decision is visible
in it:

- The `mail.` subdomain survives, and the same org placeholder appears
  in both the hostname and the email address, so the relationship
  between them is intact.
- The host octet `.19` survives; only the /24 network changed.
- The AWS key still looks like an AWS key, so Claude knows what it found.
- The connection string collapses to one opaque placeholder, because
  the whole credential span is sensitive.
- The `nginx` version banner, the latency, the port, and the Dell OUI
  comment are untouched. They aren't client-identifying.
- `github.com` is untouched, because it's on the built-in allowlist.
- **`xyzcorp` in the GitHub URL path is untouched**, because a
  company name in a path has no detectable shape. That is exactly what
  the wizard's "Customer name variations" prompt is for, and the reason
  it's the first question it asks.

## Stability

A given real value always maps to the same placeholder for the life of
an engagement. This is not incidental; it is the reason the tool is
usable at all.

Claude can still reason that `tok1a2b3c4d5e6f7890.com` and
`mail.tok1a2b3c4d5e6f7890.com` belong to the same organization, that a
finding on one host relates to a finding on another, that an email
address belongs to the same company as a web server. It just never
learns which organization that is.

Mappings live in `tokens.db` in the engagement's own directory. They
persist across restarts, so the placeholder Claude saw yesterday is
still the same one today.

## Structure is preserved where it helps

Placeholders are not opaque blobs when the structure carries useful,
non-identifying context:

- A domain keeps its real public suffix. `xyzcorp-fixture.co.uk`
  becomes `tok<hex>.co.uk`, so country and sector context survives.
- An IPv4 address keeps its real host octet, and only the /24 network is
  replaced. Hosts that were adjacent stay adjacent.
- An email keeps its shape, with a placeholder local part at a
  placeholder domain.
- A credential keeps its vendor prefix. An AWS key still looks like an
  AWS key (`AKIAFAKE...`), so Claude knows what kind of secret it is
  looking at without seeing the secret.

Every placeholder shape is documented in
[Placeholder shapes](./reference/placeholders.md). All of them are
structurally guaranteed never to collide with a real value: the fake
IPv4 range is RFC 2544 benchmarking space, fake phone numbers use the
reserved 555-01XX exchange, fake credentials embed a `FAKE` marker in a
position where real ones can only carry hex.

## What gets scanned

Only the content-carrying strings inside a Messages API body: the
`messages` array in a request, and the `content` array in a response.
That is where operator and tool-output text lives.

Deliberately not scanned:

- The top-level `system` field. It is Claude Code's own prompt
  boilerplate, and this is where the working-directory leak in
  [Known gaps](./security/gaps.md) comes from.
- `thinking` and `redacted_thinking` blocks. The text and its signature
  together are a cryptographic proof the API validates on replay, so any
  edit makes the next request fail.
- Server-executed tool blocks (web search, code execution). These run on
  Anthropic's own infrastructure and never carry local client data.
- Images and documents, which are binary payloads rather than text.

MCP tool calls and results **are** scanned. An MCP server is local
infrastructure you control, and its output is exactly the kind of real
client data this proxy exists to keep off the wire.

The rewrite is surgical: only the matched spans change, and every other
byte, including JSON key order, is preserved. That matters because
Claude Code's prompt-cache breakpoints are a prefix match on exact
bytes, so a reserialized body would silently destroy caching.

## Detection is regex-based

There is no model in the loop, no network call, and no learning. A
detector is a pattern plus a validation step, and the full set is in
[Detector categories](./reference/categories.md).

The consequences are worth internalizing:

- **Shapes get caught, prose does not.** An IP, an email, an API key, a
  domain: caught. A client's name, a codename, a project name: not
  caught, because there is no shape to match. That is what
  [rules](./rules.md) are for, and why the wizard asks for names first.
- **Encoded data passes straight through.** A `.env` piped through
  `base64` doesn't look like anything to a regex. Decode it locally
  first.
- **False positives happen.** The proxy inspects text and has no notion
  of code structure, so something merely domain-shaped (`table.style`,
  where `.style` is a real suffix) can occasionally get tokenized. This
  is harmless in operation, since the real value is substituted back
  before anything executes, and `rules allow` fixes it permanently.

## Fail closed

If the proxy cannot finish redacting a request, it returns an error
rather than forwarding bytes. An unredacted forward is the one outcome
this project treats as worse than a broken request. A malformed body, a
detector that errors, a token store that can't commit: all of them fail
the request instead of passing it through.

## Cost

Scan results are cached by content hash, so you pay per distinct string,
once. Conversation history is resent every turn, so most of a typical
request is cache hits.

The exception is a body that mints hundreds of new values at once, a
full-subnet `nmap` the first time you run it being the obvious one. Each
value is its own committed write, which is what makes the store
crash-safe and what turns milliseconds into seconds. Sending the same
output again costs nothing.
