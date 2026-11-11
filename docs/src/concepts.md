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
an engagement.

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

In auto mode, Claude Code also sends a `safeguards` field so the API can
review each tool call before it runs. Its context repeats local details
the conversation already describes: the working directory, the git
remote, your permission allow and deny rules, and the auto-mode notes
from your settings. Every text value in it is scanned with the same
placeholders as the conversation, so the server's review sees the same
redacted values the model does. Only the field's type tags and the
tool-call IDs it refers to are left as they are. The review's verdicts
come back in `safeguard_results`, which the proxy returns unchanged.

Deliberately not scanned:

- The top-level `system` field. It is Claude Code's own prompt
  boilerplate, and the folder-name leak in
  [Known gaps](./security/gaps.md) comes from the project-memory
  directory name it carries.
- `thinking` and `redacted_thinking` blocks. The text and its signature
  together are a cryptographic proof the API validates on replay, so any
  edit makes the next request fail.
- Server-executed tool blocks (web search, web fetch, code execution,
  server-side tool search). These run on Anthropic's own infrastructure
  and never carry local client data.
- Server-side `compaction` blocks. Like thinking, the summary is signed
  and must go back byte-for-byte, and it was written from the already
  redacted conversation.
- Images and documents, which are binary payloads rather than text.

A body is scanned whenever it is JSON, whatever its `Content-Type`
header says; one that starts like JSON but is malformed is blocked.

Message Batches are covered as well, for other clients you point at the
proxy (Claude Code does not use them): each entry of a create-batch body
is scanned like a normal request, and each line of the batch's results
has its real values restored.

The definitions of MCP tools in the `tools` array are scanned too: the
tool's description, and the descriptions, titles, defaults, enum values
and examples in its input schema. An MCP server is yours, and its
descriptions often name client hosts. Tool names, property names and
the rest of the schema are left as they are, and the definitions of
Claude Code's built-in tools are never touched. The redacted text is
the same on every request, so the prompt cache is not affected, and an
enum value the model picks is restored before your MCP server sees it.

MCP tool calls and results **are** scanned, unlike the server-executed
blocks above. What separates them is where the tool runs: web search and
code execution run on Anthropic's own infrastructure, while an MCP
server is local infrastructure you control (a database query tool, an
internal API client, a custom tool of your own), and its output is
exactly the kind of real client data this proxy exists to keep off the
wire.

The proxy sits between Claude Code and the API, never between Claude
Code and your MCP server.
The local connection to that server is not intercepted, not blocked, and
not modified. What gets scanned is the copy of the exchange carried in
the API body: an `mcp_tool_result` is tokenized on the way out, and an
`mcp_tool_use` in a response is detokenized before Claude Code executes
it, so the MCP server itself receives the real values, exactly as `Bash`
does. The same goes for `search_result` blocks inside a tool result: a
local search tool's titles, URLs and snippets are scanned like any other
tool output.

A few block types are protocol markers with no content of their own, and
pass through unchanged: `tool_reference` (Claude Code loading a deferred
tool through tool search), `tool_addition` and `tool_removal` (an MCP
server connecting or disconnecting mid-session), and `fallback` (the API
switched to another model after a refusal). Each is accepted only in its
exact known shape; one carrying any other field is treated as unknown.

Switching models never needs anything from the proxy, whether by `/model`
or by a refusal fallback: placeholders are stable for the engagement, so
the new model sees the same ones. If a refusal cuts a streamed response
off mid-block, the partial text is still restored in full, so the copy
Claude Code sends back when it continues on a fallback model matches
what the API produced.

The rewrite is surgical: only the matched spans change, and every other
byte, including JSON key order, is preserved. That matters because
Claude Code's prompt-cache breakpoints are a prefix match on exact
bytes, so a reserialized body would silently destroy caching.

## Detection is regex-based

There is no model in the loop, no network call, and no learning. A
detector is a pattern plus a validation step, and the full set is in
[Detector categories](./reference/categories.md).

What follows from that:

- **Shapes get caught, prose does not.** An IP, an email, an API key, a
  domain: caught. A client's name, a codename, a project name: not
  caught, because there is no shape to match. That is what
  [rules](./rules.md) are for, and why the wizard asks for names first.
- **Encoded data passes straight through.** A `.env` piped through
  `base64` doesn't look like anything to a regex. Decode it locally
  first.
- **False positives happen.** The proxy inspects text and has no notion
  of code structure, so something merely domain-shaped (`config.live`,
  where `.live` is a real suffix) can occasionally get tokenized. Method
  calls like `datetime.now()` and filename-like names like `server.py`
  are recognized and left alone. The rest is harmless in operation,
  since the real value is substituted back before anything executes,
  and `rules allow` fixes it permanently.

## Fail closed

If the proxy cannot finish redacting a request, it returns an error
rather than forwarding bytes. An unredacted forward is the one outcome
this project treats as worse than a broken request. A malformed body, a
detector that errors, a token store that can't commit: all of them fail
the request instead of passing it through. So does a content block of a
type the proxy doesn't recognize, such as one from a newer API feature:
the request is refused with an error naming the type, rather than
forwarded with that block unscanned.

## Cost

Scanning a body is the expensive part, so results are cached by content
hash: any given string is scanned once, however many times you send it.
Claude Code resends the whole conversation every turn, so after the
first turn most of a request is cache hits and costs close to nothing to
redact.

Two things are not cached.

The first is minting a token for a value the store has never seen. Each
new value is its own committed write, which is what lets the store
survive being killed at any point without losing the mapping for a value
already sent to the model. A body that discovers hundreds of new values
at once, the first run of a full-subnet `nmap` being the obvious case,
pays all of those writes in one request and can visibly stall it.
Sending the same output again is free, because by then every value is
known and the scan itself is cached.

The second is the response direction. Detokenizing scans for
placeholders every time, with no equivalent cache, because the model can
return known placeholders in any arrangement it likes. That cost scales
with response size rather than with how much you have redacted so far.
