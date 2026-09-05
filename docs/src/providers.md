# Other API providers

`--upstream` accepts any base URL that speaks the Anthropic Messages
API. It defaults to real Claude. Each engagement remembers its own
choice in `upstream.txt`, so different client projects can run against
different providers side by side.

> [!NOTE]
> A provider with a genuinely different wire format, such as the
> OpenAI-shaped tools Codex CLI uses, will not work. The detection and
> streaming code is built around the Messages API shape specifically.
> z.ai works because it deliberately exposes an Anthropic-compatible
> endpoint, not because this proxy is provider-agnostic.

## Choosing a provider

Re-run the wizard at any time and answer the provider question
differently to switch an engagement:

```text
Which API is this engagement talking to?
  1) Claude (Anthropic): uses whatever Claude Code is already signed in with
  2) z.ai
  3) Manual / another provider: writes a placeholder skeleton to edit by hand
  (currently: Claude)
```

Whichever you pick, the wizard clears out every env var a *different*
provider choice would have set. Switching in any direction cannot leave
a previous provider's auth token, model name, or tuning variable behind.

Only three choices are offered, deliberately. Claude needs no input at
all, z.ai is a known and verified integration that can be configured
from one API key, and anything else gets a placeholder skeleton rather
than a guess. A wrong guess at which auth header some provider expects
fails silently rather than loudly, which is worse than asking you to
fill it in.

## 1. Claude

The default. redactproxy never asks for an Anthropic credential:
whatever Claude Code is already signed in with, subscription login or
otherwise, reaches the upstream exactly as before, because every client
header is forwarded untouched. The proxy only ever needs to know a URL.

Switching an engagement back to Claude removes `upstream.txt` entirely
rather than leaving an empty file behind.

## 2. z.ai

The wizard asks for one thing, your API key, and fills in the rest from
z.ai's own published configuration:

| Setting | Value |
|---|---|
| Base URL | `https://api.z.ai/api/anthropic` |
| Auth | `ANTHROPIC_AUTH_TOKEN` (Bearer) |
| Main model | `glm-5.2` |
| Background/haiku model | `glm-4.7` |
| `API_TIMEOUT_MS` | `3000000` |
| `CLAUDE_CODE_AUTO_COMPACT_WINDOW` | `1000000` |

The main model resolves `ANTHROPIC_MODEL` plus the opus and sonnet
aliases, so a fresh launch, `/model opus` and `/model sonnet` all land on
it. The background model covers the haiku alias and Claude Code's own
internal background calls.

Leaving the key prompt blank means "don't touch the existing one", not
"clear it". Re-running the wizard on a working z.ai engagement to add a
rule and pressing Enter at the key prompt will not silently delete a
working credential.

## 3. Manual / another provider

Two paths. Answer yes to enter the details now, and the wizard asks for
the base URL (validated as absolute), the API key, which auth header to
send it in, and the model names. Answer no and it writes a deliberately
non-functional skeleton for you to edit:

- `upstream.txt` gets `https://REPLACE-ME.example.com`
- `.claude/settings.local.json` gets `REPLACE-ME` env values

Non-functional on purpose. Starting redactproxy without editing it first
fails loudly rather than quietly talking to whatever
`REPLACE-ME.example.com` happens to resolve to.

Adding another fully-supported provider like z.ai is a code change, not
a config option. See CONTRIBUTING.md's "Adding a provider".

## Why `ANTHROPIC_API_KEY` gets blanked

Picking z.ai or manual sets `ANTHROPIC_API_KEY` to an empty string in
the folder's env block.

Every client header is forwarded untouched. So if you, your shell, or
your user-level Claude settings already have a **real Anthropic API
key** set, and this folder's `ANTHROPIC_BASE_URL` now points at a third
party, that real Anthropic credential would go out as a header on every
request the proxy forwards, straight to that third party.

Blanking the key overrides any inherited value for this project only.
Switching back to Claude clears the override out rather than leaving it
blank, so Claude's own key resolution isn't permanently short-circuited.

## Overriding per run

```bash
redactproxy --upstream https://api.z.ai/api/anthropic
```

An explicit `--upstream` wins over the persisted value for that run
only, the same "CLI flag is a this-run override" convention `--disable`
follows.

The URL must be absolute and must use `http` or `https`. A typo like
`htps://` is caught at startup rather than surfacing later as a generic
"request to provider failed" the first time Claude Code sends something.

## What redactproxy stores

`upstream.txt` holds the bare base URL and never a credential. The
provider's auth token is a Claude Code concern: it's sent as a header
Claude Code already attaches, forwarded through untouched, and it lives
in `.claude/settings.local.json`.
