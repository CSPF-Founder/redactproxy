# Your first engagement

This walks through setting up one engagement end to end. It assumes
`redactproxy` is on your `PATH`; see [Install](./install.md) if it
isn't.

## Pick a folder

Work in one folder per client project. Everything below is per-folder:
the engagement marker, the Claude Code settings, the `CLAUDE.md` note.

> [!WARNING]
> **Don't name the folder after the client.** Claude Code puts its own
> working directory into a part of every request this proxy deliberately
> never scans, so a folder called `acme-bank-pentest` sends "acme bank"
> to the model on every single request, no matter what your rules say.
> Use an engagement code. This is the one leak redaction cannot close;
> see [Known gaps](./security/gaps.md).

```bash
mkdir ~/engagements/eng-2026-014
cd ~/engagements/eng-2026-014
```

## Run the wizard

```bash
redactproxy wizard --engagement eng-2026-014
```

The wizard is a normal, separate invocation of the binary. It doesn't
need a running proxy, and you can re-run it at any time, including
mid-session against an engagement whose proxy is already up.

It asks four things.

### 1. Customer name variations

Names have no detectable shape, so nothing finds them automatically.
This is where you list them: the legal name, the trading name,
abbreviations, product names, internal codenames. One per line, blank
line to move on.

```text
Customer name variations (legal name, abbreviations, product names, one per line, blank line to move on):
> XYZCorp
> XYZ Corporation
>
```

These become case-insensitive **substring** matches, so `XYZCorp`
also catches `XYZCorporation`.

### 2. Domains

```text
Domains (one per line, blank line to finish):
> xyzcorp-fixture.internal
>
```

Give the base domain only: no `www.`, no subdomain. Everything else
resolves from it automatically, so one entry covers subdomains, email
addresses at that domain, and URLs. Entries from this prompt get the
structure-preserving domain treatment described in
[Rules](./rules.md#blocking-a-domain), the same as
`rules block --domain`.

Right after this prompt the wizard checks the folder you are standing in
against the rules you just entered. `~/engagements/eng-2026-014` doesn't
contain any of them, so nothing is printed here and the wizard moves
straight on to the next question.

If the folder were named after the client, say
`~/clients/xyzcorp-pentest`, its name would contain a value you just
asked to have redacted, and the wizard would print this instead:

```text
WARNING: this folder's path ("/home/you/clients/xyzcorp-pentest") currently matches your own block-list pattern "(?i)xyzcorp":
it WILL be sent unredacted on every request from here. Consider a different folder name.
```

That is the folder-naming problem from the top of this page, caught
after the fact. Renaming the folder is the only fix; no rule can cover
it. See [Known gaps](./security/gaps.md).

### 3. Which API this engagement talks to

```text
Which API is this engagement talking to?
  1) Claude (Anthropic): uses whatever Claude Code is already signed in with
  2) z.ai
  3) Manual / another provider: writes a placeholder skeleton to edit by hand
  (currently: Claude)
> 1
```

Choose 1 unless you have a reason not to. redactproxy never asks for an
Anthropic credential: Claude Code's own authentication is forwarded
through untouched. See [Other API providers](./providers.md) for 2 and
3.

### 4. Two conveniences for this folder

```text
Add a CLAUDE.md note explaining the redaction placeholders (./CLAUDE.md)? [Y/n] y
appended the redaction-placeholder note to ./CLAUDE.md

Configure Claude Code in this folder to use the proxy automatically (writes ./.claude/settings.local.json)? [Y/n] y
wrote ./.claude/settings.local.json
```

Say yes to both. The first teaches Claude what the placeholder values
mean so it treats them as values to reuse rather than typos to correct.
The second points Claude Code at the proxy and closes several channels
that bypass the proxy entirely. Both are covered in
[Configuring Claude Code](./claude-code.md).

If `.claude/settings.local.json` already exists, the wizard prints the
current file, lists exactly what it would change, and asks before
writing. It merges; it never overwrites.

## Start the proxy

In the same folder:

```bash
redactproxy
```

```text
level=INFO msg="rules loaded" disabled_count=0 block_entries=2 allow_entries=0
level=INFO msg="redactproxy listening" addr=127.0.0.1:8787 engagement=eng-2026-014 ...

redactproxy is running. This folder's Claude Code is already configured to use it
(.claude/settings.local.json), so just run `claude` here, no export needed.

Type here any time without stopping the proxy: "show", "remove <value>", "rules ...", "help".
```

No `--engagement` needed: the wizard left a `.redactproxy-engagement`
marker in this folder and every later command run from here picks the
name up from it.

Leave this terminal open. It is also a live console: see
[Tokens and the live console](./tokens.md#the-live-console).

## Start Claude Code

In a second terminal, in the same folder:

```bash
claude
```

That's it. Claude Code reads `ANTHROPIC_BASE_URL` from this folder's
settings file and its traffic now goes through the proxy.

## Without the wizard

Skipping the wizard is fine. You lose the `CLAUDE.md` note and the
settings hardening, and have to point Claude Code at the proxy yourself:

```bash
redactproxy --engagement eng-2026-014 &
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

`ANTHROPIC_BASE_URL` only applies to the shell you set it in. Close that
terminal when you're done with the engagement, or `unset` it, so an
unrelated session later doesn't go through the same proxy by accident.

## Check it's working

Ask Claude something that mentions a client value and watch what comes
back. Or, in the proxy's own terminal, type:

```text
show
```

That prints every mapping minted so far, real value on the left and
placeholder on the right.

## What next

- [How redaction works](./concepts.md) for what's actually happening.
- [Rules: what to redact](./rules.md) to add values mid-engagement.
- [Known gaps](./security/gaps.md) before you trust it with real client
  data. This is the important one.
