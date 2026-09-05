# Rules: what to redact

Rules are per-engagement and live in that engagement's `rules.json`.
There are two separate kinds of thing you can name, and they are always
separate commands, never guessed from the argument:

- A **category** is a built-in detector (`cloud.aws`, `network.mac`) or
  a built-in exception (`allowlist.wellknown_platforms`). You
  `enable` or `disable` it.
- A **value** is a literal string or regex you add yourself. You
  `block` or `allow` it.

The commands warn when a value you block happens to match a category
name.

## Changes apply live

`rules.json` is polled every two seconds, so a change from the CLI, the
wizard, the proxy console, or a hand edit reaches a running proxy within
a couple of seconds. No restart, and no dropped in-flight request.

> [!IMPORTANT]
> Rule changes only affect text tokenized from that point on. Adding a
> block rule will not scrub a value that already reached the model
> earlier in the same conversation. If that matters, start a fresh
> conversation. Disabling a category likewise only gates future
> detection; anything already tokenized keeps detokenizing correctly.

If a reload finds `rules.json` invalid, the proxy logs the error and
keeps the previous rules active rather than starting to send unredacted
traffic.

## Blocking a value

```bash
redactproxy rules block "XYZCorp"
```

A block entry matches **case-insensitively as a substring**, so
`XYZCorp` also catches `XYZCorporation`. This is what you
use for everything with no detectable shape: client names, trading
names, product names, internal codenames, project names.

Add a note so the entry is still legible months later:

```bash
redactproxy rules block --note "acquired subsidiary" "XYZAnotherCorp"
```

Or use a regex:

```bash
redactproxy rules block --regex --note "customer VPN range" '10\.42\.\d+\.\d+'
```

### Blocking a domain

By default `rules block` treats its value as opaque text: matched and
redacted, nothing about it preserved. Add `--domain` when the value
really is a domain, and it gets the same structure-preserving treatment
as any domain the tool finds on its own, everywhere that domain turns
up, whether as a subdomain, inside an email address, or in a URL:

```bash
redactproxy rules block --domain "xyzcorp-fixture.internal"
```

The wizard's "Domains" prompt does this for you, so anything entered
there already counts as a domain entry.

Always give the **base** domain: no `www.`, no subdomain. Subdomains,
emails and URLs resolve from the base automatically; it does not work in
the other direction. Entering a subdomain by mistake still works, since
it resolves back to the base, but the CLI points it out.

Internal-only names work too: an Active Directory forest, a private
naming scheme, anything that will never appear on a public suffix list.
`--domain` takes your word for it and only checks that the value is
syntactically a hostname. A URL, an email address or an arbitrary string
still gets added, but as an ordinary literal value, with a warning
explaining why.

This flag exists partly because of a deliberate detection gap: bare
apex domains on file-extension TLDs (`.do`, `.ai`, `.rs`, `.sh`, `.py`
and friends) are not detected automatically, because `main.rs` and
`logo.ai` are far more often filenames. Use `--domain` for those.

## Allowing a value

```bash
redactproxy rules allow "mylab.internal"
```

An allow entry matches the **exact** value only, case-insensitively.
That is deliberately narrower than `block`: an allow entry takes
protection away, so it should be as specific as possible.

Use it for your own infrastructure, your own testing tooling, and for
false positives you want to stop seeing.

> [!WARNING]
> An allow entry always overrides a block entry for the same value, with
> no exception. Because a value in both lists would never mean anything,
> `block` and `allow` refuse to add a value already covered by the other
> list, and `rules show` flags any existing contradictory pair left over
> from a hand edit.

## Removing an entry

```bash
redactproxy rules remove "XYZCorp"
```

Removes the value from the block list, the allow list, or both,
whichever it is in. It says which.

This changes what gets redacted in future. It does not delete a mapping
already minted; for that see [Tokens](./tokens.md).

## Turning detectors on and off

```bash
redactproxy rules disable india_pii.pan
redactproxy rules enable india_pii.pan
```

Naming a bare category toggles every subcategory under it in one call:

```bash
redactproxy rules disable india_pii     # both aadhaar and pan
```

`rules show` lists every category with its current state and
description. The full list is in
[Detector categories](./reference/categories.md).

Disabling a detector is a real reduction in protection, so the proxy
logs a warning line for it at startup and on every reload, rather than
letting it scroll by as routine output.

### The allowlist categories are inverted

Four categories work backwards from the rest:

| Category | Exempts |
|---|---|
| `allowlist.wellknown_platforms` | github.com, npmjs.com, stackoverflow.com and similar |
| `allowlist.web_infrastructure` | CDN, font, analytics and widget hosts |
| `allowlist.security_testing_services` | Burp Collaborator, interact.sh, webhook.site and similar |
| `allowlist.third_party_saas` | specific vendor products a client integrates with |

These exist so Claude can recognize infrastructure that carries no
client identity. It is useful for Claude to know that a domain is
GitHub, or that a callback host is Burp Collaborator and therefore your
own tooling rather than the client's.

**Disabling one of these makes more get redacted, not less.** `rules
show` flags them with a warning for exactly that reason. Most
engagements should leave all four enabled.

`allowlist.third_party_saas` is the weakest judgment call of the four,
since seeing a vendor domain does reveal something about the client's
tech stack, just not the client's identity. It is a separate category so
you can disable that one alone on an engagement where even tech-stack
fingerprinting should stay hidden.

## Disabling a category for one run

```bash
redactproxy --disable cloud.aws,network.mac
```

This merges with `rules.json`'s own disabled list rather than replacing
it, and is not persisted. It stays in effect for the life of that
process, including across rule reloads. For a change that outlives the
run, use `rules disable`.

## Reviewing what's active

```bash
redactproxy rules show        # categories, block list, allow list
redactproxy rules validate    # check rules.json without starting the proxy
```

`rules validate` is the one to run after hand-editing the file. It
reports invalid entries, and warns about category names it does not
recognize, which are usually a case typo.

## Editing rules.json by hand

Supported, and the file is written to be self-documenting: every known
category appears in it with its description and, where relevant, its
warning. See [rules.json](./reference/rules-json.md) for the format, and
run `rules validate` afterwards.
