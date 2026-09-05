# rules.json

One per engagement, at
`$HOME/.redactproxy/engagements/<name>/rules.json`. It holds which
detector categories are enabled and any custom block and allow entries.

Hand-editing is supported and the file is written to be
self-documenting: every known category appears in it with its
description and, where relevant, its warning. Run
`redactproxy rules validate` afterwards.

## Shape

```json
{
  "categories": {
    "cloud.aws": {
      "enabled": true,
      "description": "AWS access key IDs (AKIA/ASIA-prefixed) and secret access keys ..."
    },
    "allowlist.wellknown_platforms": {
      "enabled": true,
      "description": "Exempts well-known public dev platforms (github.com, ...)",
      "warning": "Disabling this makes MORE get redacted, not less: ..."
    }
  },
  "block": [
    {
      "value": "XYZCorp",
      "regex": false,
      "note": "wizard 2026-09-05, customer name"
    },
    {
      "value": "xyzcorp-fixture.internal",
      "regex": false,
      "note": "wizard 2026-09-05, domain",
      "is_domain": true
    }
  ],
  "allow": [
    {
      "value": "mylab.internal",
      "regex": false,
      "note": "our own lab"
    }
  ]
}
```

## `categories`

A map of category name to state.

| Field | Type | Meaning |
|---|---|---|
| `enabled` | bool | whether the detector runs |
| `description` | string | maintained by redactproxy; edits are overwritten |
| `warning` | string | present on the inverted `allowlist.*` categories |

The map is reconciled against the running build every time redactproxy
writes the file: missing categories are added with their defaults, and
names the build does not recognize are dropped, with a note on stderr:

```text
note: rules.json had a category "Cloud.AWS" this build doesn't recognize, so it
was dropped. If it was meant to match an existing category, check for a typo
(case matters) ...
```

Case matters. That note exists because a silently-reverted typo on a
file whose whole premise is "safe to hand-edit" is exactly the trap
worth flagging.

`rules validate` warns about unrecognized names without writing
anything, which makes it the safe way to check an edit before it takes
effect.

## `block` and `allow`

Arrays of entries.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `value` | string | required | the literal string or regex |
| `regex` | bool | `false` | treat `value` as a regular expression |
| `note` | string | omitted | free text explaining why the entry exists |
| `is_domain` | bool | omitted | block entries only; give the value structure-preserving domain treatment |

**Block** entries match case-insensitively as a substring.
**Allow** entries match the exact value only, case-insensitively.

An allow entry always overrides a block entry for the same value, with
no exception. The CLI refuses to create such a pair; `rules show` flags
one left over from a hand edit:

```text
Block:
  - [string] "mylab.internal"  ⚠ has NO effect: an Allow entry for the same value always overrides Block
```

### `is_domain`

```json
{"value": "xyzcorp-fixture.internal", "regex": false, "is_domain": true}
```

Equivalent to `rules block --domain`. The value is treated as a real
domain and tokenized with structure preserved, everywhere it appears:
bare, as a subdomain, inside an email address, or in a URL. Without it,
the entry is opaque text matched literally.

Give the **base** domain, no `www.` and no subdomain.

A hand-edited file gets no interactive warning, so a nonsensical
`is_domain` (set on a URL by accident, say) is handled quietly rather
than breaking anything: it falls back to an ordinary literal block
value, and redactproxy logs a one-time warning at startup or reload:

```text
level=WARN msg="block entry marked \"is_domain\" doesn't look like a real
domain; treating it as an ordinary literal block value instead" value=...
```

### Regex entries

```json
{"value": "10\\.42\\.\\d+\\.\\d+", "regex": true, "note": "customer VPN range"}
```

Go's `regexp` syntax (RE2). Remember JSON string escaping: a regex
backslash is written `\\`.

An invalid pattern fails `rules validate`, and on a live reload the
proxy logs the error and **keeps the previous rules active** rather than
starting to send unredacted traffic.

## Concurrency

Every command that modifies the file does the whole load-modify-save
cycle under a lock, so two concurrent `rules` commands cannot silently
discard each other's change. A running proxy takes the same lock when it
reconciles categories at startup.

`rules.json` is not held open the way `tokens.db` is. It is polled every
two seconds, so edits from any source reach a running proxy within a
couple of seconds with no restart.

## What is not in this file

- **Minted mappings** live in `tokens.db`. See [Tokens](../tokens.md).
- **The upstream provider** lives in `upstream.txt`, one bare URL and
  never a credential. See [Other API providers](../providers.md).
- **Claude Code settings** live in the working folder's
  `.claude/settings.local.json`. See
  [Configuring Claude Code](../claude-code.md).
