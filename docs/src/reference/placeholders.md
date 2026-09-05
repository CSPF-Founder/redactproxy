# Placeholder shapes

Every placeholder is designed so it can never be mistaken for, or
collide with, a real value. Where the structure of a value carries
context that is useful but not identifying, that structure is preserved.

This is the same material `redactproxy memory` puts into an engagement's
`CLAUDE.md`, in more detail. If you are wondering whether a
strange-looking string in a session is a placeholder, this is the page.

## Structure-preserving shapes

These keep part of the real value, because that part is useful to reason
with and does not identify anyone.

| Value | Placeholder | What survives |
|---|---|---|
| Domain | `tok<16 hex>.<real suffix>` | the real public suffix, and any subdomain |
| Email | `user-<12 hex>@<domain token>` | the shape, and which org the domain belongs to |
| IPv4 | `198.18.<n>.<real host octet>` | the host octet, so hosts stay distinguishable |
| IPv6 | `fd00:c0de:<32 bits>:<real interface ID>` | the 64-bit interface ID |
| NANP phone | `<area code>-555-01<2 digits>` | that it is a NANP number |
| International phone | `<real country code> 555-<4 digits>` | the real country calling code |

A worked example:

```text
mail.xyzcorp-fixture.internal  ->  mail.tok5198ede8bdbb1ada.internal
rahul.menon@xyzcorp-...        ->  user-428791a054d2@tok5198ede8bdbb1ada.internal
10.42.7.19                     ->  198.18.0.19
```

The subdomain, the shared org token across hostname and email, and the
host octet all survive. That is what lets Claude reason about
relationships between hosts without ever seeing whose they are.

### Why these ranges

- **`198.18.0.0/15`** is RFC 2544 benchmarking space, reserved for
  network interconnect device testing and never publicly routed. It is
  used deliberately *instead* of an RFC 1918 range, because internal
  engagements routinely target real `10.x`, `172.16-31.x` and
  `192.168.x` addresses, and the token space must not overlap real
  targets.
- **`fd00::/8`** is RFC 4193 Unique Local Address space, never a real
  global address.
- **`555-01XX`** is the NANP exchange reserved for fictional use under
  every area code, the same convention film and TV rely on. Placeholder
  numbers draw from a spread of real geographic area codes, so the token
  space is large enough for an engagement cataloging hundreds of
  extensions.

> [!IMPORTANT]
> A placeholder IP is **not test data**. The range looks reserved
> because it was chosen to be unmistakable, not because the address it
> stands in for is any less real or less sensitive. Treat it exactly
> like a genuine external target in your reasoning.

## Credential shapes

These keep the vendor prefix, so the **type** of credential stays
recognizable, and replace everything after it. Knowing you found an AWS
key is useful; knowing which one is not.

| Value | Placeholder prefix |
|---|---|
| AWS access key ID | `AKIAFAKE` |
| AWS secret access key | `tok-aws-secret-` |
| GitHub token | `ghp_FAKE` |
| GitLab token | `glpat-FAKE` |
| Bitbucket | `ATBBFAKE` |
| Slack token | `xoxb-9999999999-9999999999-FAKE` |
| Slack webhook | `REDACTED-WEBHOOK-` |
| Stripe | `sk_live_FAKE` |
| Razorpay | `rzp_live_FAKE` |
| Google API key | `AIzaSyFAKE` |
| npm | `npm_FAKE` |
| DigitalOcean | `dop_v1_FAKE` |
| Cloudflare | `cfat_FAKE` |
| Azure storage key | `REDACTED-AZUREKEY-` |
| Artifactory | `AKCpFAKE` |
| Docker Hub | `dckr_pat_FAKE` |
| CircleCI | `CCIPAT_FAKE` |
| Terraform | `FAKE00000000.atlasv1.FAKE` |
| Snyk | `deadfake-dead-fake-snyk-` |
| Vault | `hvs.FAKE` |
| Twilio SID | `ACFAKE` |
| SendGrid | `SG.FAKE` |
| OpenAI | `sk-FAKE` |
| Anthropic | `sk-ant-api03-FAKE` |
| JWT | `eyJredacted...` |
| Opaque bearer token | `tok-bearer-` |
| Connection string | `REDACTED-CREDS-` |
| PEM private key | `-----BEGIN REDACTED PRIVATE KEY-----` |

`FAKE` is the anchor, and it is not decorative: `K` is not a valid hex
digit, so `FAKE` can never appear inside a real random-hex secret. AWS
in particular never allocates `FAKE` as the four characters after
`AKIA`, so the placeholder is structurally non-issuable rather than just
visually distinct.

## Other shapes

| Value | Placeholder | Why it cannot be real |
|---|---|---|
| MAC address | `02:00:00:xx:xx:xx` | `02` sets IEEE 802's locally-administered bit, so it can never be a real vendor OUI |
| Password hash | `FAKEHASH<hex>` | `K`, `H` and `S` are not hex digits |
| Aadhaar | `0000 <4 digits> <4 digits>` | UIDAI never issues a number starting with 0 or 1 |
| PAN | `FAKEP<4 digits><letter>` | `E` is not a valid holder-type code in position 4 |
| AD machine account | `FAKEHOST<hex>$` | keeps the `$` suffix that makes it recognizable |
| GPP cpassword | `FAKE-CPASSWORD-<hex>` | contains `-`, which is not in the base64 alphabet, so it can never decrypt |
| Custom block entry | `tok-blocked-<hex>` | opaque by design |
| itsdangerous token | `tok-signed-<hex>` | opaque by design |

## Properties worth relying on

**Stable.** The same real value always maps to the same placeholder for
the life of the engagement.

**Random, not derived.** Placeholders come from `crypto/rand`. There is
nothing in one to reverse, and no information about the value it stands
for. This is also why `tokens remove` followed by re-encountering the
value produces a *different* placeholder.

**Never guess or reconstruct one.** Reproduce a placeholder exactly,
copied from its most recent literal appearance. A token retyped from
memory, fragmented into a bare subdomain plus suffix, or replaced with a
hand-typed `<angle bracket>` stand-in silently breaks something
downstream: an `Edit`'s `old_string` stops matching the real file, or a
report line traces back to nothing.

**An unfamiliar placeholder is not a bug.** It is either a token doing
its job, or an over-redaction of something merely domain-shaped
(`table.style`, where `.style` is a real suffix). Either way the real
value is substituted before execution, on every response rather than
just the first, so the command runs correctly regardless. Verify against
the real filesystem with `Bash` or `Read` rather than reasoning around
the token.

## Capacity limits

Two placeholder spaces are counter-allocated rather than random, and one
of them is finite:

- **IPv4 networks: 256 per engagement.** Each distinct real /24 gets
  one. An engagement touching more than 256 distinct /24 networks would
  be unusual, but if it happens the request that hits the 257th fails
  closed rather than reusing a placeholder.
- **IPv6 networks: about 4.3 billion per engagement.** No realistic
  exhaustion risk.

Everything else is drawn at random from a space large enough that
collisions are handled by retry rather than being a design concern.
