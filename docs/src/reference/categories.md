# Detector categories

There are 44 detector categories. Each can be enabled or disabled per
engagement:

```bash
redactproxy rules disable india_pii.pan     # one subcategory
redactproxy rules disable india_pii         # every subcategory under it
redactproxy rules enable  india_pii.pan
```

The authoritative list for the build you are running is
`redactproxy rules show`, which prints exactly these descriptions from
the same source. This page is that list, grouped.

> [!WARNING]
> The four `allowlist.*` categories work backwards from the rest.
> Disabling one makes **more** get redacted, not less. See
> [The allowlist categories](#the-allowlist-categories) below.

## Full list

### `ai_providers`

| Category | Detects |
|---|---|
| `ai_providers.anthropic` | Anthropic API keys. |
| `ai_providers.openai` | OpenAI API keys. |

### `allowlist`

| Category | Exempts from redaction |
|---|---|
| `allowlist.security_testing_services` | Out-of-band/security-testing callback services (burpcollaborator.net, interact.sh, webhook.site, etc.); these are the tester's OWN tooling, never the client's. |
| `allowlist.third_party_saas` | Specific third-party vendor products a client's own site actively integrates with (razorpay.com, zoho.in, engati.ai, etc.); see `wellknown.go`'s `thirdPartySaaSDomains` for the full list. This is a weaker judgment call than the other allowlist categories, since seeing one of these does reveal something about the client's tech stack, just not the client's identity. It is its own toggleable category for exactly that reason. |
| `allowlist.web_infrastructure` | Common third-party CDN/font/analytics/widget hosts (jsdelivr.net, googletagmanager.com, clarity.ms, recaptcha.net, etc.); these are embedded on almost any scanned website, client's or not, and carry no client-identifying information in the hostname itself. See `wellknown.go`'s `webInfrastructureDomains` for the full list and what is deliberately excluded (customer-subdomain SaaS platforms like Zendesk and Okta, where the hostname itself is often the finding). |
| `allowlist.wellknown_platforms` | Well-known public dev platforms (github.com, npmjs.com, pastebin.com, stackoverflow.com, etc.); see `wellknown.go`'s `wellKnownPlatformDomains` for the full list. |

### `cicd`

| Category | Detects |
|---|---|
| `cicd.circleci` | CircleCI API tokens. |
| `cicd.snyk` | Snyk API tokens. |
| `cicd.terraform` | Terraform Cloud/Enterprise API tokens. |
| `cicd.vault` | HashiCorp Vault tokens. |

### `cloud`

| Category | Detects |
|---|---|
| `cloud.artifactory` | JFrog Artifactory API tokens. |
| `cloud.aws` | AWS access key IDs (AKIA/ASIA-prefixed) and secret access keys (the 40-char value, when labeled by a nearby keyword like `aws_secret_access_key`). |
| `cloud.azure_storage_key` | Azure Storage account keys. |
| `cloud.cloudflare` | Cloudflare API tokens. |
| `cloud.digitalocean` | DigitalOcean API tokens. |
| `cloud.dockerhub` | Docker Hub access tokens. |
| `cloud.google_api_key` | Google API keys. |

### `collab`

| Category | Detects |
|---|---|
| `collab.slack_token` | Slack API tokens. |
| `collab.slack_webhook` | Slack incoming webhook URLs. |

### `comms`

| Category | Detects |
|---|---|
| `comms.sendgrid` | SendGrid API keys. |
| `comms.twilio` | Twilio account SIDs. |

### `contact`

| Category | Detects |
|---|---|
| `contact.email` | Email addresses. |
| `contact.intl_phone` | Non-NANP international phone numbers. |
| `contact.phone` | NANP-shaped (US/Canada) phone numbers. |

### `india_pii`

| Category | Detects |
|---|---|
| `india_pii.aadhaar` | Indian Aadhaar numbers (12-digit, Verhoeff-checksum validated). |
| `india_pii.pan` | Indian PAN numbers (Permanent Account Number, 10-character alphanumeric). |

### `network`

| Category | Detects |
|---|---|
| `network.domain` | Domain names and hostnames, bare or embedded in a URL. |
| `network.ipv4` | IPv4 addresses. |
| `network.ipv6` | IPv6 addresses. |
| `network.mac` | MAC addresses. |

### `packages`

| Category | Detects |
|---|---|
| `packages.npm` | npm access tokens. |

### `payments`

| Category | Detects |
|---|---|
| `payments.razorpay` | Razorpay API keys. |
| `payments.stripe` | Stripe API keys. |

### `secrets`

| Category | Detects |
|---|---|
| `secrets.bearer_token` | Opaque Bearer/API tokens following an Authorization header. |
| `secrets.connection_string` | Database/service connection strings with embedded credentials. |
| `secrets.itsdangerous_token` | Flask itsdangerous-signed tokens (session/CSRF tokens). |
| `secrets.jwt` | JSON Web Tokens (JWTs). |
| `secrets.password_hash` | Password hashes (MD5/NTLM/SHA-1/SHA-256), only when labeled by a nearby keyword, or in an Impacket secretsdump-style LM:NT pair. |
| `secrets.pem_key` | PEM-armored private key blocks. |

### `vcs`

| Category | Detects |
|---|---|
| `vcs.bitbucket` | Bitbucket app passwords/tokens. |
| `vcs.github` | GitHub personal access / OAuth tokens. |
| `vcs.gitlab` | GitLab personal access tokens. |

### `windows_ad`

| Category | Detects |
|---|---|
| `windows_ad.gpp_cpassword` | Group Policy Preferences `cpassword` values, trivially decryptable via Microsoft's published MS14-025 AES key. |
| `windows_ad.machine_account` | `$`-suffixed Active Directory machine/computer account names (e.g. `WORKSTATION01$`) in a `secretsdump.py`/pwdump line. |

## The allowlist categories

These four are exceptions, not detectors. They stop values from being
redacted, so **disabling one means more gets redacted, not less.**

They exist because it is genuinely useful for Claude to recognize
infrastructure that carries no client identity: that a domain is GitHub
and it can therefore use the `gh` CLI, that a hostname is Google Tag
Manager rather than client infrastructure, that a callback domain is
Burp Collaborator and therefore your own tooling, likely an SSRF or RCE
test. Tokenize those and Claude loses context it would otherwise have
for free.

Most engagements should leave all four enabled. The one worth
considering individually is `allowlist.third_party_saas`, since a vendor
domain does fingerprint the client's tech stack even though it does not
name the client. Disable that one alone on an engagement where even
that should stay hidden:

```bash
redactproxy rules disable allowlist.third_party_saas
```

`rules show` flags all four with a warning, and the proxy logs a
distinct message when one is disabled, so the inverted meaning is never
silent.

## What is deliberately not detected

Some things are excluded on purpose, because a detector that fires on
innocent text costs more than one that misses an edge case:

- **Bare apex domains on file-extension TLDs** (`.do`, `.ai`, `.rs`,
  `.sh`, `.py`). `main.rs` and `logo.ai` are far more often filenames.
  Use `rules block --domain` for these.
- **Reserved and documentation values.** `example.com`, RFC 5737
  documentation IP ranges and similar are excluded, since they are not
  client data and tokenizing them just adds noise.
- **Names and prose**, which have no shape at all. Use `rules block`.

See [Known gaps](../security/gaps.md) for the full picture.

## Adding a detector

New detectors are welcome, particularly for prose-shaped PII and for
Windows/AD artifacts. See CONTRIBUTING.md's "Adding a detector".
