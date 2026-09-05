package redact

// CategorizedDetector pairs a Detector with the stable identifiers used
// to select it for selective enable/disable (see FilterDetectors) and in
// any reporting/config surface built on top of this package:
// "category.subcategory" (e.g. "cloud.aws") is the on-the-wire name.
// Description is a one-line, human-readable summary of what this
// detector catches, the single source of truth rules.Config's
// self-documenting "categories" section (see rules.EnsureAllCategories)
// pulls from, so a saved rules.json never has to duplicate or drift
// from this text.
//
// Once assigned, treat a Category/Subcategory rename as a breaking
// change: anything outside this package (a saved config file, a CLI
// flag someone scripted) may already refer to it by name.
type CategorizedDetector struct {
	Detector
	Category    string
	Subcategory string
	Description string
}

// Name returns the "category.subcategory" identifier for this detector.
func (c CategorizedDetector) Name() string {
	return c.Category + "." + c.Subcategory
}

// DefaultCategorizedDetectors returns the standard regex-based detector
// set with category metadata attached. This is the source of truth;
// DefaultDetectors and FilterDetectors are both built from it.
func DefaultCategorizedDetectors() []CategorizedDetector {
	return []CategorizedDetector{
		{emailDetector{}, "contact", "email", "Email addresses."},
		{domainDetector{}, "network", "domain", "Domain names and hostnames, bare or embedded in a URL."},
		{ipv4Detector{}, "network", "ipv4", "IPv4 addresses."},
		{ipv6Detector{}, "network", "ipv6", "IPv6 addresses."},
		{macDetector{}, "network", "mac", "MAC addresses."},
		{phoneDetector{}, "contact", "phone", "NANP-shaped (US/Canada) phone numbers."},
		{intlPhoneDetector{}, "contact", "intl_phone", "Non-NANP international phone numbers."},
		{jwtDetector, "secrets", "jwt", "JSON Web Tokens (JWTs)."},
		{bearerDetector{}, "secrets", "bearer_token", "Opaque Bearer/API tokens following an Authorization header."},
		{pemKeyDetector{}, "secrets", "pem_key", "PEM-armored private key blocks."},
		{connStringDetector{}, "secrets", "connection_string", "Database/service connection strings with embedded credentials."},
		{itsdangerousDetector{}, "secrets", "itsdangerous_token", "Flask itsdangerous-signed tokens (session/CSRF tokens)."},
		{hashDetector{}, "secrets", "password_hash", "Password hashes (MD5/NTLM/SHA-1/SHA-256), only when labeled by a nearby keyword, or in an Impacket secretsdump-style LM:NT pair."},
		{adMachineAccountDetector, "windows_ad", "machine_account", "$-suffixed Active Directory machine/computer account names (e.g. \"WORKSTATION01$\") in a secretsdump.py/pwdump line."},
		{gppCPasswordDetector, "windows_ad", "gpp_cpassword", "Group Policy Preferences \"cpassword\" values, trivially decryptable via Microsoft's published MS14-025 AES key."},
		{aadhaarDetector{}, "india_pii", "aadhaar", "Indian Aadhaar numbers (12-digit, Verhoeff-checksum validated)."},
		{panDetector{}, "india_pii", "pan", "Indian PAN numbers (Permanent Account Number, 10-character alphanumeric)."},
		{githubTokenDetector, "vcs", "github", "GitHub personal access / OAuth tokens."},
		{gitlabTokenDetector, "vcs", "gitlab", "GitLab personal access tokens."},
		{bitbucketDetector, "vcs", "bitbucket", "Bitbucket app passwords/tokens."},
		{slackTokenDetector, "collab", "slack_token", "Slack API tokens."},
		{slackWebhookDetector, "collab", "slack_webhook", "Slack incoming webhook URLs."},
		{stripeKeyDetector, "payments", "stripe", "Stripe API keys."},
		{razorpayDetector, "payments", "razorpay", "Razorpay API keys."},
		{openAIDetector, "ai_providers", "openai", "OpenAI API keys."},
		{anthropicKeyDetector, "ai_providers", "anthropic", "Anthropic API keys."},
		{awsKeyDetector{}, "cloud", "aws", "AWS access key IDs (AKIA/ASIA-prefixed) and secret access keys (the 40-char value, when labeled by a nearby keyword like aws_secret_access_key)."},
		{digitalOceanDetector, "cloud", "digitalocean", "DigitalOcean API tokens."},
		{cloudflareDetector, "cloud", "cloudflare", "Cloudflare API tokens."},
		{azureStorageKeyDetector, "cloud", "azure_storage_key", "Azure Storage account keys."},
		{artifactoryDetector, "cloud", "artifactory", "JFrog Artifactory API tokens."},
		{dockerHubDetector, "cloud", "dockerhub", "Docker Hub access tokens."},
		{googleAPIKeyDetector, "cloud", "google_api_key", "Google API keys."},
		{circleCIDetector, "cicd", "circleci", "CircleCI API tokens."},
		{terraformDetector, "cicd", "terraform", "Terraform Cloud/Enterprise API tokens."},
		{snykDetector, "cicd", "snyk", "Snyk API tokens."},
		{vaultDetector, "cicd", "vault", "HashiCorp Vault tokens."},
		{twilioSIDDetector, "comms", "twilio", "Twilio account SIDs."},
		{sendGridKeyDetector, "comms", "sendgrid", "SendGrid API keys."},
		{npmTokenDetector, "packages", "npm", "npm access tokens."},
	}
}

// DefaultCategorizedDetectorsWithForcedDomains is DefaultCategorizedDetectors,
// except the domain detector treats every registrable domain in
// forceAsDomain as a real domain even where it would otherwise be skipped
// as a likely filename mention (see filenameCollisionTLDs/
// looksLikeBareFilename in detector.go). forceAsDomain is meant to be
// populated from an engagement's own rules.json block entries that are
// exactly a bare registrable domain (see rules.Compiled.ForcedDomains,
// DomainRegistrablePart), so an operator's own client domain gets the
// same structure-preserving domain token everywhere it appears
// (bare, with a subdomain, in an email, in a URL), not just an opaque
// block-list token for the one literal form they typed in. A nil or
// empty map behaves identically to DefaultCategorizedDetectors.
func DefaultCategorizedDetectorsWithForcedDomains(forceAsDomain map[string]bool) []CategorizedDetector {
	all := DefaultCategorizedDetectors()
	for i := range all {
		if all[i].Category == "network" && all[i].Subcategory == "domain" {
			all[i].Detector = domainDetector{forceAsDomain: forceAsDomain}
		}
	}
	return all
}

// FilterDetectors returns the Detector for every entry in all whose
// Category or "Category.Subcategory" is NOT in disabled: disabling a
// bare category (e.g. "cloud") drops every subcategory under it;
// disabling "cloud.aws" drops only that one. Order is preserved from
// all.
func FilterDetectors(all []CategorizedDetector, disabled map[string]bool) []Detector {
	out := make([]Detector, 0, len(all))
	for _, c := range all {
		if disabled[c.Category] || disabled[c.Name()] {
			continue
		}
		out = append(out, c.Detector)
	}
	return out
}

// CategoryInfo describes one category/subcategory for a config-editing
// surface (rules.Config's self-documenting "categories" section),
// deliberately not CategorizedDetector itself, since not every category
// this package exposes is backed by a Detector (the allowlist.*
// pseudo-categories in wellknown.go are exceptions, not detectors; see
// CategoryAllowlist's doc comment). Name returns the same
// "category.subcategory" (or bare "category" if Subcategory is empty)
// identifier CategorizedDetector.Name does.
type CategoryInfo struct {
	Category    string
	Subcategory string
	Description string
	// Warning is non-empty only for categories where disabling has a
	// counter-intuitive direction or effect worth calling out explicitly,
	// currently just the allowlist.* exceptions, where "disable"
	// means MORE gets redacted, not less.
	Warning string
}

func (c CategoryInfo) Name() string {
	if c.Subcategory == "" {
		return c.Category
	}
	return c.Category + "." + c.Subcategory
}

// AllCategoryInfo returns every category/subcategory this package
// exposes for a config-editing surface to enumerate: every built-in
// detector (from DefaultCategorizedDetectors) plus the two allowlist.*
// exceptions (from wellknown.go), which aren't detectors but need the
// same enable/disable identity for the same reason (see
// CategoryAllowlist's doc comment). This is the single source
// rules.Config.EnsureAllCategories reconciles a saved rules.json
// against. New entries here show up in existing files automatically
// the next time they're loaded, and anything removed here is pruned
// the same way.
func AllCategoryInfo() []CategoryInfo {
	detectors := DefaultCategorizedDetectors()
	out := make([]CategoryInfo, 0, len(detectors)+len(builtinAllowlists))
	for _, c := range detectors {
		out = append(out, CategoryInfo{Category: c.Category, Subcategory: c.Subcategory, Description: c.Description})
	}
	out = append(out,
		CategoryInfo{
			Category:    CategoryAllowlist,
			Subcategory: SubcategoryWellKnownPlatforms,
			Description: "Exempts well-known public dev platforms (github.com, npmjs.com, pastebin.com, stackoverflow.com, etc.) from redaction; see wellknown.go's wellKnownPlatformDomains for the full list.",
			Warning:     "Disabling this makes MORE get redacted, not less: Claude will see tokens instead of recognizing common platforms it otherwise understands natively (e.g. \"this is GitHub, I can use the gh CLI\"). Most engagements should leave this enabled.",
		},
		CategoryInfo{
			Category:    CategoryAllowlist,
			Subcategory: SubcategorySecurityTestingServices,
			Description: "Exempts out-of-band/security-testing callback services (burpcollaborator.net, interact.sh, webhook.site, etc.) from redaction; these are the tester's OWN tooling, never the client's.",
			Warning:     "Disabling this makes MORE get redacted, not less: Claude will see tokens instead of recognizing OOB callback domains it otherwise understands natively (e.g. \"this is a Burp Collaborator domain, likely an SSRF/RCE test\"). Most engagements should leave this enabled.",
		},
		CategoryInfo{
			Category:    CategoryAllowlist,
			Subcategory: SubcategoryWebInfrastructure,
			Description: "Exempts common third-party CDN/font/analytics/widget hosts (jsdelivr.net, googletagmanager.com, clarity.ms, recaptcha.net, etc.) from redaction; these are embedded on almost any scanned website, client's or not, and carry no client-identifying information in the hostname itself. See wellknown.go's webInfrastructureDomains for the full list and what's deliberately excluded (customer-subdomain SaaS platforms like Zendesk/Okta, where the hostname itself is often the finding).",
			Warning:     "Disabling this makes MORE get redacted, not less: Claude will see tokens instead of recognizing common CDN/analytics domains it otherwise understands natively (e.g. \"this is Google Tag Manager, not client infrastructure\"). Most engagements should leave this enabled.",
		},
		CategoryInfo{
			Category:    CategoryAllowlist,
			Subcategory: SubcategoryThirdPartySaaS,
			Description: "Exempts specific third-party vendor products a client's own site actively integrates with (razorpay.com, zoho.in, engati.ai, etc.) from redaction; see wellknown.go's thirdPartySaaSDomains for the full list. This is a weaker judgment call than the other allowlist categories, since seeing one of these DOES reveal something about the client's tech stack, just not the client's identity. It's kept as its own toggleable category for exactly that reason.",
			Warning:     "Disabling this makes MORE get redacted, not less: Claude will see tokens instead of recognizing these vendor domains natively. Consider disabling this specific category (rather than the whole allowlist) for an engagement where even tech-stack fingerprinting should stay hidden.",
		},
	)
	return out
}
