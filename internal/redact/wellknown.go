package redact

import "regexp"

// CategoryAllowlist is the pseudo-detector category for this file's two
// built-in, curated domain allowlists. "Pseudo" because, unlike every
// entry in DefaultCategorizedDetectors, these aren't detectors that FIND
// PII; they're exceptions that stop the domain/email detectors from
// flagging known-safe public infrastructure. They still need a
// Category/Subcategory identity for the exact same reason every real
// detector has one: so an operator can disable them via `redactproxy
// rules disable` (persisted, see rules.Config.Categories) or the
// ephemeral -disable flag, for the rare engagement where overriding
// the default judgment call is correct (see BuiltinAllowPatterns' doc
// comment). Kept as its own top-level category (not folded into
// "network.domain") specifically so `rules show`'s category listing
// doesn't present a curated judgment call as if it carries the same
// certainty as an RFC-backed detector.
const CategoryAllowlist = "allowlist"

const (
	SubcategoryWellKnownPlatforms      = "wellknown_platforms"
	SubcategorySecurityTestingServices = "security_testing_services"
	SubcategoryWebInfrastructure       = "web_infrastructure"
	SubcategoryThirdPartySaaS          = "third_party_saas"
)

// wellKnownPlatformDomains are public developer/infrastructure platforms
// that show up constantly in real pentest work (README links, package
// installs, `git clone`, dependency URLs) but are never themselves a
// pentest target or client-identifying value -- they're public knowledge
// already, same rationale as the RFC 6761 names in reserved.go.
// Tokenizing them costs real understanding for no protective benefit:
// once Claude sees a token instead of "github.com" it loses the ability
// to reason "this is GitHub, I can use the gh CLI." What's actually
// sensitive in a URL under one of these (an org name, a repo path) lives
// in the PATH, which this tool's domain detector never touches anyway
// (only the host is matched) -- so allowlisting the bare platform domain
// doesn't weaken protection of anything client-specific.
//
// Deliberately a short, curated list, not an imported "top domains"
// dataset -- a wrong entry here means real client data silently passes
// through unprotected, so every addition should be a domain that's
// unambiguously generic public infrastructure, never something that
// could itself be a client's own custom domain. Unlike reserved.go's RFC
// 6761 names (an IETF-guaranteed fact), this list is a judgment call --
// see CategoryAllowlist's doc comment for why it's disable-able.
var wellKnownPlatformDomains = []string{
	"github.com", "githubusercontent.com", "githubassets.com",
	"gitlab.com", "bitbucket.org",
	"stackoverflow.com", "stackexchange.com",
	"npmjs.com", "npmjs.org", "nodejs.org", "typescriptlang.org",
	"pypi.org", "python.org", "golang.org", "go.dev", "rubygems.org", "crates.io",
	"pastebin.com",
	"mozilla.org", "w3.org",
	// "googleapis.com" is deliberately NOT here: it's a shared base
	// domain for dozens of Google Cloud sub-services, and at least one
	// (storage.googleapis.com, GCS's virtual-hosted-style bucket URLs,
	// "<bucket>.storage.googleapis.com") puts the customer's own
	// identifier directly in the subdomain -- the exact
	// customer-name-in-hostname pattern this file already excludes
	// "onmicrosoft.com" for below. A bare wildcard entry here would
	// silently exempt that (and any future Google sub-service with the
	// same shape) from redaction. See tenantSubdomainSaaSSuffixes in
	// domainsplit.go, which handles storage.googleapis.com correctly
	// instead: the customer label gets tokenized, the shared suffix
	// stays literal.
	"google.com", "gstatic.com",
	"cloudflare.com",
	"docker.com", "hub.docker.com", "docker.io",
	"claude.ai", "anthropic.com",

	// Standards bodies / open-source foundations -- show up constantly in
	// XML namespaces, SOAP envelopes, license headers, and spec references
	// (schemas.xmlsoap.org in a WSDL, w3.org in an XML namespace) rather
	// than being visited as sites; never client-identifying.
	"apache.org", "gnu.org", "fsf.org", "mit.edu", "oasis-open.org",
	"oclc.org", "openoffice.org", "openxmlformats.org", "openhtmltopdf.com",
	"xmlsoap.org", "purl.org", "json.org", "schema.org",
	// RFC citations -- ietf.org (tools.ietf.org/html/rfcNNNN) and
	// rfc-editor.org (rfc-editor.org/rfc/rfcNNNN) are the two forms an RFC
	// reference commonly takes in a report; as ubiquitous as the other
	// standards-body domains above.
	"ietf.org", "rfc-editor.org",

	// Public JS/frontend library sites (docs, package homepages) --
	// found constantly in bundled/minified page source or package.json,
	// same "generic library reference" reasoning as npmjs.com above.
	"swagger.io", "popper.js.org", "momentjs.com", "datatables.net",
	"angular.io", "v8.dev",

	// Specific well-known open-source projects' own github.io Pages sites.
	// Deliberately full FQDNs, NOT a bare "github.io" entry -- see this
	// file's package doc comment: a client's own project can
	// legitimately live at <client>.github.io, which must stay fully
	// protected. Anchoring each pattern to its own specific FQDN (the
	// compileAllowPatterns wildcard only matches subdomains OF that exact
	// name, e.g. "x.stuk.github.io", never a sibling like
	// "otherproject.github.io") keeps that protection intact.
	"stuk.github.io", "sweetalert2.github.io",

	// Big-tech consumer/productivity platforms -- ubiquitous, not
	// client-identifying on their own. "onmicrosoft.com" is deliberately
	// NOT here: every Microsoft 365 tenant's default hostname is
	// "<company>.onmicrosoft.com", the exact customer-name-in-hostname
	// pattern this file's package doc comment already excludes for
	// Zendesk/Okta/Atlassian -- it would leak the client's tenant name.
	// "azure.com" is excluded for the identical reason: several real
	// Azure sub-services (documents.azure.com/Cosmos DB,
	// cloudapp.azure.com/Cloud Services, vault.azure.net, and others --
	// see tenantSubdomainSaaSSuffixes in domainsplit.go) put the
	// customer's own resource name directly in front of it, which a bare
	// wildcard entry here would silently exempt.
	"amazon.com", "microsoft.com", "office.com", "office365.com",
	"outlook.com", "gmail.com", "yahoo.co.in", "facebook.com", "quora.com",
	"wikipedia.org", "freepik.com", "geeksforgeeks.org", "wa.me",
}

// securityTestingServiceDomains are out-of-band interaction/callback
// platforms pentesters use as their OWN tooling -- a Burp Collaborator
// or interact.sh domain appearing in a command is the tester's own
// infrastructure for detecting blind SSRF/RCE/XXE, never the client's.
// Same rationale as wellKnownPlatformDomains: tokenizing these has no
// protective benefit and breaks Claude's ability to recognize "this is
// an OOB callback domain" when reasoning about a finding.
var securityTestingServiceDomains = []string{
	"burpcollaborator.net",
	"oastify.com",
	"interact.sh", "interactsh.com",
	"canarytokens.com", "canarytokens.org",
	"requestbin.com", "requestbin.net",
	"webhook.site",
	"dnslog.cn",
	"pipedream.net",
	"ngrok.io", "ngrok-free.app", "ngrok.app",

	// Public recon/OSINT services -- certificate-transparency lookups and
	// egress-IP echo services a pentester's own tooling calls out to;
	// never the client's infrastructure. (Whether this proxy's OWN
	// operator should actually be calling one of these from inside an
	// engagement is a separate, unrelated OPSEC question for CLAUDE.md/
	// project memory to cover -- this list only controls whether a
	// MENTION of the domain gets redacted.)
	"crt.sh", "certspotter.com",
	"nmap.org", "projectdiscovery.io",
	"ifconfig.me", "ipify.org", "ip-api.com", "ipinfo.io", "jsonip.com",
}

// webInfrastructureDomains are third-party script/font/analytics/widget
// hosts that show up embedded in the HTML of virtually any scanned
// website, client's or not: CDN-hosted JS libraries, web fonts, and
// analytics/tag-manager/error-tracking collectors. Even an unrelated
// third party's page (e.g. one a target vhost's SNI misconfig
// accidentally redirects to) will embed some of these: pure noise, the
// tag script itself carries no information about which site embeds it.
//
// Deliberately excludes SaaS platforms that put the CUSTOMER's own name
// in the hostname itself (Zendesk's <company>.zendesk.com, Okta's
// <company>.okta.com, Atlassian's <company>.atlassian.net, Shopify's
// <company>.myshopify.com, and similar) -- for those, the hostname IS
// often the client-identifying finding ("target uses Okta for SSO at
// xyzexamplecorp.okta.com"), the opposite case from a shared CDN/analytics
// collector where every embedding site's traffic looks identical at the
// hostname level and any per-site identifier lives in a query string or
// JS variable, never the host. Same reasoning as wellKnownPlatformDomains
// above, applied to a different class of ubiquitous non-target
// infrastructure.
var webInfrastructureDomains = []string{
	// Major CDN/edge providers' own generic suffix domains -- the shared
	// backend naming convention a huge fraction of unrelated sites'
	// traffic gets routed through, not something that identifies which
	// customer is behind a given hostname. IMPORTANT: this is exactly the
	// class of domain a customer's own name can appear ALONGSIDE, not
	// instead of -- e.g. a CNAME target shaped like
	// "www.<customer>.<edge-hash>.edgekey.net" -- so allowlisting the
	// suffix here relies on Engine's block-list safety pass (see
	// blockListSafetyPass in engine.go) to still catch a block-listed
	// customer name in the earlier label even once the domain detector
	// itself stops treating the whole hostname as sensitive. Confirmed
	// live: TestEngine_BlockListSafetyPass_CatchesOrgNameInPreservedSubdomainLabel
	// covers exactly this interaction.
	"akamai.com", "akam.net", "akamaiedge.net", "akamaihd.net", "edgekey.net", "edgesuite.net",

	// JS/CSS library CDNs.
	"jquery.com", "code.jquery.com",
	"jsdelivr.net",
	"unpkg.com",
	"cdnjs.com",
	"bootstrapcdn.com",
	"fontawesome.com", "use.fontawesome.com",
	"polyfill.io",

	// Web font services.
	"typekit.net", "typekit.com",
	"fonts.com",

	// Analytics / tag manager / error tracking collectors.
	"google-analytics.com", "googletagmanager.com", "googletagservices.com",
	"doubleclick.net",
	"clarity.ms",
	"hotjar.com",
	"segment.com", "segment.io",
	"mixpanel.com",
	"fullstory.com",
	"amplitude.com",
	"sentry.io", "sentry-cdn.com",
	"newrelic.com", "nr-data.net",
	"datadoghq.com", "datadoghq-browser-agent.com",
	"optimizely.com",
	"tinypass.com",
	"adobedtm.com", "demdex.net", // Adobe Dynamic Tag Manager / Audience Manager
	"go-mpulse.net", // Akamai mPulse RUM
	"clevertap.com", "clevertap-prod.com",
	"pendo.io",
	"gotrackier.com",
	"vizury.com",
	"mailcontrol.com",

	// CAPTCHA / cookie-consent / privacy-manager widgets.
	"recaptcha.net", "hcaptcha.com",
	"cookiebot.com", "onetrust.com", "cookielaw.org",
	"privacymanager.io",

	// Social embeds / share widgets / "follow us" footer links. The host
	// alone carries no per-site information; a company's own handle
	// lives in the URL PATH (e.g. linkedin.com/company/xyzexamplecorp), which
	// this tool's domain detector never touches; see
	// wellKnownPlatformDomains' doc comment for the same path-vs-host
	// distinction. These repeat across nearly any major site's page
	// source regardless of what the site itself is about.
	"facebook.net", "fbcdn.net",
	"youtube.com", "ytimg.com", "vimeo.com",
	"twitter.com", "x.com", "linkedin.com", "instagram.com", "tiktok.com", "pinterest.com",
}

// thirdPartySaaSDomains are third-party vendor products a client's own
// site actively integrates with -- a payment gateway, a shared auth
// service, a chatbot -- rather than an invisible embedded widget. Kept
// as its own subcategory (SubcategoryThirdPartySaaS), separate and
// independently disable-able from webInfrastructureDomains above, since
// the judgment call here is genuinely weaker: seeing one of these DOES
// reveal something about the client's tech stack ("this org uses
// Razorpay for payments"), just not the client's IDENTITY, the same way
// "this org uses GitHub" doesn't either. Every entry here was checked
// against the SaaS-puts-customer-name-in-the-hostname trap this file's
// package doc comment warns about (Zendesk/Okta/Atlassian-style) --
// these vendors' relevant hostnames are their own shared, generic ones
// (e.g. Zoho's "accounts.zoho.in" auth endpoint, not a per-tenant
// subdomain), not a customer-branded one.
var thirdPartySaaSDomains = []string{
	"razorpay.com",
	"zoho.in",
	"engati.ai",
}

// compileAllowPatterns turns a list of bare domains into anchored,
// case-insensitive regexes matching the exact domain or any subdomain
// of it (e.g. "api.github.com"), explicitly anchored (not a bare
// substring search) so "notgithub.com" does NOT falsely match
// "github.com": "(.*\.)?" requires whatever precedes the domain to end
// in a literal dot.
func compileAllowPatterns(domains []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(domains))
	for _, d := range domains {
		out = append(out, regexp.MustCompile(`(?i)^(.*\.)?`+regexp.QuoteMeta(d)+`$`))
	}
	return out
}

// builtinAllowlists pairs each CategoryAllowlist subcategory with its
// compiled patterns, so BuiltinAllowPatterns is one loop over this
// rather than one hand-written "not disabled at either level" condition
// per subcategory: adding the next allowlist means adding a line here
// and a CategoryInfo in categories.go, with no third place to forget.
var builtinAllowlists = []struct {
	subcategory string
	patterns    []*regexp.Regexp
}{
	{SubcategoryWellKnownPlatforms, compileAllowPatterns(wellKnownPlatformDomains)},
	{SubcategorySecurityTestingServices, compileAllowPatterns(securityTestingServiceDomains)},
	{SubcategoryWebInfrastructure, compileAllowPatterns(webInfrastructureDomains)},
	{SubcategoryThirdPartySaaS, compileAllowPatterns(thirdPartySaaSDomains)},
}

// BuiltinAllowPatterns returns the compiled allow-patterns for every
// CategoryAllowlist subcategory NOT present in disabled; merge this
// into an Engine's allow-patterns (alongside rules.json's own Allow
// entries, via SetAllowPatterns) so the exclusion applies by default but
// remains fully within the SAME override mechanism every other
// detection category already has.
//
// To force tokenization of one specific value that's in this allowlist
// (e.g. a single engagement where "pastebin.com" itself needs to be
// treated as sensitive), `rules block pastebin.com` does NOT work:
// Engine.filterAllowed drops a Detection based on its matched value
// alone, regardless of which Detector produced it, so an allow-pattern
// match vetoes a block-list match for the same value just as completely
// as it vetoes a built-in detector's. Allow always wins over block, with
// no exception for "this allow entry is built-in" vs. "this allow entry
// came from rules.json", the same precedence rule behind the plain
// block+allow-of-the-same-value confusion this was found alongside.
// The correct override here is `redactproxy rules disable
// allowlist.wellknown_platforms` (or `allowlist.security_testing_services`,
// or the bare `allowlist` category for both, persisted; the ephemeral
// `-disable` flag on `redactproxy` itself works the same way for a
// one-off run). That's a real category/subcategory toggle, not a
// per-value one; there is currently no way to force tokenization of a
// single built-in-allowlisted domain while leaving the rest of its
// category exempt.
func BuiltinAllowPatterns(disabled map[string]bool) []*regexp.Regexp {
	if disabled[CategoryAllowlist] {
		return nil // the bare category disables every subcategory under it
	}
	var out []*regexp.Regexp
	for _, list := range builtinAllowlists {
		if !disabled[CategoryAllowlist+"."+list.subcategory] {
			out = append(out, list.patterns...)
		}
	}
	return out
}
