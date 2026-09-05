package redact

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// domainParts is a fully-qualified domain name split into the pieces
// that matter for structure-preserving redaction: subdomain labels
// (infrastructure/role metadata like "ns1", "portal", "admin", useful to
// Claude's reasoning and not identifying on their own), the
// organization-identifying label (the actual sensitive part), and the
// public suffix (country/sector context, e.g. ".co.uk", ".gov").
type domainParts struct {
	// subdomainPrefix is everything before the registrable domain,
	// INCLUDING the trailing dot (e.g. "ns1." or "portal.admin.", or ""
	// if fqdn IS the registrable domain with no subdomain).
	subdomainPrefix string
	// orgLabel is the single label that identifies the organization,
	// e.g. "target-corp" in "target-corp.co.uk".
	orgLabel string
	// suffix is the public suffix, e.g. "co.uk", "com", "gov"; may be
	// multiple labels (ICANN suffixes like "co.uk") or, for domains
	// hosted on shared platforms, a "private" suffix from the same list
	// (e.g. "herokuapp.com"), in which case orgLabel correctly resolves
	// to the customer's label ("myapp" in "myapp.herokuapp.com"), not
	// the platform's.
	suffix string
	// registrable is orgLabel + "." + suffix, the effective TLD+1, used
	// as the tokenstore key so every subdomain of the same organization
	// shares one token.
	registrable string
}

// splitDomain uses the real Public Suffix List (not a hand-rolled TLD
// allowlist) to split fqdn. This matters beyond just finding where the
// suffix starts: a naive "last two labels" heuristic gets multi-label
// suffixes wrong (treating "co" as the org label in "target-corp.co.uk"),
// and gets shared-hosting domains actively wrong in a way that would
// under-redact: "myapp.herokuapp.com" has "herokuapp.com" as its
// (private) suffix, so "myapp", the actual customer-identifying label,
// is what needs tokenizing, not "herokuapp".
//
// PSL alone isn't sufficient, though: the public suffix spec's fallback
// rule treats ANY unrecognized final label as an implicit valid suffix:
// EffectiveTLDPlusOne("console.log") succeeds with suffix "log" and no
// error, indistinguishable by return value alone from a real listed
// private suffix like "github.io". That would let "console.log" and
// "scan_results_1.5.txt" both parse as if they were real registrable
// domains. So the last label of whatever suffix PSL returns is
// additionally checked against knownTLDs (see tlds.go), a curated list
// used here as a validation gate, not as the splitter.
//
// ok is false when fqdn has no recognized registrable domain (e.g. it IS
// just a bare public suffix with nothing in front of it, or its suffix's
// last label isn't a real deployed TLD); callers should leave such text
// untouched rather than guess.
func splitDomain(fqdn string) (domainParts, bool) {
	reg, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		return domainParts{}, false
	}
	suffix, _ := publicsuffix.PublicSuffix(fqdn)
	orgLabel := strings.TrimSuffix(reg, "."+suffix)
	if orgLabel == reg || orgLabel == "" {
		return domainParts{}, false // reg didn't actually end in suffix, or nothing left; malformed
	}

	if lastDot := strings.LastIndex(suffix, "."); lastDot == -1 {
		if !knownTLDs[suffix] {
			return domainParts{}, false
		}
	} else if !knownTLDs[suffix[lastDot+1:]] {
		return domainParts{}, false
	}

	// EffectiveTLDPlusOne only ever looks ONE label to the left of the
	// recognized public suffix. If that suffix happens to appear twice
	// in a row -- "svc-b.widgetcorp.net.net", a real case seen in
	// production: an LLM restating a domain in its own write-up and
	// duplicating the TLD by mistake -- the "one label left" it finds is
	// the suffix's OWN second occurrence, not the real organization
	// label another step further left. Left uncorrected, that
	// organization label (the actual sensitive part) never gets
	// classified as orgLabel at all, so nothing here ever asks to
	// tokenize it, and it survives as untouched subdomain-prefix text.
	// Detect the repeat (orgLabel is an exact match for the suffix's own
	// leading label) and walk one more label left, re-deriving the
	// split against the extended suffix, repeated in case the
	// duplication is more than one level deep.
	for {
		suffixHead := suffix
		if dot := strings.IndexByte(suffix, '.'); dot != -1 {
			suffixHead = suffix[:dot]
		}
		if !strings.EqualFold(orgLabel, suffixHead) {
			break
		}
		extended := orgLabel + "." + suffix
		remaining := strings.TrimSuffix(fqdn, "."+extended)
		if remaining == fqdn || remaining == "" {
			break // nothing further left to walk into; keep what we have
		}
		next := remaining
		if dot := strings.LastIndexByte(remaining, '.'); dot != -1 {
			next = remaining[dot+1:]
		}
		if next == "" {
			break
		}
		orgLabel, suffix = next, extended
	}
	reg = orgLabel + "." + suffix

	subdomainPrefix := ""
	if len(fqdn) > len(reg) {
		subdomainPrefix = strings.TrimSuffix(fqdn, reg)
		if !strings.HasSuffix(subdomainPrefix, ".") {
			return domainParts{}, false // shouldn't happen given EffectiveTLDPlusOne's contract, but never guess
		}
	}

	return domainParts{
		subdomainPrefix: subdomainPrefix,
		orgLabel:        orgLabel,
		suffix:          suffix,
		registrable:     reg,
	}, true
}

// tenantSubdomainSaaSSuffixes are third-party SaaS platforms where the
// CUSTOMER's own tenant/org name goes in the subdomain immediately in
// front of the vendor's domain (https://xyzexamplecorp.okta.com), the
// opposite structure from a client's own domain, where the registrable
// label itself is the sensitive part and subdomains are just
// infrastructure/role metadata (see domainParts' doc comment). The
// public suffix list already gets this right for a few platforms that
// submitted themselves as PSL "private" entries: EffectiveTLDPlusOne
// already resolves "myapp.herokuapp.com" to org label "myapp", suffix
// "herokuapp.com", so those need no special handling here. These
// vendors are NOT in the PSL's private section, so splitDomain alone
// would treat e.g. "xyzexamplecorp.okta.com" as suffix "com" / org label
// "okta", tokenizing the wrong half (a public vendor name, nothing
// sensitive) and leaving "xyzexamplecorp", the actual client-identifying
// tenant name, in plaintext (SSO/helpdesk findings referencing a
// client's Okta or Zendesk tenant are a common real-world case this
// guards against).
//
// Deliberately conservative: only vendors where "<tenant>.<vendor
// suffix>" is confirmed to be the actual, single-label convention used
// in practice. Salesforce ("xyzexamplecorp.lightning.force.com", an extra
// fixed literal segment between tenant and suffix) and Workday (tenant
// name lives in the URL PATH, not the subdomain) are deliberately
// excluded rather than guessed at; a wrong guess here would either miss
// a real leak or mis-redact a literal product-line segment as if it were
// the client's name. The same reasoning excludes several AWS-generated
// hostnames that look like they'd fit (rds.amazonaws.com,
// cache.amazonaws.com, es.amazonaws.com, cloudsearch.amazonaws.com,
// dkr.ecr.<region>.amazonaws.com): those have a region and/or an
// AWS-random-id label between the customer's own identifier and the
// service suffix, so "the one label immediately before the suffix" is
// the region or random id, not the customer's name, and adding them here
// would silently redact the wrong label while still leaving the real
// identifier in plaintext, the exact failure mode this file exists to
// fix, not a fix for it.
//
// The entries below aren't all third-party SaaS in the CRM/helpdesk
// sense the platforms above are: several are a cloud vendor's OWN
// sub-service that vendor simply hasn't registered as its own PSL
// private suffix (Azure and AWS are both inconsistent about this even
// across their own sibling services: azurewebsites.net and
// blob.core.windows.net are correctly in PSL, database.windows.net and
// vault.azure.net are not). Mechanically and for redaction purposes
// they're the same shape either way: a single customer-chosen label
// sitting in front of a fixed multi-label suffix nobody but this list
// currently tells splitDomain how to parse.
var tenantSubdomainSaaSSuffixes = []string{
	"okta.com",
	"zendesk.com",
	"atlassian.net",
	"freshdesk.com", "freshservice.com",
	"service-now.com",
	"onelogin.com",
	"auth0.com",
	"database.windows.net", "database.secure.windows.net",
	"queue.core.windows.net", "table.core.windows.net",
	"redis.cache.windows.net",
	"vault.azure.net",
	"documents.azure.com",
	"search.windows.net",
	"azurecr.io",
	"azurehdinsight.net",
	"scm.azurewebsites.net",
	"cloudapp.azure.com",
	"storage.googleapis.com",
	"firebaseio.com",
	"db.ondigitalocean.com",
	"wpengine.com",
}

// splitTenantSubdomainSaaS reports whether fqdn (already lowercase) ends
// in one of tenantSubdomainSaaSSuffixes with a genuine tenant label in
// front of it, and if so splits it the same shape splitDomain returns:
// suffix is the matched vendor domain, orgLabel is the single label
// immediately before it (the tenant name, the actual sensitive part),
// and subdomainPrefix is anything further back (e.g. "sso." in
// "sso.xyzexamplecorp.okta.com"), same infrastructure-label semantics as
// everywhere else. A bare vendor domain with no tenant label in front
// (just "okta.com" on its own) is not a match; nothing tenant-specific
// to protect there.
func splitTenantSubdomainSaaS(fqdn string) (domainParts, bool) {
	for _, suffix := range tenantSubdomainSaaSSuffixes {
		dotSuffix := "." + suffix
		if !strings.HasSuffix(fqdn, dotSuffix) {
			continue
		}
		rest := strings.TrimSuffix(fqdn, dotSuffix)
		if rest == "" {
			continue
		}
		subdomainPrefix, orgLabel := "", rest
		if idx := strings.LastIndexByte(rest, '.'); idx != -1 {
			subdomainPrefix, orgLabel = rest[:idx+1], rest[idx+1:]
		}
		if orgLabel == "" {
			continue
		}
		return domainParts{
			subdomainPrefix: subdomainPrefix,
			orgLabel:        orgLabel,
			suffix:          suffix,
			registrable:     orgLabel + "." + suffix,
		}, true
	}
	return domainParts{}, false
}

// minOrgWordLen is the shortest org-label word fragment the leak check
// will match on. Below this, short common syllables ("co", "it", "gp")
// would trigger the fallback on essentially any subdomain, defeating the
// point of preserving structure at all.
const minOrgWordLen = 3

// subdomainLeaksOrgName reports whether any subdomain label contains a
// word from the organization's own label, e.g. "target-admin" contains
// "target", a fragment of "target-corp". When true, preserving that
// subdomain label literally would leak part of the org's identity
// through the "structure-preserving" path this file exists to add, so
// the caller should fall back to fully opaque tokenization instead.
func subdomainLeaksOrgName(subdomainPrefix, orgLabel string) bool {
	if subdomainPrefix == "" {
		return false
	}
	lowerPrefix := strings.ToLower(subdomainPrefix)
	for _, word := range strings.FieldsFunc(orgLabel, func(r rune) bool { return r == '-' || r == '_' }) {
		if len(word) >= minOrgWordLen && strings.Contains(lowerPrefix, strings.ToLower(word)) {
			return true
		}
	}
	return false
}
