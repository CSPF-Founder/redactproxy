package redact

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// TestWellKnownPlatformDomains_NeverTokenized covers the curated
// dev-platform and security-testing-service allowlists: these are
// public infrastructure a pentest engagement routinely references (repo
// URLs, package installs, OOB callback domains) but are never
// themselves a client target. See wellknown.go's doc comment for why
// tokenizing them costs real understanding for no protective benefit.
func TestWellKnownPlatformDomains_NeverTokenized(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"github.com bare", "clone it from github.com/torvalds/linux"},
		{"github.com subdomain", "check the release notes at docs.github.com"},
		{"gitlab.com", "mirrored on gitlab.com as well"},
		{"pastebin.com", "found a leak posted on pastebin.com"},
		{"npmjs.com", "installed via npmjs.com registry"},
		{"burpcollaborator.net", "used abc123.burpcollaborator.net for the OOB callback"},
		{"oastify.com", "callback fired on xyz.oastify.com"},
		{"interact.sh", "set up a listener on interact.sh"},
		{"webhook.site", "logged the request at webhook.site/unique-id"},
		{"ietf.org", "per https://tools.ietf.org/html/rfc6238"},
		{"rfc-editor.org", "see https://www.rfc-editor.org/rfc/rfc4226"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newCorpusEngine(t)
			out, err := e.Tokenize(tc.text)
			if err != nil {
				t.Fatal(err)
			}
			if out != tc.text {
				t.Errorf("well-known infrastructure domain was tokenized:\n  in:  %q\n  out: %q", tc.text, out)
			}
		})
	}
}

// TestWellKnownPlatformDomains_ClientSubdomainsUnderGitHubIOStillProtected
// is the control case that proves the allowlist doesn't overreach: only
// "github.com" itself is allowlisted, not "github.io"; a client's own
// custom pages subdomain (a genuinely client-identifying pattern, unlike
// anything under github.com) must still be tokenized normally.
func TestWellKnownPlatformDomains_ClientSubdomainsUnderGitHubIOStillProtected(t *testing.T) {
	e, _ := newCorpusEngine(t)
	in := "internal docs hosted at widgetcorp-fixture.github.io"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out == in {
		t.Fatalf("expected the client's custom github.io subdomain to be tokenized, got it unchanged: %q", out)
	}
}

// TestWebInfrastructureDomains_NeverTokenized covers the curated
// CDN/font/analytics/widget allowlist: even an unrelated third party's
// page (e.g. one a target vhost's SNI misconfig accidentally redirects
// to) will embed some of these, and its Google Analytics/reCAPTCHA
// embeds tokenizing right alongside the actual finding would be pure
// noise, since a script tag's host carries no information about which
// site embeds it.
func TestWebInfrastructureDomains_NeverTokenized(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"jsdelivr.net", "loaded from cdn.jsdelivr.net/npm/vue"},
		{"code.jquery.com", "script src code.jquery.com/jquery-3.6.0.js"},
		{"googletagmanager.com", "gtag/js?id=G-ABC123 from www.googletagmanager.com"},
		{"google-analytics.com", "beacon sent to www.google-analytics.com"},
		{"clarity.ms", "loaded c.clarity.ms for session replay"},
		{"recaptcha.net", "widget served from www.recaptcha.net"},
		{"hotjar.com", "tracking snippet from static.hotjar.com"},
		{"sentry-cdn.com", "error tracking loaded from js.sentry-cdn.com"},
		{"datadoghq-browser-agent.com", "RUM agent from www.datadoghq-browser-agent.com"},
		{"linkedin.com footer link", "follow us on www.linkedin.com/company/xyzexamplecorp"},
		{"youtube.com footer link", "watch on www.youtube.com/xyzexamplecorp"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newCorpusEngine(t)
			out, err := e.Tokenize(tc.text)
			if err != nil {
				t.Fatal(err)
			}
			if out != tc.text {
				t.Errorf("web infrastructure domain was tokenized:\n  in:  %q\n  out: %q", tc.text, out)
			}
		})
	}
}

// TestWebInfrastructureDomains_CustomerSubdomainSaaSStillProtected is the
// control case proving the exclusion documented in webInfrastructureDomains
// actually holds: SaaS platforms where the customer's own name lives in
// the subdomain (Zendesk, Okta, Atlassian, Shopify) are deliberately NOT
// in this list, since for those the hostname itself is often the
// client-identifying finding.
func TestWebInfrastructureDomains_CustomerSubdomainSaaSStillProtected(t *testing.T) {
	cases := []string{
		"support runs on xyzexamplecorp.zendesk.com",
		"SSO is handled via xyzexamplecorp.okta.com",
		"tracked in xyzexamplecorp.atlassian.net",
		"storefront at xyzexamplecorp.myshopify.com",
	}
	for _, in := range cases {
		e, _ := newCorpusEngine(t)
		out, err := e.Tokenize(in)
		if err != nil {
			t.Fatal(err)
		}
		if out == in {
			t.Errorf("expected a customer-subdomain SaaS host to still be tokenized, got it unchanged: %q", in)
		}
	}
}

// TestBuiltinAllowPatterns_CategorizedAndToggleable confirms an operator
// CAN disable either allowlist independently, or both via the bare
// "allowlist" category, using the exact same map shape
// buildDetectors/FilterDetectors already uses for every other category:
// these allowlists are controllable via rules.json's Disabled list
// (and -disable) exactly like every real detector category.
func TestBuiltinAllowPatterns_CategorizedAndToggleable(t *testing.T) {
	t.Run("nothing disabled: both lists active", func(t *testing.T) {
		e, _ := newCorpusEngine(t)
		out, err := e.Tokenize("clone github.com and report to burpcollaborator.net")
		if err != nil {
			t.Fatal(err)
		}
		if out != "clone github.com and report to burpcollaborator.net" {
			t.Fatalf("expected both untouched by default, got: %q", out)
		}
	})

	t.Run("bare 'allowlist' category disabled: both lists inactive", func(t *testing.T) {
		e, _ := newCorpusEngine(t)
		e.SetAllowPatterns(BuiltinAllowPatterns(map[string]bool{CategoryAllowlist: true}))
		out, err := e.Tokenize("clone github.com and report to burpcollaborator.net")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "github.com") || strings.Contains(out, "burpcollaborator.net") {
			t.Fatalf("expected both to be tokenized once the whole allowlist category is disabled, got: %q", out)
		}
	})

	t.Run("only wellknown_platforms disabled: github.com tokenized, burpcollaborator.net still exempt", func(t *testing.T) {
		e, _ := newCorpusEngine(t)
		e.SetAllowPatterns(BuiltinAllowPatterns(map[string]bool{
			CategoryAllowlist + "." + SubcategoryWellKnownPlatforms: true,
		}))
		out, err := e.Tokenize("clone github.com and report to burpcollaborator.net")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "github.com") {
			t.Errorf("expected github.com to be tokenized with wellknown_platforms disabled, got: %q", out)
		}
		if !strings.Contains(out, "burpcollaborator.net") {
			t.Errorf("expected burpcollaborator.net to stay untouched (only the OTHER subcategory was disabled), got: %q", out)
		}
	})

	t.Run("only security_testing_services disabled: burpcollaborator.net tokenized, github.com still exempt", func(t *testing.T) {
		e, _ := newCorpusEngine(t)
		e.SetAllowPatterns(BuiltinAllowPatterns(map[string]bool{
			CategoryAllowlist + "." + SubcategorySecurityTestingServices: true,
		}))
		out, err := e.Tokenize("clone github.com and report to burpcollaborator.net")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "github.com") {
			t.Errorf("expected github.com to stay untouched (only the OTHER subcategory was disabled), got: %q", out)
		}
		if strings.Contains(out, "burpcollaborator.net") {
			t.Errorf("expected burpcollaborator.net to be tokenized with security_testing_services disabled, got: %q", out)
		}
	})

	t.Run("only web_infrastructure disabled: jsdelivr.net tokenized, github.com still exempt", func(t *testing.T) {
		e, _ := newCorpusEngine(t)
		e.SetAllowPatterns(BuiltinAllowPatterns(map[string]bool{
			CategoryAllowlist + "." + SubcategoryWebInfrastructure: true,
		}))
		out, err := e.Tokenize("clone github.com and load cdn.jsdelivr.net/npm/vue")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "github.com") {
			t.Errorf("expected github.com to stay untouched (only the OTHER subcategory was disabled), got: %q", out)
		}
		if strings.Contains(out, "jsdelivr.net") {
			t.Errorf("expected jsdelivr.net to be tokenized with web_infrastructure disabled, got: %q", out)
		}
	})
}

// TestBuiltinAllowlist_BlockAddDoesNotOverridePerValue pins the real
// precedence rule: a block-list entry for a value that's ALSO covered
// by an active allow-pattern has no effect; Engine.filterAllowed drops
// a Detection by its matched value alone, regardless of which Detector
// produced it, so allow always wins over block, including over a
// user-added block entry for something in the BUILT-IN allowlist. The
// only correct way to force tokenization of a built-in-allowlisted
// domain is disabling its category (see
// TestBuiltinAllowPatterns_CategorizedAndToggleable), not block-add;
// see BuiltinAllowPatterns' doc comment.
func TestBuiltinAllowlist_BlockAddDoesNotOverridePerValue(t *testing.T) {
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	blockPattern := regexp.MustCompile(`(?i)pastebin\.com`)
	e := New(store, append(DefaultDetectors(), NewBlockDetector([]*regexp.Regexp{blockPattern}))...)

	out, err := e.Tokenize("check pastebin.com and also github.com")
	if err != nil {
		t.Fatal(err)
	}
	if out != "check pastebin.com and also github.com" {
		t.Fatalf("expected block-add for a built-in-allowlisted value to have NO effect (allow always wins), got: %q", out)
	}
}
