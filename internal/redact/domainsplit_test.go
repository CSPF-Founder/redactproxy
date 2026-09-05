package redact

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// TestDomainDetect_UnderscoreGluedPrefix is a regression test for a real
// leak found live: a domain glued directly onto a preceding identifier
// via underscore -- e.g. a locally-created filename like
// "hdr_widgetcorp-fixture.com" (a genuinely common pattern: dumping a
// captured response to a file named after its target) -- was invisible
// to domainLabelUnicodeRe entirely. RE2's \b treats "_" as a word character, so no
// boundary ever fired between "_" and the domain's first letter, and the
// WHOLE domain (not just a fragment) escaped detection. Confirmed before
// the fix: domainDetector{}.Detect("hdr_widgetcorp-fixture.com") returned
// zero detections.
func TestDomainDetect_UnderscoreGluedPrefix(t *testing.T) {
	dets, err := domainDetector{}.Detect("cat /tmp/hdr_widgetcorp-fixture.com | head -1")
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d: %+v", len(dets), dets)
	}
	d := dets[0]
	if got := "cat /tmp/hdr_widgetcorp-fixture.com | head -1"[d.Start:d.End]; got != "widgetcorp-fixture.com" {
		t.Errorf("detected span = %q, want %q", got, "widgetcorp-fixture.com")
	}
}

// TestDomainDetect_BareFilenameExemptionStillWorks pins that a bare
// (no-subdomain, no-scheme) mention in a filename-collision TLD is still
// correctly exempted after the regex rework -- e.g. "crt.sh" with no
// surrounding evidence is still a plausible shell-script filename
// mention, not a domain, exactly as before the fix.
func TestDomainDetect_BareFilenameExemptionStillWorks(t *testing.T) {
	dets, err := domainDetector{}.Detect("run get-crt.sh now")
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) != 0 {
		t.Fatalf("expected 0 detections (bare filename-collision exemption), got %d: %+v", len(dets), dets)
	}
}

// TestEngine_BlockListSafetyPass_CatchesOrgNameInPreservedSubdomainLabel
// is a regression test for a real leak found live: a customer's own name
// (an explicit block rule) survives when it appears as a NON-adjacent
// subdomain label in a multi-level hostname -- e.g. an Akamai CNAME
// target shaped like "www.<customer>.<edge-hash>.edgekey.net". The domain
// detector only ever redacts the single label immediately before the
// recognized public suffix (the edge-hash here), and preserves every
// other label -- including the customer's real name -- as "safe"
// subdomain-prefix text. Because the domain detection's span covers the
// WHOLE hostname, it wins overlap resolution against the block
// detector's own independent match on the same substring, silently
// suppressing it. Fixed with an unconditional final safety pass (see
// Engine.blockListSafetyPass) that re-scans the block patterns against
// the already-substituted output -- a no-op for every correctly-handled
// occurrence, since those no longer contain the literal string, but a
// real backstop for exactly this case.
func TestEngine_BlockListSafetyPass_CatchesOrgNameInPreservedSubdomainLabel(t *testing.T) {
	e, _ := newCorpusEngine(t)
	e.SetDetectors(append(DefaultDetectors(), NewBlockDetector([]*regexp.Regexp{
		regexp.MustCompile(`(?i)widgetcorp`),
	})))

	in := "www.widgetcorp.abcdef1234567890.edgekey.net"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "widgetcorp") {
		t.Fatalf("LEAK: org name survived as a preserved subdomain label: %q", out)
	}
	back := e.Detokenize(out)
	if back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

// TestSplitDomain_DoubledTLDSuffix is a regression test for a real leak
// found in a production engagement: golang.org/x/net/publicsuffix's
// EffectiveTLDPlusOne only ever looks one label to the left of the
// recognized public suffix. When that suffix appears twice in a row
// (e.g. an LLM restating a domain in its own write-up and accidentally
// duplicating the TLD), the "one label left" it finds is the suffix's
// own second occurrence, not the real organization label another step
// further left, which never gets classified as orgLabel at all.
func TestSplitDomain_DoubledTLDSuffix(t *testing.T) {
	parts, ok := splitDomain("svc-b.widgetcorp.net.net")
	if !ok {
		t.Fatal("expected splitDomain to succeed")
	}
	if parts.orgLabel != "widgetcorp" {
		t.Errorf("orgLabel = %q, want %q", parts.orgLabel, "widgetcorp")
	}
	if parts.suffix != "net.net" {
		t.Errorf("suffix = %q, want %q", parts.suffix, "net.net")
	}
	if parts.subdomainPrefix != "svc-b." {
		t.Errorf("subdomainPrefix = %q, want %q", parts.subdomainPrefix, "svc-b.")
	}
	if parts.registrable != "widgetcorp.net.net" {
		t.Errorf("registrable = %q, want %q", parts.registrable, "widgetcorp.net.net")
	}
}

// TestSplitDomain_DoubledTLDSuffix_NoSubdomain covers the bare
// registrable-domain case (no subdomain prefix at all) with the same
// doubled-suffix shape.
func TestSplitDomain_DoubledTLDSuffix_NoSubdomain(t *testing.T) {
	parts, ok := splitDomain("widgetcorp.net.net")
	if !ok {
		t.Fatal("expected splitDomain to succeed")
	}
	if parts.orgLabel != "widgetcorp" {
		t.Errorf("orgLabel = %q, want %q", parts.orgLabel, "widgetcorp")
	}
	if parts.subdomainPrefix != "" {
		t.Errorf("subdomainPrefix = %q, want empty", parts.subdomainPrefix)
	}
}

// TestSplitDomain_NormalDomainsUnaffected pins that the doubled-suffix
// correction never triggers for ordinary domains, including ones whose
// organization label happens to itself look TLD-shaped as long as it
// doesn't literally repeat the suffix immediately next to it.
func TestSplitDomain_NormalDomainsUnaffected(t *testing.T) {
	cases := []struct {
		fqdn            string
		wantOrgLabel    string
		wantSuffix      string
		wantSubdomain   string
		wantRegistrable string
	}{
		{"widgetcorp-fixture.com", "widgetcorp-fixture", "com", "", "widgetcorp-fixture.com"},
		{"portal.widgetcorp-fixture.com", "widgetcorp-fixture", "com", "portal.", "widgetcorp-fixture.com"},
		{"xyzexample.co.uk", "xyzexample", "co.uk", "", "xyzexample.co.uk"},
		{"art.com", "art", "com", "", "art.com"}, // org label happens to be a real gTLD word, but doesn't repeat "com"
		{"sub.art.com", "art", "com", "sub.", "art.com"},
	}
	for _, c := range cases {
		t.Run(c.fqdn, func(t *testing.T) {
			parts, ok := splitDomain(c.fqdn)
			if !ok {
				t.Fatalf("expected splitDomain(%q) to succeed", c.fqdn)
			}
			if parts.orgLabel != c.wantOrgLabel {
				t.Errorf("orgLabel = %q, want %q", parts.orgLabel, c.wantOrgLabel)
			}
			if parts.suffix != c.wantSuffix {
				t.Errorf("suffix = %q, want %q", parts.suffix, c.wantSuffix)
			}
			if parts.subdomainPrefix != c.wantSubdomain {
				t.Errorf("subdomainPrefix = %q, want %q", parts.subdomainPrefix, c.wantSubdomain)
			}
			if parts.registrable != c.wantRegistrable {
				t.Errorf("registrable = %q, want %q", parts.registrable, c.wantRegistrable)
			}
		})
	}
}

// TestSplitDomain_GenuineRepeatedWordDomainWithNoSubdomain documents the
// accepted, narrow tradeoff of the doubled-suffix fix: a domain whose
// REAL registrable name is itself a repeated word matching its own TLD
// (a rare "domain hack" style registration, e.g. "io.io") still splits
// correctly as long as there's no subdomain in front of it; the
// doubled-suffix walk-left loop only ever triggers when there's
// something further left to walk into.
func TestSplitDomain_GenuineRepeatedWordDomainWithNoSubdomain(t *testing.T) {
	parts, ok := splitDomain("io.io")
	if !ok {
		t.Fatal("expected splitDomain to succeed")
	}
	if parts.orgLabel != "io" || parts.suffix != "io" {
		t.Errorf("orgLabel/suffix = %q/%q, want io/io", parts.orgLabel, parts.suffix)
	}
}

// TestDetokenize_DomainTokenGluedToPrecedingUnderscore is a regression
// test for a real bug found live, the detokenize-direction mirror of
// TestDomainDetect_UnderscoreGluedPrefix above: a model echoing a
// previously-tokenized value verbatim (exactly what it's supposed to do)
// wrote it as part of a locally-created filename like
// "hdr_tok<hex>.com" -- domainTokenRe's old bare \b never fires between
// "_" and the token's first character, so detokenization silently
// skipped it and the raw token, not the real value, reached the
// operator's own terminal. Fixed the same way as the tokenize-direction
// bug: the boundary moved into a capture group so "_" (like any other
// non-alphanumeric character) now correctly separates the token from
// what precedes it.
func TestDetokenize_DomainTokenGluedToPrecedingUnderscore(t *testing.T) {
	e, _ := newCorpusEngine(t)

	tokenized, err := e.Tokenize("saved as /tmp/hdr_widgetcorp-fixture.com for later diffing")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tokenized, "widgetcorp-fixture.com") {
		t.Fatalf("expected the domain to be tokenized on the way out, got %q", tokenized)
	}

	back := e.Detokenize(tokenized)
	if back != "saved as /tmp/hdr_widgetcorp-fixture.com for later diffing" {
		t.Fatalf("expected the underscore-glued token to detokenize back to the real value, got %q", back)
	}
}

// TestDomainDetect_ForceAsDomainBypassesBareFilenameExemption is the
// mirror of TestDomainDetect_BareFilenameExemptionStillWorks: the same
// bare, no-subdomain mention in a filename-collision TLD that's normally
// exempted must be treated as a real domain when it's in forceAsDomain
// (populated from an operator's own rules.json block entry for exactly
// this bare registrable domain; see rules.Compiled.ForcedDomains).
func TestDomainDetect_ForceAsDomainBypassesBareFilenameExemption(t *testing.T) {
	d := domainDetector{forceAsDomain: map[string]bool{"widgetcorp-fixture.do": true}}
	dets, err := d.Detect("checked widgetcorp-fixture.do, found the admin panel")
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection once widgetcorp-fixture.do is force-listed, got %d: %+v", len(dets), dets)
	}
	if got := "checked widgetcorp-fixture.do, found the admin panel"[dets[0].Start:dets[0].End]; got != "widgetcorp-fixture.do" {
		t.Errorf("detected span = %q, want %q", got, "widgetcorp-fixture.do")
	}

	// An unrelated domain under the same collision-prone TLD, NOT in the
	// force list, must still be exempted exactly as before -- the force
	// list is per-domain, not a blanket toggle for the whole TLD.
	dets2, err := d.Detect("run get-crt.sh now")
	if err != nil {
		t.Fatal(err)
	}
	if len(dets2) != 0 {
		t.Fatalf("expected 0 detections for a domain NOT in the force list, got %d: %+v", len(dets2), dets2)
	}
}

// TestDomainDetect_ForceAsDomainInternalOnlyTLD is the fallback path for
// a domain whose TLD isn't a recognized public suffix at all -- an
// Active Directory forest name, a purely-internal naming scheme
// (something like "printer.mycorpad", not on any public suffix list and
// not one of tlds.go's curated "local"/"internal" exceptions either).
// domainReplacement never validates these on its own; forcedDomainSuffix
// is the fallback that trusts the operator's own IsDomain assertion
// instead. Must still work with a subdomain (preserved as literal
// prefix) and reject an unrelated domain not in the force list.
func TestDomainDetect_ForceAsDomainInternalOnlyTLD(t *testing.T) {
	if _, _, ok := DomainRegistrablePart("fileserver.mycorpad"); ok {
		t.Fatal("test premise broken: \"mycorpad\" is apparently already a recognized suffix")
	}

	d := domainDetector{forceAsDomain: map[string]bool{"fileserver.mycorpad": true}}

	dets, err := d.Detect("connect to fileserver.mycorpad now")
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection for the bare internal domain, got %d: %+v", len(dets), dets)
	}
	if got := "connect to fileserver.mycorpad now"[dets[0].Start:dets[0].End]; got != "fileserver.mycorpad" {
		t.Errorf("detected span = %q, want %q", got, "fileserver.mycorpad")
	}

	in := "printer1.fileserver.mycorpad is offline"
	dets2, err := d.Detect(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(dets2) != 1 {
		t.Fatalf("expected 1 detection with the subdomain preserved, got %d: %+v", len(dets2), dets2)
	}
	if got := in[dets2[0].Start:dets2[0].End]; got != "printer1.fileserver.mycorpad" {
		t.Errorf("detected span = %q, want %q", got, "printer1.fileserver.mycorpad")
	}
	if dets2[0].Lookups[0].Real != "fileserver.mycorpad" {
		t.Errorf("expected the lookup key to be the registrable part only, got %q", dets2[0].Lookups[0].Real)
	}

	dets3, err := d.Detect("connect to otherhost.notmycorpad now")
	if err != nil {
		t.Fatal(err)
	}
	if len(dets3) != 0 {
		t.Fatalf("expected 0 detections for a domain NOT in the force list, got %d: %+v", len(dets3), dets3)
	}
}

// TestLooksLikeHostname pins the syntactic-only check: an internal-only
// TLD passes (it's still a real hostname shape), but a URL, an email,
// and an arbitrary string all correctly fail -- same grammar domainLabelUnicodeRe
// itself requires, so nothing LooksLikeHostname accepts could ever be
// permanently unmatchable by the real scanning path.
func TestLooksLikeHostname(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"fileserver.mycorpad", true},
		{"widgetcorp-fixture.do", true},
		{"https://widgetcorp-fixture.do", false},
		{"admin@widgetcorp-fixture.do", false},
		{"XyzExampleCorp", false},
		{"widgetcorp-fixture.do/path", false},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			if got := LooksLikeHostname(tc.value); got != tc.want {
				t.Errorf("LooksLikeHostname(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// TestDomainRegistrablePart pins the exact bare-vs-subdomain distinction
// the CLI's block-add warning and rules.Compiled.ForcedDomains both rely
// on: only the bare registrable domain qualifies, not "www." or a real
// subdomain, and a non-domain string or an RFC-reserved example domain
// is correctly rejected outright.
func TestDomainRegistrablePart(t *testing.T) {
	cases := []struct {
		name            string
		value           string
		wantRegistrable string
		wantBare        bool
		wantOK          bool
	}{
		{"bare domain", "widgetcorp-fixture.do", "widgetcorp-fixture.do", true, true},
		{"bare domain, mixed case", "Widgetcorp-Fixture.DO", "widgetcorp-fixture.do", true, true},
		{"subdomain", "admin.widgetcorp-fixture.do", "widgetcorp-fixture.do", false, true},
		{"www prefix", "www.widgetcorp-fixture.do", "widgetcorp-fixture.do", false, true},
		{"not a domain at all", "XyzExampleCorp", "", false, false},
		{"RFC 2606 reserved example domain", "example.com", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registrable, isBare, ok := DomainRegistrablePart(tc.value)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if registrable != tc.wantRegistrable {
				t.Errorf("registrable = %q, want %q", registrable, tc.wantRegistrable)
			}
			if isBare != tc.wantBare {
				t.Errorf("isBare = %v, want %v", isBare, tc.wantBare)
			}
		})
	}
}

// TestForcedDomain_ConsistentAcrossSubdomainEmailURL is a regression test
// for a real corruption bug found live: before ForcedDomains existed, a
// block-listed bare domain and a LATER subdomain/email/URL occurrence of
// the same domain in the same text collided in the token store (keyed by
// real value alone, not by entity type) -- the domain detector's
// structure-preserving template wrapped the block detector's already-
// opaque token with its own literal suffix, producing garbage like
// "admin.tok-blocked-....do" that didn't even round-trip correctly.
// With the domain detector force-unlocked for this exact registrable
// domain instead, it owns every occurrence consistently and correctly.
func TestForcedDomain_ConsistentAcrossSubdomainEmailURL(t *testing.T) {
	forceAsDomain := map[string]bool{"widgetcorp-fixture.do": true}
	cases := []string{
		"Their storefront is widgetcorp-fixture.do. Their admin panel is at admin.widgetcorp-fixture.do.",
		"Their storefront is widgetcorp-fixture.do. Contact admin@widgetcorp-fixture.do for support.",
		"Their storefront is widgetcorp-fixture.do. See https://admin.widgetcorp-fixture.do/login for the portal.",
	}
	for _, text := range cases {
		t.Run(text, func(t *testing.T) {
			store, err := tokenstore.Open(filepath.Join(t.TempDir(), "tokens.db"))
			if err != nil {
				t.Fatalf("tokenstore.Open: %v", err)
			}
			defer store.Close()
			dets := FilterDetectors(DefaultCategorizedDetectorsWithForcedDomains(forceAsDomain), nil)
			e := New(store, dets...)

			out, err := e.Tokenize(text)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, "widgetcorp-fixture.do") {
				t.Errorf("real domain leaked: %q", out)
			}
			if back := e.Detokenize(out); back != text {
				t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", text, out, back)
			}
		})
	}
}
