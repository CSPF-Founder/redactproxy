package redact

import (
	"path/filepath"
	"testing"
	"unicode/utf8"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// FuzzEngineTokenizeDetokenize fuzzes Engine.Tokenize/Detokenize, the
// core text-in, text-out redaction path every request and response body
// eventually funnels through (via jsonwalk's per-field calls).
//
// Deliberately a single free-form string input, not a structured/typed
// set of fields built to look like known PII shapes: the fuzzer already
// gets realistic PII shapes from the seed corpus below and is free to
// mutate them into byte sequences no seed or hand-written test would
// think to try. A more constrained target (e.g. separate prefix/secret/
// suffix fields) would make it easier to assert a semantic "the known
// secret never survives" property, but only for whatever the harness
// already knows is a secret, exactly the kind of already-known-shape
// testing this is meant to go beyond.
//
// The invariants checked are deliberately narrow and false-positive
// free rather than a strict byte-exact round-trip: several entity types
// (domains, MAC addresses, Aadhaar numbers, international phone numbers)
// are stored and restored in a canonical form by design (see e.g.
// domainDetector.Detect's case-folding comment), so "Detokenize(Tokenize(x))
// == x" does not hold in general even with zero bugs. What must always
// hold regardless of any detector's own canonicalization choices:
//   - Tokenize and Detokenize never panic or hang on any input.
//   - Neither ever turns valid UTF-8 into invalid UTF-8.
//   - Tokenizing the identical text twice against the same store
//     produces byte-identical output both times (every real value is
//     already minted after the first call, so the second call has
//     nothing left to decide differently).
//   - If Tokenize makes no change at all, Detokenize must also make no
//     change (nothing was replaced, so there is nothing for Detokenize
//     to find and restore).
func FuzzEngineTokenizeDetokenize(f *testing.F) {
	dir := f.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		f.Fatalf("tokenstore.Open: %v", err)
	}
	f.Cleanup(func() { store.Close() })
	e := New(store, DefaultDetectors()...)

	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		out1, err1 := e.Tokenize(text)
		if err1 != nil {
			return // a detector rejected this input on purpose (e.g. not valid JSON, if ever routed there) -- not a bug
		}
		if utf8.ValidString(text) && !utf8.ValidString(out1) {
			t.Fatalf("Tokenize turned valid UTF-8 into invalid UTF-8:\n  in:  %q\n  out: %q", text, out1)
		}

		out2, err2 := e.Tokenize(text)
		if err2 != nil {
			t.Fatalf("Tokenize(text) succeeded once then failed on the identical input: %v", err2)
		}
		if out1 != out2 {
			t.Fatalf("Tokenize(text) is not deterministic against its own store:\n  first:  %q\n  second: %q", out1, out2)
		}

		back := e.Detokenize(out1)
		if utf8.ValidString(out1) && !utf8.ValidString(back) {
			t.Fatalf("Detokenize turned valid UTF-8 into invalid UTF-8:\n  in:  %q\n  out: %q", out1, back)
		}

		if out1 == text {
			backNoop := e.Detokenize(text)
			if backNoop != text {
				t.Fatalf("Tokenize made no change, but Detokenize altered the same text anyway:\n  text: %q\n  got:  %q", text, backNoop)
			}
		}
	})
}

// FuzzEngineDetokenizeArbitrary fuzzes Detokenize directly on free-form
// text, NOT restricted to a prior Tokenize call's own output -- unlike
// the round-trip fuzzer above, which only ever asks Detokenize to
// resolve tokens it just minted itself. Detokenize's real input is
// whatever the upstream API sends back: content this proxy does not
// control and that Detokenize must handle correctly (or at minimum, not
// crash on) even when it is adversarial or merely coincidentally
// token-shaped -- e.g. a model quoting back a URL or an identifier from
// a fetched web page that happens to start with "tok" or "555-", or
// (per SafeFlushPoint's own doc comment) a raw streamed chunk handed
// straight to Detokenize per content block.
//
// Every store lookup a fresh store like this one performs is a miss, so
// this exercises exactly the fail-open "not a token we know about,
// leave it as literal text" path throughout -- the seeds below are
// shaped to look like every real token format (see
// tokenstore/generator.go's Token*Prefix constants) specifically to
// drive as many detokenizeXTokens candidate regexes as possible into
// that path, including the ones that parse the candidate through
// something that can itself error or panic on a malformed string
// (netip.ParseAddr for IPv6, arithmetic on capture-group boundaries for
// the domain/suffix-echo reconstruction).
func FuzzEngineDetokenizeArbitrary(f *testing.F) {
	dir := f.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		f.Fatalf("tokenstore.Open: %v", err)
	}
	f.Cleanup(func() { store.Close() })
	e := New(store, DefaultDetectors()...)

	seeds := append([]string{}, fuzzSeeds...)
	seeds = append(seeds,
		"tok1a2b3c4d5e6f7890.com",
		"tok1a2b3c4d5e6f7890.co.uk",
		"tokdeadbeefdeadbeef.net.net",
		"tok",
		"user-0123456789ab@tok0123456789abcdef.com",
		"user-",
		"198.18.1.2.3",
		"198.18.256.999",
		"fd00:c0de:ffff:ffff::1234",
		"fd00:c0de::",
		"fd00:c0de:zzzz::1",
		"555-0199",
		"555-01",
		"+91-555-0199",
		"+1-555-019999999999999999999999",
		"eyJredactedxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"tok-bearer-",
		"tok-bearer-\x00\x00",
	)
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		back := e.Detokenize(text)
		if utf8.ValidString(text) && !utf8.ValidString(back) {
			t.Fatalf("Detokenize turned valid UTF-8 into invalid UTF-8:\n  in:  %q\n  out: %q", text, back)
		}

		back2 := e.Detokenize(text)
		if back != back2 {
			t.Fatalf("Detokenize(text) is not deterministic against its own store:\n  first:  %q\n  second: %q", back, back2)
		}
	})
}

// fuzzSeeds gives the fuzzer a realistic starting point in a space it
// would otherwise have to find by chance: every built-in entity shape
// (credentials, network identifiers, PII) mixed into surrounding prose,
// several scripts and Unicode edge cases already known to matter
// (invisible/format characters, IDN domains, directional overrides),
// structural edge cases (empty string, an already-tokenized-looking
// value, deeply nested-looking punctuation), and a few large/degenerate
// inputs.
var fuzzSeeds = []string{
	"",
	" ",
	"\n\t\r",
	"plain prose with no PII at all, nothing to see here",

	// core entity shapes, alone and embedded in prose
	"contact admin@widgetcorp-fixture.com about the finding",
	"internal host is fileserver.corp.widgetcorp-fixture.local",
	"nmap scan of 10.20.30.40 found port 445 open",
	"IPv6 mgmt interface at fe80::a1b2:c3d4:e5f6:7890",
	"call the on-call engineer at 415-867-5309",
	"regional contact: +91 98214 67359",
	"AA:BB:CC:DD:EE:FF is the device's MAC address",
	"AWS key found in a public .env: AKIAIOSFODNN7EXAMPLE",
	"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	githubPATPrefix + "1234567890abcdef1234567890abcdef1234",
	"Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
	"WORKSTATION01$:1105:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::",
	"Aadhaar on file: 234123412346",
	"PAN: ABCPE1234F",
	"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxyz1234567890fakekeymaterial1234567890abcdefgh\n-----END RSA PRIVATE KEY-----",
	slackWebhookPrefix + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
	"Server=tcp:widgetcorp-prod.database.windows.net;User=sa;Password=Sup3rSecretDbPW!",

	// doubled/tripled TLD suffix -- an LLM restating a domain and
	// duplicating the TLD by mistake, or the same pattern nested deeper
	"internal host is svc-b.widgetcorp-fixture.net.net for the pivot",
	"host is widgetcorp-fixture.net.net.net repeated again",
	"double-suffix tenant SaaS: xyzexamplecorp.okta.com.com maybe",
	"co.uk doubled: widgetcorp-fixture.co.uk.co.uk seen in the wild",
	"widgetcorp-fixture.net.net and widgetcorp-fixture.net.net repeated twice in one message",

	// Unicode / non-ASCII, including domain/email edge cases (invisible
	// format characters, IDN labels, doubled/repeated Unicode content)
	"münchen-realtest.de",
	"visit https://münchenmün.com and email useraa@münchenmün.com",
	"xyzexample\u200bhiddenchartest.com",
	"see hiddenchartest\u200b.com now",
	"here is the value: \u202ewidgetcorp-fixture.com\u202c -- please use it",
	"这是一个重要的网站widgetcorp-fixture.com请访问谢谢",
	"这是一段完全没有任何网址的中文句子测试一下",
	"посетите widgetcorp-fixture.com сайт",
	"café-fixture.com",
	"🔥widgetcorp-fixture.com🔥",
	string([]byte{0xff, 0xfe, 0xfd}), // invalid UTF-8
	string([]byte{0xc3}),             // truncated multi-byte sequence

	// structural edge cases
	"tok1a2b3c4d5e6f7890.com",                                              // shaped like this tool's own domain token
	"user-0123456789ab@tok0123456789abcdef.com",                            // shaped like this tool's own email token
	"widgetcorp-fixture.com widgetcorp-fixture.com widgetcorp-fixture.com", // repeated
	"admin@widgetcorp-fixture.com and admin@widgetcorp-fixture.com again",
	"nested \"admin@widgetcorp-fixture.com\" 'inside quotes' `and backticks`",
	"a.b.c.d.e.f.widgetcorp-fixture.com",
	"widgetcorp-fixture.com.widgetcorp-fixture.com",
	"://widgetcorp-fixture.com",
	"widgetcorp-fixture.com:8443/path?q=1&r=admin@widgetcorp-fixture.com",

	// mixed real report snippet
	"whois + subdomain enum for Widgetcorp:\nwidgetcorp-fixture.com -- registered, DC at dc01.corp.widgetcorp-fixture.local (10.20.30.5)\nstaff found via LinkedIn/breach data: priya.nair@widgetcorp-fixture.com\nIT escalation line: 415-867-5309",

	// vendor credential formats with no representation above -- added
	// specifically so mutation-based fuzzing has a real starting point
	// inside each detector's own post-regex Go logic (a cross-detector
	// deferral check, a context-window search, a submatch extraction),
	// not just its bare regex match. Random byte mutation starting from
	// ordinary prose has no realistic chance of independently
	// discovering a fixed multi-character prefix like "AIzaSy" or a
	// ".atlasv1." infix, so without a seed for each of these, the
	// corresponding branch of that detector's Detect was effectively
	// unreachable by this fuzzer. Every value below deliberately avoids
	// the substring "FAKE"/"fake" -- several detectors treat that
	// specific substring as "already a token" and would skip real
	// detection logic entirely on a seed containing it.
	"gitlab token: " + gitlabPATPrefix + "aB3dE5fG7hJ9kL1mN2pQ4",
	"slack token " + slackBotPrefix + "01234567890-01234567890aB3dE5fG7h in the message",
	"stripe secret " + stripeLivePrefix + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0 seen in config",
	"google api key " + googleAPIKeyPrefix + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYa found",
	npmPrefix + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3d in .npmrc",
	"twilio account sid " + twilioSIDPrefix + "0123456789abcdef0123456789abcdef",
	"sendgrid key " + sendGridPrefix + "aB3dE5fG7hJ9kL1mN2pQ4r.aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3dE5fG7hJ",
	"digitalocean token " + digitalOceanPrefix + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	"cloudflare token " + cloudflarePrefix + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3dE5fG01234567",
	"AccountKey=aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3dE5fG7hJ9kL1mN2pQ4r== in the connection config",
	"artifactory key " + artifactoryPrefix + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3dE",
	dockerHubPrefix + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8 docker hub token",
	"circleci " + circleCIPrefix + "aB3dE5fG7hJ9kL1mN2pQ4r_0123456789abcdef0123456789abcdef01234567",
	"terraform token aB3dE5fG7hJ9kL" + terraformInfix + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3",
	"snyk org token 01234567-0123-0123-0123-0123456789ab",
	"bitbucket app password " + bitbucketPrefix + "aB3dE5fG7hJ9kL1mN2pQ4rS6",
	"vault token " + vaultPrefix + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3dE5fG7hJ9kL1mN2pQ4rS6tU8v",
	"openai key " + openAIProjectPrefix + "aB3dE5fG7hJ9kL1mN2pQT3BlbkFJaB3dE5fG7hJ9kL1mN2pQ",
	"anthropic key " + anthropicPrefix + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vWAA",
	"razorpay key " + razorpayLivePrefix + "aB3dE5fG7hJ9kL",
	"csrf_token=ImMyYjM3YWJhN2RlNzg0MDM0NDgwOTM3ZjhjMGU2ZjI5ZGVjMzVmZjYi.Dudyfw.q4PuqxwtjVP8GhkK5xzf1dsLYg in the form",
	`GPP cpassword="j1Uyj3Vx8Tad9YbedtLI3sJ6vqvNMbfhrjIYYZH21g==" found in Groups.xml`,
	"secretsdump line: WORKSTATION02$:1105:0123456789abcdef0123456789abcdef:0123456789abcdef0123456789abcdef:::",
	"you can use this API key aB3dE5fG7hJ9kL1mN2pQ4rS6tU8 to authenticate",
	"mongodb+srv://dbuser:S3cretPass123@cluster0.abcde-fixture.mongodb.net/mydb connection string",

	// Verhoeff-checksum boundary for Aadhaar: 234123412346 is a genuine
	// (non-degenerate) verhoeff-valid 12-digit number; 234123412347 is
	// the adjacent check-digit value, verhoeff-invalid, so mutation
	// starting near either seed can explore both sides of the checksum
	// gate directly rather than needing to discover a valid checksum by
	// chance across the full 10-value space.
	"Aadhaar 234123412346 valid checksum",
	"Aadhaar 234123412347 invalid checksum",
	// PAN holder-code boundary: ABCPE1234F has holder code 'P'
	// (individual, valid); ABCXE1234F has 'X', not in the documented
	// holder-code set.
	"PAN ABCXE1234F invalid holder code",
}
