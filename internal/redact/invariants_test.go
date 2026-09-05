package redact

import "testing"

// This file tests every registered detector (DefaultCategorizedDetectors)
// against the same set of first-principles invariants that MUST hold
// for any entity type in this system, rather than one bespoke test per
// detector: a systematic sweep catches the "forgot to update the
// detokenize side" class of bug that scenario-specific tests can easily
// miss if nobody happens to write a round-trip test for that exact new
// detector.
//
// The five invariants, checked for every case:
//  1. Detection actually fires: the input changes when tokenized.
//  2. Idempotency: tokenizing already-tokenized output leaves it
//     unchanged (a token is never mistaken for a new real value).
//  3. Stability: tokenizing the same real input twice (same engine/
//     store) produces byte-identical output both times.
//  4. Round-trip fidelity: Detokenize(Tokenize(in)) reconstructs the
//     original exactly, UNLESS the entity has a documented, deliberate
//     normalization (e.g. intl phone numbers restore to canonical E.164,
//     not the original human spacing; see invariantCase.roundTripWant).
//  5. No false collision: two different real values of the same entity
//     type never produce identical tokenized output.
type invariantCase struct {
	name string // category.subcategory, matching CategorizedDetector.Name()
	// in1, in2 are two DIFFERENT short texts, each embedding exactly one
	// real value of this entity type in realistic surrounding context.
	in1, in2 string
	// roundTripWant overrides the expected Detokenize(Tokenize(in1))
	// result when it's NOT byte-identical to in1, only for entities
	// with a documented normalization. Empty means "must equal in1
	// exactly."
	roundTripWant string
}

func invariantCases(t *testing.T) []invariantCase {
	t.Helper()
	aadhaar1 := validAadhaar(t, "23456789012")
	aadhaar2 := validAadhaar(t, "34567890123")
	return []invariantCase{
		{name: "contact.email",
			in1: "contact admin@widgetcorp-fixture.com",
			in2: "contact jane.doe@othercorp-fixture.io"},
		{name: "network.domain",
			in1: "target widgetcorp-fixture.com",
			in2: "target othercorp-fixture.io"},
		{name: "network.ipv4",
			in1: "host 104.248.115.96",
			in2: "host 128.199.134.38"},
		{name: "network.ipv6",
			in1: "host 2001:aaaa:bbbb::1234",
			in2: "host 2001:cccc:dddd::5678"},
		{name: "network.mac",
			in1: "arp: aa:bb:cc:dd:ee:ff",
			in2: "arp: 11:22:33:44:55:66"},
		{name: "contact.phone",
			in1: "call +1 555-867-5309",
			in2: "call +1 555-234-9876"},
		{name: "contact.intl_phone",
			in1:           "call +91 98123 45678",
			in2:           "call +44 20 7946 0958",
			roundTripWant: "call +919812345678"},
		{name: "secrets.jwt",
			in1: "Authorization header carried eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c in the request",
			in2: "Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMxMjMifQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
		{name: "secrets.bearer_token",
			in1: "curl -H 'Authorization: Bearer sk-test-abcdefghijklmnopqrstuvwxyz0123456789' https://api.example-fixture.com",
			in2: "curl -H 'Authorization: Bearer zz-test-zyxwvutsrqponmlkjihgfedcba9876543210' https://api.example-fixture.com"},
		{name: "secrets.pem_key",
			in1: "cat id_rsa:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL\n-----END RSA PRIVATE KEY-----\ndone",
			in2: "cat id_rsa:\n-----BEGIN RSA PRIVATE KEY-----\nZZZZpZIBAAKCAQEAzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n-----END RSA PRIVATE KEY-----\ndone"},
		{name: "secrets.connection_string",
			in1: "connect via mongodb://dbadmin:S3cr3tP@ss@10.0.0.5:27017/prod",
			in2: "connect via mongodb://otheruser:Passw0rd1@10.0.0.6:27017/prod"},
		{name: "secrets.itsdangerous_token",
			in1: `body: "csrf_token=ImMyYjM3YWJhN2RlNzg0MDM0NDgwOTM3ZjhjMGU2ZjI5ZGVjMzVmZjYi.Dudyfw.q4PuqxwtjVP8GhkK5xzf1dsLYg&filesystem_id=..."`,
			in2: `body: "csrf_token=ImZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYi.Zzzzzz.zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz&filesystem_id=..."`},
		{name: "secrets.password_hash",
			in1: "password hash: 8846f7eaee8fb117ad06bdd830b7586c",
			in2: "password hash: e10adc3949ba59abbe56e057f20f883e"},
		{name: "windows_ad.machine_account",
			in1: "WORKSTATION01$:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::",
			in2: "FILESRV01$:1109:aad3b435b51404eeaad3b435b51404ee:c8825db10f2590d8e388b3d10da9f11c:::"},
		{name: "windows_ad.gpp_cpassword",
			in1: `cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLtl0BMPqDpMhpc4xUcyfEjIQ" newName="admin"`,
			in2: `cpassword="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" newName="admin"`},
		{name: "india_pii.aadhaar",
			in1:           "Aadhaar on file: " + aadhaar1,
			in2:           "Aadhaar on file: " + aadhaar2,
			roundTripWant: "Aadhaar on file: " + aadhaar1[:4] + " " + aadhaar1[4:8] + " " + aadhaar1[8:]},
		{name: "india_pii.pan",
			in1: "PAN on file: ABCPE1234F",
			in2: "PAN on file: ABCHE5678F"},
		{name: "vcs.github",
			in1: "leaked in .env: GITHUB_TOKEN=" + githubPATPrefix + "16C7e42F292c6912E7710c838347Ae178B4a",
			in2: "leaked in .env: GITHUB_TOKEN=" + githubPATPrefix + "99Z9e42F292c6912E7710c838347Ae178Z9Z"},
		{name: "vcs.gitlab",
			in1: "GITLAB_TOKEN=" + gitlabPATPrefix + "aBcDeFgHiJkLmNoPqRst",
			in2: "GITLAB_TOKEN=" + gitlabPATPrefix + "zZyYxXwWvVuUtTsSrRqQ"},
		{name: "vcs.bitbucket",
			in1: "git clone https://svc-account:" + bitbucketPrefix + "Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1@bitbucket.org/org/repo.git",
			in2: "git clone https://svc-account:" + bitbucketPrefix + "Zz9Zz9Zz9Zz9Zz9Zz9Zz9Zz9Zz9Zz9@bitbucket.org/org/repo.git"},
		{name: "collab.slack_token",
			in1: "SLACK_TOKEN=" + slackBotPrefix + "1234567890-1234567890-abcdefghijklmnopqrstuvwx",
			in2: "SLACK_TOKEN=" + slackBotPrefix + "9999999999-9999999999-zyxwvutsrqponmlkjihgfed"},
		{name: "collab.slack_webhook",
			in1: "webhook: https://" + slackWebhookPrefix + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
			in2: "webhook: https://" + slackWebhookPrefix + "T11111111/B11111111/YYYYYYYYYYYYYYYYYYYYYYYY"},
		{name: "payments.stripe",
			in1: "STRIPE_SECRET_KEY=" + stripeLivePrefix + "51H8xyzABCDEFGHIJKLMNOPQ",
			in2: "STRIPE_SECRET_KEY=" + stripeLivePrefix + "51Z9zyxABCDEFGHIJKLMNOPQ"},
		{name: "payments.razorpay",
			in1: "RAZORPAY_KEY_ID=" + razorpayLivePrefix + "ABCDEFGHIJKLMN",
			in2: "RAZORPAY_KEY_ID=" + razorpayLivePrefix + "ZYXWVUTSRQPONM"},
		{name: "ai_providers.openai",
			in1: "OPENAI_API_KEY=" + openAIPrefix + "Ab1cD2Ab1cD2Ab1cD2Ab1cD2Ab1cD2Ab1cD2Ab1cD2Ab1cD2T3BlbkFJeF3gH4eF3gH4eF3gH4eF3gH4eF3gH4eF3gH4eF3gH4eF3gH4",
			in2: "OPENAI_API_KEY=" + openAIPrefix + "Zz9yXz9yXz9yXz9yXz9yXz9yXz9yXz9yXz9yXz9yXz9yXz9yT3BlbkFJwQ8rS7wQ8rS7wQ8rS7wQ8rS7wQ8rS7wQ8rS7wQ8rS7wQ8rS7"},
		{name: "ai_providers.anthropic",
			in1: "ANTHROPIC_API_KEY=sk-ant-api03-" + repeatStr("aB1cD2eF3", 10) + "xyzAA",
			in2: "ANTHROPIC_API_KEY=sk-ant-api03-" + repeatStr("fE9dC8bA7", 10) + "xyzAA"},
		{name: "cloud.aws",
			in1: "AWS_ACCESS_KEY_ID=" + awsKeyIDPrefix + "ABCD1234EFGH5678",
			in2: "AWS_ACCESS_KEY_ID=" + awsKeyIDPrefix + "ZYXW9876VUTS5432"},
		{name: "cloud.digitalocean",
			in1: "DO_TOKEN=" + digitalOceanPrefix + "a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3abcd",
			in2: "DO_TOKEN=" + digitalOceanPrefix + repeatStr("f1e2d3", 10) + "1234"},
		{name: "cloud.cloudflare",
			in1: "CF_TOKEN=cfat_" + repeatStr("Ab1cD2eF3g", 4) + "a1b2c3d4",
			in2: "CF_TOKEN=cfat_" + repeatStr("Zx8wD1B2h0", 4) + "f1e2d3c4"},
		{name: "cloud.azure_storage_key",
			in1: "DefaultEndpointsProtocol=https;AccountName=mystore;AccountKey=" + repeatStr("aB3", 29) + "==;EndpointSuffix=core.windows.net",
			in2: "DefaultEndpointsProtocol=https;AccountName=mystore;AccountKey=" + repeatStr("cD5", 29) + "==;EndpointSuffix=core.windows.net"},
		{name: "cloud.artifactory",
			in1: "ARTIFACTORY_KEY=AKCp" + repeatStr("x9", 34) + "y",
			in2: "ARTIFACTORY_KEY=AKCp" + repeatStr("y8", 34) + "w"},
		{name: "cloud.dockerhub",
			in1: "DOCKER_TOKEN=dckr_pat_" + repeatStr("Ab1", 9),
			in2: "DOCKER_TOKEN=dckr_pat_" + repeatStr("Cd2", 9)},
		{name: "cloud.google_api_key",
			in1: "GOOGLE_API_KEY=" + googleAPIKeyPrefix + "D3xM9k2L8pQ7rN4vB1cE6fH0jK5sT9wZx",
			in2: "GOOGLE_API_KEY=" + googleAPIKeyPrefix + repeatStr("Zy9", 11)},
		{name: "cicd.circleci",
			in1: "CIRCLE_TOKEN=CCIPAT_" + repeatStr("Ab1cD2", 3) + "wxYZ_" + repeatStr("a1b2c3d4e5", 4),
			in2: "CIRCLE_TOKEN=CCIPAT_" + repeatStr("Zy9Xw8", 3) + "vuTS_" + repeatStr("f1e2d3c4b5", 4)},
		{name: "cicd.terraform",
			in1: "TF_TOKEN=a1B2c3D4e5F6gH.atlasv1." + repeatStr("a1B2c3D4e5", 6) + "a1B2c3D",
			in2: "TF_TOKEN=z9Y8x7W6v5U4tS.atlasv1." + repeatStr("z9Y8x7W6v5", 6) + "z9Y8x7W"},
		{name: "cicd.snyk",
			in1: "snyk auth token: 12345678-90ab-cdef-1234-567890abcdef",
			in2: "snyk auth token: fedcba98-76ab-cdef-4321-fedcba987654"},
		{name: "cicd.vault",
			in1: "VAULT_TOKEN=hvs." + repeatStr("aB1cD2eF3", 8) + "gH",
			in2: "VAULT_TOKEN=hvs." + repeatStr("zZ9yXw8vU7", 8) + "gH"},
		{name: "comms.twilio",
			in1: "TWILIO_ACCOUNT_SID=" + twilioSIDPrefix + "1234567890abcdef1234567890abcdef",
			in2: "TWILIO_ACCOUNT_SID=" + twilioSIDPrefix + repeatStr("fedcba9876543210", 2)},
		{name: "comms.sendgrid",
			in1: "SENDGRID_API_KEY=" + sendGridPrefix + "aBcDeFgHiJkLmNoPqRsT.uVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ012",
			in2: "SENDGRID_API_KEY=" + sendGridPrefix + "zZyYxXwWvVuUtTsSrRqQ.pPoOnNmMlLkKjJiIhHgGfFeEdDcCbBaA987654321zyx"},
		{name: "packages.npm",
			in1: "//registry.npmjs.org/:_authToken=" + npmPrefix + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
			in2: "//registry.npmjs.org/:_authToken=" + npmPrefix + "ZzYyXxWwVvUuTtSsRrQqPpOoNn9876543210"},
	}
}

// repeatStr avoids importing "strings" solely for Repeat in this file.
func repeatStr(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for range n {
		out = append(out, s...)
	}
	return string(out)
}

func TestAllDetectors_FirstPrinciplesInvariants(t *testing.T) {
	cases := invariantCases(t)

	// Coverage check: every registered detector must have a case here,
	// so a future detector added without a corresponding invariant case
	// fails loudly instead of just silently not being swept.
	covered := make(map[string]bool, len(cases))
	for _, tc := range cases {
		covered[tc.name] = true
	}
	for _, c := range DefaultCategorizedDetectors() {
		if !covered[c.Name()] {
			t.Errorf("no invariant case for registered detector %q; add one to invariantCases()", c.Name())
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTypesEngine(t)

			out1, err := e.Tokenize(tc.in1)
			if err != nil {
				t.Fatalf("Tokenize(in1) error: %v", err)
			}
			if out1 == tc.in1 {
				t.Fatalf("nothing detected/tokenized in in1: %q", tc.in1)
			}

			out1Again, err := e.Tokenize(out1)
			if err != nil {
				t.Fatalf("Tokenize(out1) error: %v", err)
			}
			if out1Again != out1 {
				t.Errorf("not idempotent: re-tokenizing already-tokenized output changed it:\n  out1:       %q\n  out1 again: %q", out1, out1Again)
			}

			out1Repeat, err := e.Tokenize(tc.in1)
			if err != nil {
				t.Fatalf("Tokenize(in1) second call error: %v", err)
			}
			if out1Repeat != out1 {
				t.Errorf("not stable: tokenizing the same real input twice gave different results:\n  out1:        %q\n  out1 repeat: %q", out1, out1Repeat)
			}

			want := tc.roundTripWant
			if want == "" {
				want = tc.in1
			}
			if back := e.Detokenize(out1); back != want {
				t.Errorf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q\n  want: %q", tc.in1, out1, back, want)
			}

			out2, err := e.Tokenize(tc.in2)
			if err != nil {
				t.Fatalf("Tokenize(in2) error: %v", err)
			}
			if out2 == tc.in2 {
				t.Fatalf("nothing detected/tokenized in in2: %q", tc.in2)
			}
			if out1 == out2 {
				t.Errorf("false collision: two different real values produced identical tokenized output: %q", out1)
			}
		})
	}
}
