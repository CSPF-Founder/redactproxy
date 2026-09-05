package redact

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// newTypesEngine is the same fixture-building helper used elsewhere in
// this package, duplicated locally to avoid import-order coupling with
// engine_test.go / pentest_corpus_test.go.
func newTypesEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatalf("tokenstore.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return New(store, DefaultDetectors()...)
}

// validAadhaar builds a synthetic 12-digit Verhoeff-valid number for
// tests, by brute-forcing the check digit against an arbitrary,
// non-degenerate 11-digit prefix, never a real person's Aadhaar number.
func validAadhaar(t *testing.T, prefix string) string {
	t.Helper()
	for d := 0; d <= 9; d++ {
		candidate := prefix + string(rune('0'+d))
		if verhoeffValid(candidate) {
			return candidate
		}
	}
	t.Fatalf("no valid check digit found for prefix %q (shouldn't happen)", prefix)
	return ""
}

func TestJWT_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	in := "Authorization header carried " + jwt + " in the request"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, jwt) {
		t.Fatalf("real JWT leaked: %q", out)
	}
	if !strings.Contains(out, "eyJredacted") {
		t.Fatalf("expected a JWT-shaped token in output, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

func TestBearerToken_PreservesTheWordBearer(t *testing.T) {
	e := newTypesEngine(t)
	in := "curl -H 'Authorization: Bearer sk-test-abcdefghijklmnopqrstuvwxyz0123456789' https://api.example-fixture.com"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Bearer ") {
		t.Fatalf("expected the literal word 'Bearer' to survive redaction, got %q", out)
	}
	if strings.Contains(out, "sk-test-abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Fatalf("real bearer token leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestBearerToken_BareAPIKeyWithLabel_RoundTrip is a regression test for
// a real leak found live: an API key handed to the model as a bare
// value in ordinary chat, with no "Authorization: Bearer" framing at
// all -- bearerRe alone never sees it. The real leaked text put ~140
// characters of prose between the label and the value; this pins that
// exact shape, not just a tight "keyword: value" adjacency.
func TestBearerToken_BareAPIKeyWithLabel_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "User-issued API key for this org (given 2026-08-28, use only for direct REST calls to this instance, never paste elsewhere): `xyzexample_a1b2c3d4_e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8`"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "a1b2c3d4_e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8") {
		t.Fatalf("real bare API key leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

// TestBearerToken_BareHighEntropyValueNoKeywordLeftAlone is the false-
// positive guard for the fix above: a bare 20+ char token-shaped string
// with no credential-labeling keyword anywhere nearby (a git SHA, a
// correlation ID, a session identifier) must NOT get swept up just
// because it happens to be long and random-looking -- that's exactly
// the false-positive minefield bareCredentialKeywordRe's keyword gate
// exists to avoid.
func TestBearerToken_BareHighEntropyValueNoKeywordLeftAlone(t *testing.T) {
	e := newTypesEngine(t)
	in := "correlation-id: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 (see trace log)"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("expected a bare high-entropy value with no credential keyword nearby to pass through untouched, got %q", out)
	}
}

// TestBearerToken_PlainIdentifierNearKeywordLeftAlone is a false-positive
// regression: bareCredentialKeywordRe's keyword-anchored window will
// claim ANY 20+ char run of letters/digits/underscore/hyphen after a
// credential keyword, which also matches ordinary plain-English
// identifiers that happen to sit nearby -- an env var NAME (as opposed
// to its value) or a URL path slug. Confirmed live against real
// pentest-report-shaped text. The fix requires at least one digit in
// the candidate (every credential shape this file recognizes is
// generated from random bytes and always mixes digits in); a run of
// pure letters/underscores/hyphens is left untouched.
func TestBearerToken_PlainIdentifierNearKeywordLeftAlone(t *testing.T) {
	cases := []string{
		`api_key = os.environ.get("SERVICE_API_KEY_CONFIG_NAME_LONG_IDENTIFIER")`,
		"Full docs: https://docs.example.com/en/5.0/ref/settings/#std-setting-SECRET-KEY-reference-page-here",
	}
	for _, in := range cases {
		e := newTypesEngine(t)
		out, err := e.Tokenize(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, tokenstore.TokenBearerPrefix) {
			t.Fatalf("expected the plain-English identifier near the keyword to be left alone, got %q from input %q", out, in)
		}
	}
}

// TestBearerToken_CredentialShapedValueNearGenericKeywordStillRedacted is
// a regression for a real miss found live: a 40-char alphanumeric value
// (the same shape as a git commit SHA, and also the shape
// awsSecretKeyKeywordRe expects) sitting near a *generic* credential
// keyword like "access token" was silently skipped entirely -- not even
// the generic bearer placeholder -- because the AWS-shape check used to
// defer on shape alone, regardless of whether an actual AWS-labeling
// keyword was anywhere nearby. It must now get the generic bearer
// token treatment and round-trip correctly.
func TestBearerToken_CredentialShapedValueNearGenericKeywordStillRedacted(t *testing.T) {
	e := newTypesEngine(t)
	in := "The OAuth access token flow was reviewed. See commit 4a2b3c4d5e6f7890abcd1234ef567890abcdef12 for the relevant middleware change."

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "4a2b3c4d5e6f7890abcd1234ef567890abcdef12") {
		t.Fatalf("real value leaked: %q", out)
	}
	if !strings.Contains(out, tokenstore.TokenBearerPrefix) {
		t.Fatalf("expected the generic bearer placeholder, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

func TestAWSAccessKey_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	// AWS's own standard documentation placeholder key ID shape.
	in := "found AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in the leaked .env file"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("real-shaped AWS key leaked: %q", out)
	}
	if !strings.Contains(out, "AKIAFAKE") {
		t.Fatalf("expected an AWS-key-shaped token in output, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestAWSAccessKey_AllDocumentedPrefixes covers all eight AWS access-key
// prefixes, not just AKIA/ASIA; IAM user/role keys and the other prefix
// types show up constantly in cloud recon (e.g. an AROA- role ID from
// sts:GetCallerIdentity).
func TestAWSAccessKey_AllDocumentedPrefixes(t *testing.T) {
	for _, prefix := range []string{"AKIA", "ASIA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "APKA"} {
		t.Run(prefix, func(t *testing.T) {
			e := newTypesEngine(t)
			real := prefix + "IOSFODNN7EXAMPLE"
			in := "id: " + real
			out, err := e.Tokenize(in)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, real) {
				t.Fatalf("real-shaped %s-prefixed key leaked: %q", prefix, out)
			}
			if !strings.Contains(out, "AKIAFAKE") {
				t.Fatalf("expected an AWS-key-shaped token in output, got %q", out)
			}
		})
	}
}

// TestAWSSecretKey_KeywordAnchored_RoundTrip is a regression test: the
// key ID (AKIA/ASIA/...) was detected, but the paired secret access
// key (the actual authentication material, always present alongside
// the ID in AWS CLI configs, .env files, Terraform state, and IAM API
// responses) had no detector at all. Covers the real-world label
// shapes this now recognizes.
func TestAWSSecretKey_KeywordAnchored_RoundTrip(t *testing.T) {
	secret := "wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEYX" // 40 base64-alphabet chars, AWS's own documented example shape
	cases := []struct {
		name string
		in   string
	}{
		{"aws cli credentials file", "aws_secret_access_key = " + secret},
		{"environment variable", "AWS_SECRET_ACCESS_KEY=" + secret},
		{"IAM API JSON", `"SecretAccessKey": "` + secret + `"`},
		{"terraform-style", `aws_secret_key: "` + secret + `"`},
		{"prose label", "the aws secret access key is " + secret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTypesEngine(t)
			out, err := e.Tokenize(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, secret) {
				t.Fatalf("real secret access key leaked: %q", out)
			}
			if !strings.Contains(out, tokenstore.TokenAWSSecretKeyPrefix) {
				t.Fatalf("expected an AWS-secret-key-shaped token in output, got %q", out)
			}
			if back := e.Detokenize(out); back != tc.in {
				t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", tc.in, back)
			}
		})
	}
}

// TestAWSSecretKey_NoKeywordNoMatch confirms the keyword anchor actually
// gates the match: an unrelated 40-char base64-alphabet string (a
// base64-encoded hash, a random token) with no AWS-labeling keyword
// nearby must be left untouched, the same false-positive concern
// hashKeywordRe's own doc comment raises for bare hex hashes.
func TestAWSSecretKey_NoKeywordNoMatch(t *testing.T) {
	unrelated := "wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEYX"
	cases := []string{
		"session token: " + unrelated,
		"random value " + unrelated + " generated for the test fixture",
	}
	for _, in := range cases {
		e := newTypesEngine(t)
		out, err := e.Tokenize(in)
		if err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Fatalf("expected no match without an AWS-labeling keyword nearby, got %q from input %q", out, in)
		}
	}
}

// TestAWSCredentialPair_BothHalvesTokenizedTogether confirms the key ID
// and its paired secret, appearing together the way a real AWS
// credentials file always has them, both get caught under the same
// "cloud.aws" category in one pass.
func TestAWSCredentialPair_BothHalvesTokenizedTogether(t *testing.T) {
	e := newTypesEngine(t)
	id := "AKIAIOSFODNN7EXAMPLE"
	secret := "wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEYX"
	in := "aws_access_key_id = " + id + "\naws_secret_access_key = " + secret

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, id) || strings.Contains(out, secret) {
		t.Fatalf("real credential pair leaked: %q", out)
	}
	if !strings.Contains(out, "AKIAFAKE") || !strings.Contains(out, tokenstore.TokenAWSSecretKeyPrefix) {
		t.Fatalf("expected both the key ID and secret key tokenized, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestPEMPrivateKey_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	key := "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL\n" +
		"-----END RSA PRIVATE KEY-----"
	in := "cat id_rsa:\n" + key + "\ndone"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL") {
		t.Fatalf("real key material leaked: %q", out)
	}
	if !strings.Contains(out, "REDACTED PRIVATE KEY") {
		t.Fatalf("expected a fake PEM block in output, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}

	// Idempotency: tokenizing already-tokenized text (our own fake PEM
	// block) must not mint a second, nested token.
	twice, err := e.Tokenize(out)
	if err != nil {
		t.Fatal(err)
	}
	if twice != out {
		t.Fatalf("tokenizing an already-tokenized PEM block changed it:\n  once:  %q\n  twice: %q", out, twice)
	}
}

func TestMACAddress_RoundTripAndDenylist(t *testing.T) {
	e := newTypesEngine(t)
	in := "arp: 10.0.0.5 at aa:bb:cc:dd:ee:ff, broadcast at ff:ff:ff:ff:ff:ff, null at 00:00:00:00:00:00"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "aa:bb:cc:dd:ee:ff") {
		t.Fatalf("real MAC leaked: %q", out)
	}
	if !strings.Contains(out, "ff:ff:ff:ff:ff:ff") || !strings.Contains(out, "00:00:00:00:00:00") {
		t.Fatalf("broadcast/null MACs should pass through untouched (never real device identifiers), got %q", out)
	}
	if !strings.Contains(out, "02:00:00:") {
		t.Fatalf("expected a locally-administered-range fake MAC in output, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestIntlPhone_PreservesCountryCode(t *testing.T) {
	e := newTypesEngine(t)
	in := "contact numbers: +91 98123 45678 (India) and +44 20 7946 0958 (UK)"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "98123") || strings.Contains(out, "7946") {
		t.Fatalf("real subscriber digits leaked: %q", out)
	}
	if !strings.Contains(out, "+91-555-") {
		t.Fatalf("expected the real India country code (+91) preserved, got %q", out)
	}
	if !strings.Contains(out, "+44-555-") {
		t.Fatalf("expected the real UK country code (+44) preserved, got %q", out)
	}
	// Detokenize restores the canonical E.164 form, not the original
	// human spacing, a deliberate tradeoff; see intlPhoneDetector's doc
	// comment (the store key has to be format-invariant for dedup, so
	// the restored value is whatever was stored under that key).
	back := e.Detokenize(out)
	if !strings.Contains(back, "+919812345678") || !strings.Contains(back, "+442079460958") {
		t.Fatalf("expected canonical E.164 numbers restored, got %q", back)
	}
}

func TestIntlPhone_ConsistentAcrossTwoCalls(t *testing.T) {
	e := newTypesEngine(t)
	first, err := e.Tokenize("call +91 98123 45678 now")
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.Tokenize("re-checking +91 98123 45678 again")
	if err != nil {
		t.Fatal(err)
	}
	extract := func(s string) string {
		i := strings.Index(s, "+91-555-")
		if i == -1 {
			t.Fatalf("no intl phone token found in %q", s)
		}
		return s[i : i+12]
	}
	if extract(first) != extract(second) {
		t.Fatalf("same real number got different tokens across calls: %q vs %q", first, second)
	}
}

// TestIntlPhone_RealNumberContainingLiteral555IsStillRedacted covers
// real numbers that happen to contain TokenIntlPhonePrefix ("555-")
// somewhere in their human formatting, e.g. an Indian mobile written
// "+91-98555-01234". Four ordinary characters like that turn up by
// coincidence often enough that the already-tokenized guard cannot be a
// substring test: reading one of these as a token means the real number
// goes to the model in full. See ownIntlPhoneTokenRe.
func TestIntlPhone_RealNumberContainingLiteral555IsStillRedacted(t *testing.T) {
	for _, in := range []string{
		"call +91-98555-01234 now", // "555-" inside the subscriber digits
		"call +44-5551-234567 now", // "555" opening the national number
		"call +91 98555 01234 now", // same number, spaces: always worked
	} {
		e := newTypesEngine(t)
		out, err := e.Tokenize(in)
		if err != nil {
			t.Fatal(err)
		}
		if out == in {
			t.Errorf("real number containing a literal %q was left unredacted: %q", tokenstore.TokenIntlPhonePrefix, out)
			continue
		}
		if back := e.Detokenize(out); !strings.Contains(back, "+91") && !strings.Contains(back, "+44") {
			t.Errorf("tokenized %q -> %q did not detokenize back to a real number: %q", in, out, back)
		}
	}
}

// TestIntlPhone_OwnTokenIsNotReTokenized is the other half of
// ownIntlPhoneTokenRe's job: a minted token echoed back in resent
// conversation history must keep resolving to the same real value
// rather than minting a second, different placeholder for itself.
func TestIntlPhone_OwnTokenIsNotReTokenized(t *testing.T) {
	e := newTypesEngine(t)
	in := "call +91 98123 45678 now"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	again, err := e.Tokenize(out)
	if err != nil {
		t.Fatal(err)
	}
	if again != out {
		t.Fatalf("re-tokenizing already-tokenized text changed it:\n  first:  %q\n  second: %q", out, again)
	}
	if back := e.Detokenize(again); !strings.Contains(back, "+919812345678") {
		t.Fatalf("expected the real number restored after a re-tokenize round trip, got %q", back)
	}
}

func TestIntlPhone_RejectsUnassignedCallingCode(t *testing.T) {
	e := newTypesEngine(t)
	// "999" is not an ITU-T assigned calling code.
	in := "ref +999 1234567 in the ticket"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("a candidate with no real calling code should pass through untouched, got %q", out)
	}
}

func TestIntlPhone_NANPLeftToPhoneDetector(t *testing.T) {
	e := newTypesEngine(t)
	// "1" (NANP) is deliberately excluded from intlPhoneDetector's
	// calling-code table; phoneDetector already owns it with tighter
	// formatting. Confirm it still gets redacted (just via the other
	// detector), not silently missed by both.
	out, err := e.Tokenize("call +1 202-867-5309 now")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "202-867-5309") {
		t.Fatalf("real NANP number leaked: %q", out)
	}
}

// TestIntlPhone_NANPTokenSurvivesLiteralCountryCodePrefix pins the fix
// for a real collision: phoneRe's leading boundary doesn't capture a
// "+1" prefix on a NANP number (see TestIntlPhone_NANPLeftToPhoneDetector
// above), so it passes through tokenize as literal text sitting right in
// front of the minted "555-01XX" token. Without the TokenPhonePrefix
// guard in detokenizeIntlPhoneTokens, that "+1-555-01XX" shape gets
// misread as an international token on the way back and the whole match
// -- including the literal "+1-" that was never part of any token -- is
// replaced by just the NANP digits, silently dropping the country code.
func TestIntlPhone_NANPTokenSurvivesLiteralCountryCodePrefix(t *testing.T) {
	e := newTypesEngine(t)
	in := "call +1-415-867-5309 now"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "415-867-5309") {
		t.Fatalf("real NANP number leaked: %q", out)
	}

	back := e.Detokenize(out)
	if back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestIntlPhone_NeverMintsIntoNANPReservedRange confirms the generator
// side of the same fix: an international number's random subscriber
// digits never land in TokenPhonePrefix's reserved 555-01XX pool, so the
// detokenize-side guard above is never left restoring the wrong entity's
// value for a genuine international token.
func TestIntlPhone_NeverMintsIntoNANPReservedRange(t *testing.T) {
	e := newTypesEngine(t)
	for i := 0; i < 300; i++ {
		in := fmt.Sprintf("call +91 9%07d now", i)
		out, err := e.Tokenize(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "555-01") {
			t.Fatalf("intl-phone token minted inside NANP's reserved range: %q", out)
		}
	}
}

// TestPhoneDetector_ManyDistinctNumbersRoundTripCleanly pins the fix for
// NANP token pool exhaustion end-to-end, through the full Tokenize/
// Detokenize pipeline rather than just the tokenstore layer: 300 distinct
// real NANP numbers -- three times the old fixed-area-code pool's hard
// 100-number limit -- must all tokenize without error and restore
// exactly on detokenize. Before nanpFakeAreaCodes, the 101st distinct
// number in one engagement would fail-closed and block that request.
func TestPhoneDetector_ManyDistinctNumbersRoundTripCleanly(t *testing.T) {
	e := newTypesEngine(t)
	for i := 0; i < 300; i++ {
		in := fmt.Sprintf("call 415-%03d-%04d now", 200+i%800, 1000+i)
		out, err := e.Tokenize(in)
		if err != nil {
			t.Fatalf("mint #%d (%s): %v", i, in, err)
		}
		back := e.Detokenize(out)
		if back != in {
			t.Fatalf("round-trip mismatch on #%d:\n  in:   %q\n  out:  %q\n  back: %q", i, in, out, back)
		}
	}
}

// TestIntlPhone_DoesNotSwallowFollowingNewline confirms an international
// phone number at the end of a numbered list item ("+91-8082282294\n3.
// Nikhil Raut") doesn't have its candidate regex's separator class match
// the newline and pull the next line's leading digit in as if it were
// part of the phone number, which would silently drop the swallowed
// "\n3" from the output and corrupt the list numbering below it.
func TestIntlPhone_DoesNotSwallowFollowingNewline(t *testing.T) {
	e := newTypesEngine(t)
	in := "Mobile: +91-8082282294\n3. Nikhil Raut\nMobile: +91-9812345678\n4. Jay Thakker"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "\n3. Nikhil Raut") {
		t.Fatalf("expected the list numbering '3.' and newline to survive, got %q", out)
	}
	if !strings.Contains(out, "\n4. Jay Thakker") {
		t.Fatalf("expected the list numbering '4.' and newline to survive, got %q", out)
	}
	// Detokenize restores canonical E.164 digits (documented tradeoff,
	// see intlPhoneDetector's doc comment), not byte-identical hyphen
	// placement, but the list structure around it must be untouched.
	back := e.Detokenize(out)
	if !strings.Contains(back, "\n3. Nikhil Raut") || !strings.Contains(back, "\n4. Jay Thakker") {
		t.Fatalf("list numbering corrupted after detokenize: %q", back)
	}
	if !strings.Contains(back, "8082282294") || !strings.Contains(back, "9812345678") {
		t.Fatalf("expected both real subscriber numbers restored, got %q", back)
	}
}

func TestGitHubToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "leaked in .env: GITHUB_TOKEN=" + githubPATPrefix + "16C7e42F292c6912E7710c838347Ae178B4a"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "16C7e42F292c6912E7710c838347Ae178B4a") {
		t.Fatalf("real GitHub token leaked: %q", out)
	}
	if !strings.Contains(out, "ghp_FAKE") {
		t.Fatalf("expected a GitHub-token-shaped fake in output, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestGitLabToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "GITLAB_TOKEN=" + gitlabPATPrefix + "aBcDeFgHiJkLmNoPqRst"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "aBcDeFgHiJkLmNoPqRst") {
		t.Fatalf("real GitLab token leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestSlackToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "SLACK_TOKEN=" + slackBotPrefix + "1234567890-1234567890-abcdefghijklmnopqrstuvwx"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "abcdefghijklmnopqrstuvwx") {
		t.Fatalf("real Slack token leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestSlackWebhook_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "webhook: https://" + slackWebhookPrefix + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "T00000000/B00000000") {
		t.Fatalf("real Slack webhook path leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestSlackWebhook_RoundTripWithoutScheme pins a real collision: without
// "https://", the same webhook shape used to fall through to the generic
// domain detector, which only protects "hooks.slack.com" and leaves the
// actual secret (the team/bot/token path right after it) as unredacted
// literal text.
func TestSlackWebhook_RoundTripWithoutScheme(t *testing.T) {
	e := newTypesEngine(t)
	in := "webhook: " + slackWebhookPrefix + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "T00000000/B00000000") {
		t.Fatalf("real Slack webhook path leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestStripeKey_RoundTripAndPublishableKeyIgnored(t *testing.T) {
	e := newTypesEngine(t)
	secret := stripeLivePrefix + "51H8xyzABCDEFGHIJKLMNOPQ"
	in := "STRIPE_SECRET_KEY=" + secret + ", publishable=pk_live_51H8xyzABCDEFGHIJKLMNOPQ"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "pk_live_51H8xyzABCDEFGHIJKLMNOPQ") {
		t.Fatalf("publishable key (not a secret) should pass through untouched, got %q", out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("real Stripe secret key leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestStripeKey_TestModeKeysAlsoRedacted confirms "_test_" secret/
// restricted keys (sk_test_/rk_test_) are redacted, not just "_live_"
// ones. Test keys are still real Stripe account credentials (same
// character shape, same leaked-.env-file risk, just scoped to Stripe's
// test environment instead of production) and turn up in practice at
// least as often as live keys, since they're handled less carefully.
func TestStripeKey_TestModeKeysAlsoRedacted(t *testing.T) {
	e := newTypesEngine(t)
	secret := stripeTestPrefix + "51H8xyzABCDEFGHIJKLMNOPQ"
	restricted := stripeRestrictedTestPrefix + "51H8xyzABCDEFGHIJKLMNOPQ"
	in := "STRIPE_TEST_SECRET=" + secret + ", restricted=" + restricted + ", publishable=pk_test_51H8xyzABCDEFGHIJKLMNOPQ"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("real Stripe test-mode secret key leaked: %q", out)
	}
	if strings.Contains(out, restricted) {
		t.Fatalf("real Stripe test-mode restricted key leaked: %q", out)
	}
	if !strings.Contains(out, "pk_test_51H8xyzABCDEFGHIJKLMNOPQ") {
		t.Fatalf("publishable test key (not a secret) should pass through untouched, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestGoogleAPIKey_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "GOOGLE_API_KEY=" + googleAPIKeyPrefix + "D3xM9k2L8pQ7rN4vB1cE6fH0jK5sT9wZx"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "D3xM9k2L8pQ7rN4vB1cE6fH0jK5sT9wZ") {
		t.Fatalf("real Google API key leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestNPMToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "//registry.npmjs.org/:_authToken=" + npmPrefix + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789") {
		t.Fatalf("real npm token leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestTwilioSID_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "TWILIO_ACCOUNT_SID=" + twilioSIDPrefix + "1234567890abcdef1234567890abcdef"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "1234567890abcdef1234567890abcdef") {
		t.Fatalf("real Twilio SID leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestTwilioSID_BareHexNeverMatchesAlone(t *testing.T) {
	e := newTypesEngine(t)
	// A bare 32-hex string (e.g. an MD5 hash, common in pentest output)
	// must NOT be redacted just because it's hex-shaped; only the
	// "AC"-prefixed SID is distinctive enough to act on.
	in := "md5sum: 5d41402abc4b2a76b9719d911017c592"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("bare hex hash should pass through untouched, got %q", out)
	}
}

func TestSendGridKey_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "SENDGRID_API_KEY=" + sendGridPrefix + "aBcDeFgHiJkLmNoPqRsT.uVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ012"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "aBcDeFgHiJkLmNoPqRsT") {
		t.Fatalf("real SendGrid key leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestConnString_URLStyleRoundTripPreservesScheme(t *testing.T) {
	e := newTypesEngine(t)
	in := "connect via mongodb://dbadmin:S3cr3tP@ss@10.0.0.5:27017/prod"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "dbadmin") || strings.Contains(out, "S3cr3tP") {
		t.Fatalf("real DB credentials leaked: %q", out)
	}
	if !strings.HasPrefix(out, "connect via mongodb://") {
		t.Fatalf("expected the real scheme 'mongodb://' preserved, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

// TestConnString_HTTPBasicAuthRoundTrip confirms plain http(s) URLs with
// embedded Basic Auth credentials are redacted, not just DB/service
// connection-string schemes, at least as common a real leak shape
// (e.g. "curl -x http://user:pass@host/api").
func TestConnString_HTTPBasicAuthRoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "curl -x http://admin:Str0ngP@ssw0rd@internal-tool.widgetcorp-fixture.com/api"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "admin") || strings.Contains(out, "Str0ngP") {
		t.Fatalf("real HTTP Basic Auth credentials leaked: %q", out)
	}
	if !strings.HasPrefix(out, "curl -x http://") {
		t.Fatalf("expected the real scheme 'http://' preserved, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

func TestConnString_ADOStyleRoundTripAndContextGate(t *testing.T) {
	e := newTypesEngine(t)
	in := "Server=10.0.0.5;Database=erp;User Id=sa;Password=Str0ngP@ssw0rd!;"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Str0ngP@ssw0rd!") {
		t.Fatalf("real ADO.NET connection string password leaked: %q", out)
	}
	if strings.Contains(out, "10.0.0.5") {
		t.Fatalf("real IP leaked (the IPv4 detector should independently redact it too): %q", out)
	}
	// Everything except the password value and the IP (redacted by a
	// different, unrelated detector) stays literal.
	for _, keyword := range []string{"Server=", "Database=erp", "User Id=sa", "Password="} {
		if !strings.Contains(out, keyword) {
			t.Fatalf("expected %q preserved in output, got %q", keyword, out)
		}
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}

	// The narrower gate: a bare "password=" with no nearby Server=/Data
	// Source=/Uid= context must NOT be treated as a connection string;
	// this is deliberately NOT the general "context-anchored generic
	// secret" detector that was declined elsewhere.
	proseIn := "the wiki says the default password=admin123 for the demo box"
	proseOut, err := e.Tokenize(proseIn)
	if err != nil {
		t.Fatal(err)
	}
	if proseOut != proseIn {
		t.Fatalf("a bare 'password=' with no connection-string context should pass through untouched, got %q", proseOut)
	}
}

func TestDigitalOceanToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "DO_TOKEN=dop_v1_" + strings.Repeat("a1b2c3", 10) + "abcd"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, strings.Repeat("a1b2c3", 10)) {
		t.Fatalf("real DigitalOcean token leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestCloudflareToken_RoundTrip's fixture must have no separator between
// the 40-char and 8-char hex groups
// (`cf(?:[ua]t|k)_[a-zA-Z0-9]{40}[a-f0-9]{8}` has none) or cloudflareRe
// never matches at all; asserts tokenization actually happened, not
// just round-trip consistency, which would trivially hold even if
// nothing were tokenized.
func TestCloudflareToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "CF_TOKEN=cfat_" + strings.Repeat("Ab1cD2eF3g", 4) + "a1b2c3d4"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out == in {
		t.Fatalf("expected the Cloudflare token to be detected and tokenized, got it unchanged: %q", in)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

func TestAzureStorageKey_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	key := strings.Repeat("aB3", 29) + "=="
	in := "DefaultEndpointsProtocol=https;AccountName=mystore;AccountKey=" + key + ";EndpointSuffix=core.windows.net"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, key) {
		t.Fatalf("real Azure storage key leaked: %q", out)
	}
	if !strings.Contains(out, "AccountKey=") {
		t.Fatalf("expected the AccountKey= keyword preserved, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

// TestArtifactoryToken_RoundTrip's fixture must supply EXACTLY 69 alnum
// characters after "AKCp" (`AKCp[a-zA-Z0-9]{69}`) or no `\b`-bounded
// match exists; asserts tokenization actually happened, not just
// round-trip consistency.
func TestArtifactoryToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "ARTIFACTORY_KEY=AKCp" + strings.Repeat("x9", 34) + "y"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out == in {
		t.Fatalf("expected the Artifactory token to be detected and tokenized, got it unchanged: %q", in)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestDockerHubToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "DOCKER_TOKEN=dckr_pat_" + strings.Repeat("Ab1", 9)
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestCircleCIToken_RoundTrip's fixture must supply EXACTLY 22 alnum
// characters before the "_"
// (`CCIPAT_[a-zA-Z0-9]{22}_[a-fA-F0-9]{40}`) or it never matches;
// asserts tokenization actually happened, not just round-trip
// consistency.
func TestCircleCIToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "CIRCLE_TOKEN=CCIPAT_" + strings.Repeat("Ab1cD2", 3) + "wxYZ_" + strings.Repeat("a1b2c3d4e5", 4)
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out == in {
		t.Fatalf("expected the CircleCI token to be detected and tokenized, got it unchanged: %q", in)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

func TestTerraformToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "TF_TOKEN=a1B2c3D4e5F6gH.atlasv1." + strings.Repeat("a1B2c3D4e5", 6) + "a1B2c3D"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "FAKE") {
		t.Fatalf("expected a Terraform-shaped fake token in output, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

func TestSnykToken_RoundTripPreservesKeyword(t *testing.T) {
	e := newTypesEngine(t)
	in := "snyk auth token: 12345678-90ab-cdef-1234-567890abcdef"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "12345678-90ab-cdef-1234-567890abcdef") {
		t.Fatalf("real Snyk token leaked: %q", out)
	}
	if !strings.HasPrefix(out, "snyk auth token: ") {
		t.Fatalf("expected the 'snyk auth token: ' context preserved literally, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

func TestSnykToken_UUIDAloneWithoutKeywordUntouched(t *testing.T) {
	e := newTypesEngine(t)
	// A bare UUID (very common as a generic identifier in pentest output:
	// asset IDs, session IDs) must not be redacted without the "snyk"
	// keyword nearby.
	in := "asset id: 12345678-90ab-cdef-1234-567890abcdef"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("a bare UUID with no 'snyk' keyword should pass through untouched, got %q", out)
	}
}

// TestItsdangerousToken_RoundTrip covers a Flask CSRF token shape that
// would otherwise pass through completely untouched: it's JWT-shaped (3
// dot-separated base64url segments) but doesn't start with "eyJ"
// (itsdangerous payloads aren't JSON), so jwtRe never matches it.
func TestItsdangerousToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := `body: "csrf_token=ImMyYjM3YWJhN2RlNzg0MDM0NDgwOTM3ZjhjMGU2ZjI5ZGVjMzVmZjYi.Dudyfw.q4PuqxwtjVP8GhkK5xzf1dsLYg&filesystem_id=..."`

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ImMyYjM3YWJhN2RlNzg0MDM0NDgwOTM3ZjhjMGU2ZjI5ZGVjMzVmZjYi") {
		t.Fatalf("real itsdangerous-signed CSRF token leaked: %q", out)
	}
	if !strings.HasPrefix(out, `body: "csrf_token=`) {
		t.Fatalf("expected the 'csrf_token=' keyword preserved literally, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

// TestItsdangerousToken_NoKeywordNearbyLeftUntouched confirms the
// deliberate false-positive-minimizing tradeoff: the same JWT-shaped
// value with no csrf_token=/session=/itsdangerous keyword nearby is left
// alone, rather than broadening the shape match to catch it (which would
// risk matching unrelated dot-separated identifiers).
func TestItsdangerousToken_NoKeywordNearbyLeftUntouched(t *testing.T) {
	e := newTypesEngine(t)
	in := "some_field=ImMyYjM3YWJhN2RlNzg0MDM0NDgwOTM3ZjhjMGU2ZjI5ZGVjMzVmZjYi.Dudyfw.q4PuqxwtjVP8GhkK5xzf1dsLYg"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("expected this to pass through untouched with no signed-token keyword nearby, got %q", out)
	}
}

// TestItsdangerousToken_JWTShapedDefersToJWTDetector confirms the two
// detectors don't double-claim the same value: a real JWT (eyJ-prefixed)
// appearing after "session=" must still be claimed by jwtDetector, not
// this one, so its token has the expected "eyJredacted..." shape.
func TestItsdangerousToken_JWTShapedDefersToJWTDetector(t *testing.T) {
	e := newTypesEngine(t)
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	in := "Set-Cookie: session=" + jwt

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, jwt) {
		t.Fatalf("real JWT leaked: %q", out)
	}
	if !strings.Contains(out, "eyJredacted") {
		t.Fatalf("expected jwtDetector's token shape, got %q", out)
	}
}

func TestBitbucketPassword_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "git clone https://svc-account:ATBB" + strings.Repeat("Ab1", 10) + "@bitbucket.org/org/repo.git"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

func TestVaultToken_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "VAULT_TOKEN=hvs." + strings.Repeat("aB1cD2eF3", 8) + "gH"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestOpenAIKey_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "OPENAI_API_KEY=sk-" + strings.Repeat("Ab1cD2", 8) + "T3BlbkFJ" + strings.Repeat("eF3gH4", 8)
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "T3BlbkFJ"+strings.Repeat("eF3gH4", 8)) {
		t.Fatalf("real OpenAI key leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestAnthropicKey_RoundTrip's fixture must supply anthropicKeyRe's
// required 93-character body (`sk-ant-(?:admin01|api03)-[\w-]{93}AA`) or
// it never matches; asserts tokenization actually happened, not just
// round-trip consistency.
func TestAnthropicKey_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "ANTHROPIC_API_KEY=sk-ant-api03-" + strings.Repeat("aB1cD2eF3", 10) + "xyzAA"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out == in {
		t.Fatalf("expected the Anthropic key to be detected and tokenized, got it unchanged: %q", in)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

func TestRazorpayKey_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "RAZORPAY_KEY_ID=" + razorpayLivePrefix + "ABCDEFGHIJKLMN"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ABCDEFGHIJKLMN") {
		t.Fatalf("real Razorpay key leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestAadhaar_RoundTripAndChecksumGate(t *testing.T) {
	e := newTypesEngine(t)
	real := validAadhaar(t, "29384756123")
	spaced := real[:4] + " " + real[4:8] + " " + real[8:]
	in := "Aadhaar on file: " + spaced

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, real) {
		t.Fatalf("real Aadhaar number leaked: %q", out)
	}
	if !strings.Contains(out, "0000 ") {
		t.Fatalf("expected a fake Aadhaar token (0000-prefixed) in output, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

func TestAadhaar_FalsePositiveGuards(t *testing.T) {
	e := newTypesEngine(t)

	// A random 12-digit run that does NOT satisfy Verhoeff must pass
	// through untouched; this is the whole point of the checksum gate.
	var notAadhaar string
	for _, candidate := range []string{"234567890123", "918273645102", "504938271605"} {
		if !verhoeffValid(candidate) {
			notAadhaar = candidate
			break
		}
	}
	if notAadhaar == "" {
		t.Fatal("test setup: expected at least one candidate to fail Verhoeff")
	}
	in := "order id " + notAadhaar + " shipped"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("a checksum-invalid 12-digit number should not be tokenized as Aadhaar, got %q", out)
	}

	// Degenerate runs must never be tokenized even if they somehow pass
	// Verhoeff by coincidence.
	for _, degenerate := range []string{"000000000000", "111111111111"} {
		out, err := e.Tokenize("id: " + degenerate)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, degenerate) {
			t.Fatalf("degenerate digit run %q should pass through untouched, got %q", degenerate, out)
		}
	}
}

func TestPAN_RoundTripAndHolderCodeGate(t *testing.T) {
	e := newTypesEngine(t)
	// 4th character 'P' = individual, a real, valid holder-type code.
	in := "PAN on file: ABCPE1234F"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ABCPE1234F") {
		t.Fatalf("real PAN leaked: %q", out)
	}
	if !strings.Contains(out, "FAKEP") {
		t.Fatalf("expected a fake PAN token in output, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}

	// 4th character 'X' isn't a real holder-type code, and shape alone
	// shouldn't be enough to trigger tokenization.
	notPAN := "ABCXE1234F"
	out2, err := e.Tokenize("ref " + notPAN)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2, notPAN) {
		t.Fatalf("a PAN-shaped string with an invalid holder code should pass through untouched, got %q", out2)
	}
}

// TestPasswordHash_KeywordAnchored_RoundTrip covers each hash-type
// keyword this codebase's hashKeywordRe recognizes, at the matching
// real-world length.
func TestPasswordHash_KeywordAnchored_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   string
		hash string
	}{
		{"NTLM", "NTLM: aad3b435b51404eeaad3b435b51404ee", "aad3b435b51404eeaad3b435b51404ee"},
		{"MD5", "md5 hash is 5f4dcc3b5aa765d61d8327deb882cf99 for password", "5f4dcc3b5aa765d61d8327deb882cf99"},
		{"SHA1", "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"64-hex under an unambiguous label", "password hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"nt hash phrase", "nt hash: 31d6cfe0d16ae931b73c59d7e0c089c0 recovered", "31d6cfe0d16ae931b73c59d7e0c089c0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTypesEngine(t)
			out, err := e.Tokenize(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, tc.hash) {
				t.Fatalf("real hash leaked: %q", out)
			}
			if !strings.Contains(out, tokenstore.TokenPasswordHashPrefix) {
				t.Fatalf("expected a password-hash-shaped token in output, got %q", out)
			}
			if back := e.Detokenize(out); back != tc.in {
				t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", tc.in, back)
			}
		})
	}
}

// TestPasswordHash_HeaderLineThenDumpLine_RoundTrip is a regression test
// for hashKeywordRe's window: a descriptive header line followed by the
// actual "username:hash" dump line is a common real-world shape (tool
// output that labels a hash dump before printing it) that the previous
// 20-char window missed entirely -- confirmed failing before the fix
// (0 detections) since the gap from "NTLM" to the hash here is ~21
// chars, just over the old limit.
func TestPasswordHash_HeaderLineThenDumpLine_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	hash := "aad3b435b51404eeaad3b435b51404ee"
	in := "NTLM hashes found:\nadmin:" + hash

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, hash) {
		t.Fatalf("real hash leaked: %q", out)
	}
	if !strings.Contains(out, tokenstore.TokenPasswordHashPrefix) {
		t.Fatalf("expected a password-hash-shaped token in output, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestPasswordHash_SecretsdumpPair_RoundTrip covers the Impacket
// secretsdump.py / pwdump-style "user:rid:LMHASH:NTHASH:::" line shape,
// which needs no keyword anchoring since the triple-colon ending is
// already distinctive.
func TestPasswordHash_SecretsdumpPair_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	lm := "aad3b435b51404eeaad3b435b51404ee"
	nt := "31d6cfe0d16ae931b73c59d7e0c089c0"
	in := "Administrator:500:" + lm + ":" + nt + ":::"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, lm) || strings.Contains(out, nt) {
		t.Fatalf("real LM/NT hash leaked: %q", out)
	}
	if strings.Count(out, tokenstore.TokenPasswordHashPrefix) != 2 {
		t.Fatalf("expected both LM and NT hashes tokenized separately, got %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  back: %q", in, back)
	}
}

// TestPasswordHash_NoKeywordNoMatch is the direct false-positive
// regression test this detector exists specifically to pass: a
// hash-shaped hex string with NO nearby keyword and NOT in the
// secretsdump triple-colon shape (a git commit SHA is exactly this
// shape (40 hex chars) and appears constantly in ordinary tool output)
// must be left completely untouched.
func TestPasswordHash_NoKeywordNoMatch(t *testing.T) {
	cases := []string{
		"commit da39a3ee5e6b4b0d3255bfef95601890afd80709 fixed the build",
		"see https://github.com/example/repo/commit/5f4dcc3b5aa765d61d8327deb882cf99e3b0c449 for details",
		"sha256sum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  archive.tar.gz",
		"md5sum output: 5f4dcc3b5aa765d61d8327deb882cf99  file.bin",
		// A Docker image digest uses the exact same "sha256:<64 hex>"
		// shape as a labeled password hash, and is completely ordinary,
		// non-sensitive tool output; the reason "sha256"/"sha-256" was
		// deliberately dropped from the trigger keyword list entirely
		// (see hashKeywordRe's doc comment).
		"docker image sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"the hash map implementation uses 5f4dcc3b5aa765d61d8327deb882cf99 as a bucket seed",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			e := newTypesEngine(t)
			out, err := e.Tokenize(in)
			if err != nil {
				t.Fatal(err)
			}
			if out != in {
				t.Fatalf("expected an unlabeled hash-shaped hex string to pass through untouched, got:\n  in:  %q\n  out: %q", in, out)
			}
		})
	}
}

// TestADMachineAccount_RoundTrip covers the machine-account name from an
// AD/secretsdump-style test corpus. The detokenize regex must match
// randomHex(6)'s actual output width: randomHex(N) produces 2*N hex
// characters (N random bytes, hex-encoded), not N, so a regex expecting
// [0-9a-f]{6} would never match and the token would never detokenize at
// all.
func TestADMachineAccount_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := "WORKSTATION01$:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::"

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "WORKSTATION01") {
		t.Fatalf("real machine account name leaked: %q", out)
	}
	if !strings.HasSuffix(strings.SplitN(out, ":", 2)[0], "$") {
		t.Fatalf("expected the fake machine account token to still end in '$', got: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}

// TestADMachineAccount_OrdinaryUsernameNotClaimed confirms the
// deliberate scope limit: a bare human username in the identical line
// shape (no trailing "$") is left alone; only $-suffixed AD machine
// accounts are claimed, per machineAccountSecretsdumpRe's doc comment.
func TestADMachineAccount_OrdinaryUsernameNotClaimed(t *testing.T) {
	e := newTypesEngine(t)
	in := "jdoe:1105:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "jdoe:") {
		t.Fatalf("expected the bare username to pass through untouched, got: %q", out)
	}
}

// TestGPPCPassword_RoundTrip covers a real Group Policy Preferences
// cpassword value, trivially decryptable via Microsoft's published
// MS14-025 AES key, so treated as exactly as sensitive as a plaintext
// password.
func TestGPPCPassword_RoundTrip(t *testing.T) {
	e := newTypesEngine(t)
	in := `cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLtl0BMPqDpMhpc4xUcyfEjIQ" newName="admin"`

	out, err := e.Tokenize(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "edBSHOwhZLTjt") {
		t.Fatalf("real GPP cpassword value leaked: %q", out)
	}
	if back := e.Detokenize(out); back != in {
		t.Fatalf("round-trip mismatch:\n  in:   %q\n  out:  %q\n  back: %q", in, out, back)
	}
}
