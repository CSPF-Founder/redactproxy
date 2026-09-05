package tokenstore

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// Token namespaces are deliberately distinct from any real value shape, so
// a token can never be mistaken for (or collide with) a real one, and so
// the detokenize direction can find tokens with a single fixed-format
// regex instead of a lookup table scan. Exported so the redact package can
// build its detokenize detectors from the same constants.
const (
	// TokenDomainPrefix begins every generated domain (org-identifying)
	// token: "tok" + 16 hex chars, e.g. "tok1a2b3c4d5e6f70". Prefix-based
	// rather than the previous suffix-based ".tok.internal" specifically
	// so a REAL public suffix can follow the token in the visible text
	// (preserving country/sector context for Claude) while the token
	// itself stays unambiguously recognizable for the detokenize
	// direction; see redact.Engine's detokenizeDomainTokens.
	TokenDomainPrefix = "tok"
	// TokenEmailLocalPrefix begins every generated email-local-part
	// token: "user-" + 12 hex chars.
	TokenEmailLocalPrefix = "user-"
	// TokenIPNetworkPrefix begins every generated IPv4 /24-network token:
	// "198.18." + one octet (0-255), e.g. "198.18.42"; the last octet of
	// the visible address is the REAL host octet, preserved by the
	// caller, not part of this token. Base is 198.18.0.0/15 (RFC 2544,
	// reserved for network interconnect device benchmark testing) rather
	// than an RFC 1918 block like 10.0.0.0/8: internal pentest
	// engagements routinely target real 10.x/172.16-31.x/192.168.x
	// addresses, so this tool's own token space deliberately avoids
	// living in a range real targets are likely to use, to keep "is this
	// address real or ours" unambiguous.
	TokenIPNetworkPrefix = "198.18."
	// TokenIPv6NetworkPrefix begins every generated IPv6 /64-network
	// token: "fd00:c0de:" + two hex groups (32 bits), e.g.
	// "fd00:c0de:1a2b:3c4d"; the last four groups (64-bit interface ID)
	// of the visible address are preserved from the real one. fd00::/8
	// is RFC 4193 Unique Local Address space, reserved for private use,
	// never a real global address.
	TokenIPv6NetworkPrefix = "fd00:c0de:"
	// TokenPhonePrefix is the NANP N11/reserved 555-01XX exchange, which
	// carriers never assign to real subscribers. Every generated NANP
	// phone token embeds this as a fragment ("<area code>-" + this +
	// two digits, e.g. "415-555-0142"), not as the token's own literal
	// start; see nanpFakeAreaCodes' doc comment for why.
	TokenPhonePrefix = "555-01"
	// TokenIntlPhonePrefix begins every generated international-phone
	// subscriber token: "555-" + 4 digits. The real country calling code
	// is NOT part of this token; it's a real, preserved value appended
	// by the caller (see redact.intlPhoneDetector), the same way a real
	// domain suffix is appended outside the domain org-token.
	TokenIntlPhonePrefix = "555-"
	// TokenJWTPrefix begins every generated JWT token's first ("header")
	// segment, not valid base64url of real JSON, just a fixed marker
	// that can never appear in a real JWT (which always starts "eyJ" but
	// is never followed by the literal word "redacted").
	TokenJWTPrefix = "eyJredacted"
	// TokenBearerPrefix begins every generated opaque bearer/API token.
	TokenBearerPrefix = "tok-bearer-"
	// TokenAWSKeyPrefix begins every generated fake AWS access key ID. It
	// keeps the real "AKIA" prefix (so it's still recognizable as an AWS
	// key shape) but is never a real, issuable key since AWS never
	// allocates "FAKE" as the next 4 characters.
	TokenAWSKeyPrefix = "AKIAFAKE"
	// TokenAWSSecretKeyPrefix begins every generated fake AWS secret
	// access key. Unlike the key ID, AWS secret keys have no documented
	// never-allocated prefix to anchor a "structurally guaranteed
	// non-issuable" fake on (they're free-form random base64, not a
	// fixed-prefix identifier scheme), so this follows
	// TokenBearerPrefix's approach instead: a plainly human-readable
	// "this is a placeholder" marker rather than an attempt at visual
	// realism.
	TokenAWSSecretKeyPrefix = "tok-aws-secret-"
	// TokenPEMKeyBeginMarker/TokenPEMKeyEndMarker wrap every generated
	// fake PEM private-key block body.
	TokenPEMKeyBeginMarker = "-----BEGIN REDACTED PRIVATE KEY-----\n"
	TokenPEMKeyEndMarker   = "\n-----END REDACTED PRIVATE KEY-----"
	// TokenMACPrefix begins every generated fake MAC address: "02" as
	// the first octet sets IEEE 802's locally-administered bit, which by
	// definition can never be a real, globally-assigned vendor OUI.
	TokenMACPrefix = "02:00:00:"
	// TokenAadhaarPrefix begins every generated fake Aadhaar token: "0000"
	// + 8 more digits. Real Aadhaar numbers are structurally guaranteed
	// (by UIDAI's own numbering rule) to never begin with 0 or 1, so this
	// can never collide with or be mistaken for a real one, while still
	// keeping the familiar 12-digit shape.
	TokenAadhaarPrefix = "0000 "
	// TokenPANPrefix begins every generated fake PAN: "FAKEP" + 4 digits
	// + 1 letter. Position 4 of a real PAN (the "E" here) is a
	// holder-type code from a fixed set (P/C/H/A/B/G/J/L/F/T), and "E" isn't
	// in it, so this is structurally guaranteed non-issuable, not just
	// visually distinct.
	TokenPANPrefix = "FAKEP"
	// TokenPasswordHashPrefix begins every generated fake password-hash
	// token. "K", "H", and "S" aren't valid hex digits, so this can never
	// appear as a prefix of (or be confused with) a real hex-only hash;
	// same "FAKE"-as-a-non-hex-anchor idea as TokenAWSKeyPrefix.
	TokenPasswordHashPrefix = "FAKEHASH"

	// The prefixes below all begin fully-opaque vendor-credential tokens
	// (see the EntityGitHubToken family's doc comment in store.go). Each
	// embeds the real vendor prefix (so the credential TYPE stays
	// recognizable, genuinely useful context, not sensitive on its own)
	// followed by a "FAKE" marker before the random suffix, the same
	// "AKIAFAKE" idea used for AWS keys: 'K' isn't a valid hex digit, so
	// "FAKE" can never appear inside a real random-hex secret, making it
	// a safe, unambiguous anchor for the detokenize direction.
	TokenGitHubPrefix       = "ghp_FAKE"
	TokenGitLabPrefix       = "glpat-FAKE"
	TokenSlackTokenPrefix   = "xoxb-9999999999-9999999999-FAKE"
	TokenSlackWebhookMarker = "REDACTED-WEBHOOK-"
	TokenStripePrefix       = "sk_live_FAKE"
	TokenGoogleAPIKeyPrefix = "AIzaSyFAKE"
	TokenNPMPrefix          = "npm_FAKE"
	TokenTwilioSIDPrefix    = "ACFAKE"
	TokenSendGridPrefix     = "SG.FAKE"
	// TokenConnStringMarker begins the opaque replacement for BOTH
	// connection-string credential shapes this tool detects: a URL-style
	// "user:pass@host" span (the real scheme stays visible outside the
	// token, e.g. "mongodb://") and an ADO.NET/ODBC-style bare password
	// value (see redact.connStringDetector for both).
	TokenConnStringMarker = "REDACTED-CREDS-"

	TokenDigitalOceanPrefix    = "dop_v1_FAKE"
	TokenCloudflarePrefix      = "cfat_FAKE"
	TokenAzureStorageKeyPrefix = "REDACTED-AZUREKEY-"
	TokenArtifactoryPrefix     = "AKCpFAKE"
	TokenDockerHubPrefix       = "dckr_pat_FAKE"
	TokenCircleCIPrefix        = "CCIPAT_FAKE"
	TokenTerraformPrefix       = "FAKE00000000.atlasv1.FAKE"
	TokenSnykPrefix            = "deadfake-dead-fake-snyk-"
	TokenBitbucketPrefix       = "ATBBFAKE"
	TokenVaultPrefix           = "hvs.FAKE"
	TokenOpenAIPrefix          = "sk-FAKE"
	TokenOpenAIMarker          = "T3BlbkFJ"
	TokenAnthropicPrefix       = "sk-ant-api03-FAKE"
	TokenRazorpayPrefix        = "rzp_live_FAKE"
	TokenItsdangerousPrefix    = "tok-signed-"
	TokenCustomBlockPrefix     = "tok-blocked-"
	// TokenADMachineAccountPrefix begins every generated fake AD
	// machine-account name. The minted token itself always ends in a
	// literal "$" (baked in by the generator, not reconstructed via a
	// Format function), the same "preserve the structural marker,
	// opaque-ify the rest" idea as an AWS key token preserving its real
	// vendor prefix, and it keeps this a fully self-contained,
	// fixed-shape token (detokenize needs no custom per-entity logic,
	// just a plain tokenPatterns regex, unlike the domain/email/IP
	// cases that genuinely do have variable-length real structure to
	// carry through).
	TokenADMachineAccountPrefix = "FAKEHOST"
	// TokenGPPCPasswordPrefix begins every generated fake GPP cpassword
	// value, deliberately NOT valid base64 (contains "-", which never
	// appears in base64's alphabet), so it can never be mistaken for a
	// real decryptable cpassword value if it somehow ended up somewhere
	// this tool doesn't control.
	TokenGPPCPasswordPrefix = "FAKE-CPASSWORD-"
)

var counterKeyIPNetwork = []byte("ip_network")
var counterKeyIPv6Network = []byte("ipv6_network")

// nanpFakeAreaCodes is a curated set of real, ordinary geographic NANP
// area codes, combined with TokenPhonePrefix's reserved 555-01XX
// exchange to build fake NANP numbers. That exchange is reserved for
// fictional use under EVERY area code, not just one (the same
// convention film and TV productions rely on), so pairing it with any
// area code below gives a genuinely non-issuable number regardless of
// which one is picked. Drawing from a spread of area codes rather than
// one fixed one multiplies the token space from 100 (a single area
// code's worth) to len(this list)*100, comfortably covering even a
// large engagement's worth of distinct real phone numbers (a vishing-
// heavy assessment cataloging hundreds of employee extensions, say)
// without the earlier fixed-area-code design's risk of exhausting a
// mere 100 slots and fail-closed blocking the request that hit the
// 101st.
//
// Excludes N11 codes (211/311/etc.), toll-free (800/833/...), and
// premium-rate (900): none of those are ordinary geographic area
// codes, and using one would look wrong in a way that occasionally
// costs plausibility for no real benefit, since the safety property
// here comes entirely from the reserved exchange, not from which area
// code carries it.
var nanpFakeAreaCodes = []string{
	"201", "202", "205", "206", "212", "213", "214", "215", "216", "217",
	"224", "225", "234", "239", "248", "251", "260", "267", "281", "301",
	"302", "303", "305", "312", "313", "314", "315", "316", "317", "319",
	"401", "402", "404", "405", "407", "408", "410", "412", "413", "414",
	"415", "416", "469", "470", "480", "484", "501", "502", "503", "504",
	"505", "508", "510", "512", "513", "514", "515", "516", "517", "518",
	"519", "520", "530", "601", "602", "603", "604", "605", "606", "607",
	"608", "609", "610", "612", "613", "614", "615", "616", "617", "618",
	"619", "701", "702", "703", "704", "705", "706", "707", "708", "713",
	"714", "715", "716", "717", "718", "719", "720", "801", "802", "803",
	"804", "805", "806", "808", "810", "812", "813", "814", "815", "816",
	"817", "818", "901", "902", "903", "904", "905", "906", "907", "908",
	"909", "910",
}

// randomTokenShapes is the mint recipe for every entity type whose token
// is drawn at random: one closure per type, each producing a fresh
// candidate on every call (see nextRandom for the retry loop around it).
// A table rather than a switch arm each, since the arms differed only in
// which prefix and how many random characters: with the recipes lined up
// here, "does this shape match what Detokenize's pattern for the same
// entity expects?" is one glance down the column rather than a scroll
// through near-identical cases. The two counter-based types (IPv4 and
// IPv6 networks) are NOT here; they need the write transaction to
// increment a persisted counter, which a bare func() string can't carry
// (see next's own switch).
var randomTokenShapes = map[EntityType]func() string{
	EntityDomain:     func() string { return TokenDomainPrefix + randomHex(8) },
	EntityEmailLocal: func() string { return TokenEmailLocalPrefix + randomHex(6) },
	EntityPhone: func() string {
		return nanpFakeAreaCodes[randomIndex(len(nanpFakeAreaCodes))] + "-" + TokenPhonePrefix + randomDigits(2)
	},
	EntityIntlPhone: func() string {
		// Retries within "01XX" -- TokenPhonePrefix's reserved NANP
		// subrange, a strict subset of this 0000-9999 draw -- so the
		// two token subspaces stay disjoint by construction. See
		// detokenizeIntlPhoneTokens's matching guard in engine.go for
		// what a collision would otherwise cause.
		d := randomDigits(4)
		for d >= "0100" && d <= "0199" {
			d = randomDigits(4)
		}
		return TokenIntlPhonePrefix + d
	},
	EntityJWT: func() string {
		return fmt.Sprintf("%s%s.%s.%s", TokenJWTPrefix, randomHex(4), randomHex(16), randomHex(16))
	},
	EntityBearerToken:  func() string { return TokenBearerPrefix + randomHex(16) },
	EntityAWSKey:       func() string { return TokenAWSKeyPrefix + strings.ToUpper(randomHex(6)) },
	EntityAWSSecretKey: func() string { return TokenAWSSecretKeyPrefix + randomHex(16) },
	EntityPEMKey:       func() string { return TokenPEMKeyBeginMarker + randomHex(24) + TokenPEMKeyEndMarker },
	EntityPasswordHash: func() string { return TokenPasswordHashPrefix + randomHex(24) },
	EntityMAC: func() string {
		return fmt.Sprintf("%s%s:%s:%s", TokenMACPrefix, randomHex(1), randomHex(1), randomHex(1))
	},
	EntityAadhaar:         func() string { return TokenAadhaarPrefix + randomDigits(4) + " " + randomDigits(4) },
	EntityPAN:             func() string { return TokenPANPrefix + randomDigits(4) + randomUpperLetter() },
	EntityGitHubToken:     func() string { return TokenGitHubPrefix + randomHex(16) },
	EntityGitLabToken:     func() string { return TokenGitLabPrefix + randomHex(8) },
	EntitySlackToken:      func() string { return TokenSlackTokenPrefix + randomHex(4) },
	EntitySlackWebhook:    func() string { return TokenSlackWebhookMarker + randomHex(16) },
	EntityStripeKey:       func() string { return TokenStripePrefix + randomHex(8) },
	EntityGoogleAPIKey:    func() string { return TokenGoogleAPIKeyPrefix + randomHex(14) },
	EntityNPMToken:        func() string { return TokenNPMPrefix + randomHex(16) },
	EntityConnString:      func() string { return TokenConnStringMarker + randomHex(12) },
	EntityTwilioSID:       func() string { return TokenTwilioSIDPrefix + randomHex(15) },
	EntitySendGridKey:     func() string { return fmt.Sprintf("%s%s.%s", TokenSendGridPrefix, randomHex(10), randomHex(20)) },
	EntityDigitalOcean:    func() string { return TokenDigitalOceanPrefix + randomHex(30) },
	EntityCloudflare:      func() string { return TokenCloudflarePrefix + randomHex(22) },
	EntityAzureStorageKey: func() string { return TokenAzureStorageKeyPrefix + randomHex(30) },
	EntityArtifactory:     func() string { return TokenArtifactoryPrefix + randomHex(30) },
	EntityDockerHub:       func() string { return TokenDockerHubPrefix + randomHex(14) },
	EntityCircleCI:        func() string { return fmt.Sprintf("%s%s_%s", TokenCircleCIPrefix, randomHex(9), randomHex(20)) },
	EntityTerraform:       func() string { return TokenTerraformPrefix + randomHex(30) },
	EntitySnyk:            func() string { return TokenSnykPrefix + randomHex(6) },
	EntityBitbucket:       func() string { return TokenBitbucketPrefix + randomHex(20) },
	EntityVault:           func() string { return TokenVaultPrefix + randomHex(50) },
	EntityOpenAI: func() string {
		return fmt.Sprintf("%s%s%s%s", TokenOpenAIPrefix, randomHex(10), TokenOpenAIMarker, randomHex(10))
	},
	EntityAnthropicKey:      func() string { return TokenAnthropicPrefix + randomHex(44) + "AA" },
	EntityRazorpay:          func() string { return TokenRazorpayPrefix + randomHex(5) },
	EntityItsdangerousToken: func() string { return TokenItsdangerousPrefix + randomHex(16) },
	EntityCustomBlock:       func() string { return TokenCustomBlockPrefix + randomHex(16) },
	EntityADMachineAccount:  func() string { return TokenADMachineAccountPrefix + randomHex(6) + "$" },
	EntityGPPCPassword:      func() string { return TokenGPPCPasswordPrefix + randomHex(24) },
}

// AllEntityTypes returns every entity type this package can mint a token
// for, sorted so callers get a stable order.
//
// Derived from the generator's own tables (randomTokenShapes, plus the
// two counter-based network types nextToken switches on separately)
// rather than a hand-maintained list: a list would silently stop
// covering the day someone adds an entity type and doesn't know to also
// edit it, which is the failure mode where a missing check looks exactly
// like a passing one. Exported for the cross-package invariants that
// have to hold for EVERY type at once, not just the ones a given test
// happened to name: that each minted token still round-trips through
// redact.Engine.Detokenize, and that none of them outgrows the
// streaming flush window (see proxyserver's maxHeldTokenRunBytes).
func AllEntityTypes() []EntityType {
	out := make([]EntityType, 0, len(randomTokenShapes)+2)
	out = append(out, EntityIPNetwork, EntityIPv6Network)
	for et := range randomTokenShapes {
		out = append(out, et)
	}
	slices.Sort(out)
	return out
}

// nextToken mints a new token for entity type et. It must be called
// inside an open bbolt write transaction (tx) so counter increments and
// collision checks are atomic with the caller's own persistence of the
// mapping. existingTokens lets it avoid (vanishingly unlikely)
// collisions with already-minted random tokens without a DB round trip.
func nextToken(tx *bolt.Tx, et EntityType, existingTokens map[string]string) (string, error) {
	// The two counter-based network types come first: unlike everything
	// in randomTokenShapes, their token IS a sequence position, so
	// they're allocated from a persisted counter rather than drawn.
	switch et {
	case EntityIPNetwork:
		return nextIPNetwork(tx, existingTokens)
	case EntityIPv6Network:
		return nextIPv6Network(tx, existingTokens)
	}
	shape, ok := randomTokenShapes[et]
	if !ok {
		return "", fmt.Errorf("unknown entity type %q", et)
	}
	return nextRandom(existingTokens, shape)
}

// nextRandom retries generation on the astronomically unlikely event of a
// collision with an already-minted token.
func nextRandom(existingTokens map[string]string, gen func() string) (string, error) {
	for range 10 {
		candidate := gen()
		if _, taken := existingTokens[candidate]; !taken {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("failed to generate a unique token after 10 attempts")
}

// nextIPNetwork mints a fake /24-network token: "198.18." + one octet.
// Real value key (chosen by the caller, redact.ipv4Detector) is the real
// address's first three octets, so every host in the same real /24
// shares this same token; only 256 distinct networks per engagement,
// which comfortably covers realistic scope (an engagement touching
// hundreds of distinct /24s would be unusual).
func nextIPNetwork(tx *bolt.Tx, existingTokens map[string]string) (string, error) {
	b := tx.Bucket(bucketCounters)
	n, err := incrementCounter(b, counterKeyIPNetwork)
	if err != nil {
		return "", err
	}
	if n > 256 {
		return "", fmt.Errorf("exhausted %sXX token network space (256 networks)", TokenIPNetworkPrefix)
	}
	candidate := fmt.Sprintf("%s%d", TokenIPNetworkPrefix, n-1) // n is 1-indexed; shift to cover 0..255
	if _, taken := existingTokens[candidate]; taken {
		return "", fmt.Errorf("token IP network collision on %s (counter desync)", candidate)
	}
	return candidate, nil
}

// nextIPv6Network mints a fake /64-network token: "fd00:c0de:" + two hex
// groups (32 bits from a counter; over four billion distinct networks,
// no realistic exhaustion risk).
func nextIPv6Network(tx *bolt.Tx, existingTokens map[string]string) (string, error) {
	b := tx.Bucket(bucketCounters)
	n, err := incrementCounter(b, counterKeyIPv6Network)
	if err != nil {
		return "", err
	}
	high := uint16(n >> 16)
	low := uint16(n)
	candidate := fmt.Sprintf("%s%04x:%04x", TokenIPv6NetworkPrefix, high, low)
	if _, taken := existingTokens[candidate]; taken {
		return "", fmt.Errorf("token IPv6 network collision on %s (counter desync)", candidate)
	}
	return candidate, nil
}

// incrementCounter atomically reads-increments-writes a uint32 counter in
// bucket b under key, returning the new value. Must be called inside the
// same write transaction that persists whatever the counter is gating.
func incrementCounter(b *bolt.Bucket, key []byte) (uint32, error) {
	var cur uint32
	if raw := b.Get(key); raw != nil {
		if len(raw) != 4 {
			return 0, fmt.Errorf("corrupt counter value for %s", key)
		}
		cur = binary.BigEndian.Uint32(raw)
	}
	cur++
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, cur)
	if err := b.Put(key, buf); err != nil {
		return 0, err
	}
	return cur, nil
}

// randomDigits returns a string of n random decimal digits (0-9 each),
// using crypto/rand, for token bodies that must look numeric (Aadhaar,
// PAN, international phone subscriber numbers), where hex output would
// include non-digit characters.
func randomDigits(n int) string {
	digits := make([]byte, n)
	for i := range digits {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			panic(fmt.Sprintf("tokenstore: crypto/rand read failed: %v", err))
		}
		digits[i] = byte('0') + byte(d.Int64())
	}
	return string(digits)
}

// randomUpperLetter returns one random uppercase A-Z letter.
func randomUpperLetter() string {
	n, err := rand.Int(rand.Reader, big.NewInt(26))
	if err != nil {
		panic(fmt.Sprintf("tokenstore: crypto/rand read failed: %v", err))
	}
	return string(rune('A' + n.Int64()))
}

// randomIndex returns a cryptographically random index in [0, n).
func randomIndex(n int) int {
	i, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(fmt.Sprintf("tokenstore: crypto/rand read failed: %v", err))
	}
	return int(i.Int64())
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is a fatal environment problem, not a
		// recoverable case; panic rather than mint a predictable token.
		panic(fmt.Sprintf("tokenstore: crypto/rand read failed: %v", err))
	}
	return hex.EncodeToString(buf)
}
