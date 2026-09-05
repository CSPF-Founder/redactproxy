package redact

import "strings"

// Hand-rolled international phone number validation, deliberately NOT a
// full libphonenumber-equivalent dependency. A "find numbers in free
// text" API needs a permissive candidate regex plus validation anyway
// (see phoneDetector's doc comment on the loose-candidate/precise-Go-
// side-check split), so the actual work a heavyweight metadata dependency
// would add on top is just the final Parse/IsValidNumber step, not
// worth a large dependency for, given this project's preference to keep
// the dependency footprint small.
//
// This trades per-country precision (real libphonenumber knows the exact
// National Significant Number length for every region, plus area-code
// structure) for a much smaller, self-contained check: is the "+"-
// prefixed candidate's calling code a REAL, ITU-T-assigned one, and is
// what follows a plausible subscriber-number length. That's meaningfully
// more precise than shape-only (a bare digit-count regex), while staying
// dependency-free, using the same "curated reference table, not a live spec"
// approach already used for domain suffixes (tlds.go).
//
// Known imprecision, accepted deliberately: this does not validate the
// exact National Significant Number length per region (e.g. it accepts
// any length in [minNationalDigits, maxNationalDigits] for every country
// alike, when real rules vary: a UK number is always 10 digits after
// "44", a few small nations use far shorter numbers). This can pass a
// small number of not-quite-real numbers and, at the edges, reject a
// small number of real short ones. Consistent with this package's
// existing tradeoffs (see the ccTLD collision and PAN-checksum notes):
// erring toward over-redaction of plausible-looking candidates is the
// safer failure mode for a tool whose job is not letting real PII
// through.

const (
	minNationalDigits = 4
	maxNationalDigits = 12
)

// callingCodes is a curated set of real ITU-T E.164 country calling
// codes (1-3 digits). E.164 codes are allocated to be prefix-free (no
// valid code is a prefix of another), so matching longest-first and
// stopping at the first hit is safe and unambiguous.
var callingCodes = buildCallingCodes()

func buildCallingCodes() map[string]bool {
	// Zone 1 (NANP) is deliberately excluded; phoneRe/phoneDetector
	// already fully owns NANP-shaped numbers, with tighter formatting
	// (exact 3-3-4 grouping) than this package's generic bounds would
	// give; excluding "1" here avoids the two detectors fighting over
	// the same numbers with two different quality bars.
	codes := []string{
		// Zone 2: Africa + a few others
		"20", "27",
		"211", "212", "213", "216", "218", "220", "221", "222", "223", "224",
		"225", "226", "227", "228", "229", "230", "231", "232", "233", "234",
		"235", "236", "237", "238", "239", "240", "241", "242", "243", "244",
		"245", "246", "247", "248", "249", "250", "251", "252", "253", "254",
		"255", "256", "257", "258", "260", "261", "262", "263", "264", "265",
		"266", "267", "268", "269",
		// Zone 3/4: Europe
		"30", "31", "32", "33", "34", "36", "39", "40", "41", "43", "44", "45",
		"46", "47", "48", "49",
		"350", "351", "352", "353", "354", "355", "356", "357", "358", "359",
		"370", "371", "372", "373", "374", "375", "376", "377", "378", "379",
		"380", "381", "382", "383", "385", "386", "387", "389",
		"420", "421", "423",
		// Zone 5: Central/South America
		"51", "52", "53", "54", "55", "56", "57", "58",
		"590", "591", "592", "593", "594", "595", "596", "597", "598", "599",
		// Zone 6: Southeast Asia / Oceania
		"60", "61", "62", "63", "64", "65", "66",
		"670", "672", "673", "674", "675", "676", "677", "678", "679", "680",
		"681", "682", "683", "685", "686", "687", "688", "689", "690", "691",
		"692",
		// Zone 7: Russia/Kazakhstan
		"7",
		// Zone 8: East Asia
		"81", "82", "84", "86",
		"850", "852", "853", "855", "856", "880", "886",
		// Zone 9: South/West Asia, Middle East
		"90", "91", "92", "93", "94", "95", "98",
		"960", "961", "962", "963", "964", "965", "966", "967", "968", "970",
		"971", "972", "973", "974", "975", "976", "977",
		"992", "993", "994", "995", "996", "998",
	}
	m := make(map[string]bool, len(codes))
	for _, c := range codes {
		m[c] = true
	}
	return m
}

// splitCallingCode tries the longest match first (3 digits, then 2, then
// 1) against callingCodes, since E.164 codes are prefix-free. digits must
// contain ONLY '0'-'9' (no leading "+"). Returns ok=false if no real
// calling code matches.
func splitCallingCode(digits string) (cc string, rest string, ok bool) {
	for length := 3; length >= 1; length-- {
		if len(digits) <= length {
			continue
		}
		candidate := digits[:length]
		if callingCodes[candidate] {
			return candidate, digits[length:], true
		}
	}
	return "", "", false
}

// parseIntlPhone validates a "+"-prefixed candidate and, if it's a
// plausible non-NANP international number, returns the real calling code
// and the subscriber digits separately (never combined; the caller
// needs them apart to preserve the calling code and tokenize only the
// subscriber portion).
func parseIntlPhone(candidate string) (cc string, subscriber string, ok bool) {
	if !strings.HasPrefix(candidate, "+") {
		return "", "", false
	}
	digits := stripNonDigits(candidate[1:])
	cc, rest, ok := splitCallingCode(digits)
	if !ok {
		return "", "", false
	}
	if len(rest) < minNationalDigits || len(rest) > maxNationalDigits {
		return "", "", false
	}
	if isDegenerateDigitRun(rest) {
		return "", "", false // e.g. "+44 000000000": placeholder, not real
	}
	return cc, rest, true
}

func stripNonDigits(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
