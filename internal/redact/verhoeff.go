package redact

// Verhoeff checksum validation, used to gate Aadhaar-number detection. A
// bare 12-digit run is common enough in unrelated contexts (ports, IDs,
// timestamps, truncated hashes) that shape alone would cause frequent
// false positives; Verhoeff catches essentially any single-digit error or
// adjacent-digit transposition, cutting the false-accept rate on random
// 12-digit input down to 1 in 10 (one check digit) rather than 1 in 1,
// the same "validate what a loose regex found" principle used everywhere
// else in this package (netip for IPs, PSL/TLD gate for domains).
//
// Tables are the standard, publicly documented Verhoeff construction (a
// checksum over the dihedral group D5), not something this package
// invented. See https://en.wikipedia.org/wiki/Verhoeff_algorithm.

var verhoeffMultiplication = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

var verhoeffPermutation = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// verhoeffValid reports whether digits (a string of ASCII '0'-'9', rightmost
// character the check digit) satisfies the Verhoeff checksum. Any
// non-digit character makes it invalid.
func verhoeffValid(digits string) bool {
	c := 0
	n := len(digits)
	for i := 0; i < n; i++ {
		ch := digits[n-1-i]
		if ch < '0' || ch > '9' {
			return false
		}
		d := int(ch - '0')
		c = verhoeffMultiplication[c][verhoeffPermutation[i%8][d]]
	}
	return c == 0
}
