package redact

import (
	"net/netip"
	"strings"
)

// isReservedDomain reports whether a (lowercased) domain match is one of
// the RFC 6761 special-use names reserved for documentation and testing:
// example.com/net/org/edu and the .test/.example/.invalid/.localhost
// pseudo-TLDs. These can never be real registrable targets, and they
// show up constantly in practice: copied from documentation, left in
// tool default configs, or used verbatim in tutorials that get pasted
// into scan notes. Tokenizing them would be actively unhelpful: there
// is nothing to protect, and it would make example-laden text harder to
// read for no benefit.
func isReservedDomain(lower string) bool {
	switch lower {
	case "example.com", "example.net", "example.org", "example.edu",
		"test", "example", "invalid", "localhost":
		return true
	}
	for _, suf := range []string{".example.com", ".example.net", ".example.org", ".example.edu",
		".test", ".example", ".invalid", ".localhost"} {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	return false
}

// isReservedIP reports whether ip is one of the ranges that can never be
// a real pentest target: loopback (RFC 5735 127.0.0.0/8, RFC 4291 ::1),
// and the IETF documentation ranges that exist specifically so examples
// never collide with a real address: RFC 5737 (192.0.2.0/24 "TEST-NET-1",
// 198.51.100.0/24 "TEST-NET-2", 203.0.113.0/24 "TEST-NET-3") and RFC 3849
// (2001:db8::/32). Ordinary private ranges (10/8, 172.16/12, 192.168/16)
// are deliberately NOT excluded; internal pentest engagements routinely
// target exactly those addresses, and they are exactly the kind of
// network-topology detail this tool exists to protect.
func isReservedIP(ip netip.Addr) bool {
	if ip.IsLoopback() {
		return true
	}
	if ip.Is4() {
		b := ip.As4()
		switch {
		case b[0] == 192 && b[1] == 0 && b[2] == 2: // 192.0.2.0/24
			return true
		case b[0] == 198 && b[1] == 51 && b[2] == 100: // 198.51.100.0/24
			return true
		case b[0] == 203 && b[1] == 0 && b[2] == 113: // 203.0.113.0/24
			return true
		}
		return false
	}
	if ip.Is6() {
		b := ip.As16()
		// 2001:db8::/32
		if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 {
			return true
		}
	}
	return false
}
