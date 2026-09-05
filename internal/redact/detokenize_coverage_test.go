package redact

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// structurePreservingEntities are the entity types whose minted token is
// deliberately only PART of what appears on the wire: the rest is real
// text the detector carries through literally beside it (an IPv4 host
// octet, an IPv6 interface ID, an international phone number's country
// code). A bare token of one of these types is not a complete wire span
// and is not expected to detokenize on its own, so the round-trip below
// assembles the real wire shape for each and states what restoring it
// should produce.
//
// The restored form is not always byte-identical to what was stored: an
// IPv6 address comes back through netip's canonical "::"-compressed
// rendering, deliberately (see detokenizeIPv6Tokens).
var structurePreservingEntities = map[tokenstore.EntityType]struct {
	wire func(token string) string
	want string
}{
	tokenstore.EntityIPNetwork: {
		wire: func(token string) string { return token + ".42" },
		want: "10.11.12.42",
	},
	tokenstore.EntityIPv6Network: {
		wire: func(token string) string { return token + ":0000:0000:0000:1234" },
		want: "fd12:3456:7890:1::1234",
	},
	tokenstore.EntityIntlPhone: {
		wire: func(token string) string { return "+91-" + token },
		want: "+919812345678",
	},
}

// TestDetokenize_EveryEntityTypeRoundTrips holds the whole-set
// invariant: every entity type tokenstore can mint must have a matching
// pattern on the detokenize side, with a matching length.
//
// Getting that wrong is quiet and expensive. Engine.Detokenize fails
// open by design (an unrecognized token is left as literal text rather
// than erroring), so a new entity type added with no tokenPatterns entry,
// or with one whose hex-digit count doesn't match what the generator
// actually produces (randomHex(n) emits 2n characters, an easy off-by-
// double), produces no error anywhere. It just means Claude Code gets
// the fake value instead of the real one, and every tool call built on
// it runs against a hostname or credential that doesn't exist.
//
// Driven by tokenstore.AllEntityTypes rather than a list written out
// here, so a newly added type is covered the moment it exists; see that
// function's doc comment.
func TestDetokenize_EveryEntityTypeRoundTrips(t *testing.T) {
	store, err := tokenstore.Open(filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	e := New(store)

	for i, et := range tokenstore.AllEntityTypes() {
		real := realValueFor(t, et, i)
		token, err := store.GetOrCreateToken(real, et)
		if err != nil {
			t.Errorf("%s: mint: %v", et, err)
			continue
		}

		wire, wantBack := token, real
		if sp, ok := structurePreservingEntities[et]; ok {
			wire, wantBack = sp.wire(token), sp.want
		}

		// Embedded in ordinary prose, not alone: the detokenize patterns
		// carry deliberate boundary rules (see engine.go's doc comment
		// above domainTokenRe), so a token that only resolves in
		// isolation would still be a real leak in practice.
		if got := e.Detokenize("value " + wire + " here"); got != "value "+wantBack+" here" {
			t.Errorf("%s: token %q did not detokenize back to %q (got %q); is there a matching entry in tokenPatterns, or a dedicated detokenizeXxx pass, with the right length?",
				et, wire, wantBack, got)
		}
	}
}

// realValueFor builds a plausible real value to mint et's token against.
// Most entity types never look at it (the token is drawn at random
// regardless), but the two network types key off a parseable address
// shape, and the round-trip assertion compares against whatever is
// stored, so it has to be a value that shape's own detokenize pass can
// reconstruct.
func realValueFor(t *testing.T, et tokenstore.EntityType, i int) string {
	t.Helper()
	switch et {
	case tokenstore.EntityIPNetwork:
		return "10.11.12"
	case tokenstore.EntityIPv6Network:
		return "fd12345678900001" // 16 hex chars: the stored /64 key form
	case tokenstore.EntityIntlPhone:
		return "+919812345678"
	}
	return "real-value-" + string(rune('a'+i%26)) + "-" + string(et)
}

// TestDetokenize_TokenPatternsAreAllReachable guards the other direction
// of the same invariant: an entry in tokenPatterns that no generator
// shape can ever produce is dead weight that reads as coverage. Every
// pattern must match at least one actually-minted token.
func TestDetokenize_TokenPatternsAreAllReachable(t *testing.T) {
	store, err := tokenstore.Open(filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var minted []string
	for i, et := range tokenstore.AllEntityTypes() {
		token, err := store.GetOrCreateToken(realValueFor(t, et, i), et)
		if err != nil {
			t.Fatal(err)
		}
		minted = append(minted, token)
	}

	for _, re := range tokenPatterns {
		matched := false
		for _, token := range minted {
			if re.MatchString(token) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("tokenPatterns entry %q matches no token any generator shape produces; it can never fire, so whatever it was meant to restore is silently left as a placeholder", re)
		}
	}
}

// TestDetokenize_TokenPatternsDoNotOverlap confirms no two tokenPatterns
// entries claim the same minted token. combinedTokenPatternRe merges
// them into one alternation whose first matching branch wins, so an
// overlap would mean one shape's tokens silently resolving through
// another's branch, with the winner depending on declaration order
// rather than on anything deliberate.
func TestDetokenize_TokenPatternsDoNotOverlap(t *testing.T) {
	store, err := tokenstore.Open(filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for i, et := range tokenstore.AllEntityTypes() {
		token, err := store.GetOrCreateToken(realValueFor(t, et, i), et)
		if err != nil {
			t.Fatal(err)
		}
		var claimants []string
		for _, re := range tokenPatterns {
			if re.MatchString(token) {
				claimants = append(claimants, re.String())
			}
		}
		if len(claimants) > 1 {
			t.Errorf("%s token %q is claimed by %d tokenPatterns entries: %s", et, token, len(claimants), strings.Join(claimants, "  ||  "))
		}
	}
}
