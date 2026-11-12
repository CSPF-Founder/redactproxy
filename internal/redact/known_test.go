package redact

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// TestKnownValues_HistoryRoundTrip reproduces the leak found in a long
// live session: a value caught only by its label is restored for the
// operator, and Claude Code then re-sends the reply as history without
// the label. Every later occurrence must get the same token.
func TestKnownValues_HistoryRoundTrip(t *testing.T) {
	e, _ := newTestEngine(t)
	cases := map[string]string{
		"password: Winter#2024x":                            "The decoded file gives the password as Winter#2024x.",
		"Authorization: Bearer " + bearerFixture:            "I sent " + bearerFixture + " in the header.",
		"admin NTLM hash: 8846f7eaee8fb117ad06bdd830b7586c": "Cracking 8846f7eaee8fb117ad06bdd830b7586c offline.",
	}
	for labelled, history := range cases {
		first, err := e.Tokenize(labelled)
		if err != nil {
			t.Fatal(err)
		}
		reply := e.Detokenize("Noted: " + strings.SplitN(first, " ", 2)[1])
		if !strings.Contains(reply, strings.SplitN(labelled, " ", 2)[1]) {
			t.Fatalf("setup: reply not restored: %q", reply)
		}
		later, err := e.Tokenize(history)
		if err != nil {
			t.Fatal(err)
		}
		secret := secretOf(labelled)
		if strings.Contains(later, secret) {
			t.Errorf("value leaked once its label was gone:\n  %q", later)
			continue
		}
		tok := strings.TrimPrefix(first, labelled[:len(labelled)-len(secret)])
		if !strings.Contains(later, tok) {
			t.Errorf("expected the same token %q, got %q", tok, later)
		}
		if back := e.Detokenize(later); back != history {
			t.Errorf("round trip: %q", back)
		}
	}
}

func secretOf(labelled string) string {
	f := strings.Fields(labelled)
	return f[len(f)-1]
}

const bearerFixture = "sk-test-abcdefghijklmnopqrstuvwxyz0123456789"

// TestKnownValues_LimitsToWholeStrongValues: only the value standing on
// its own is matched, and weak values are not chased through ordinary
// text, since that would redact a common word everywhere.
func TestKnownValues_LimitsToWholeStrongValues(t *testing.T) {
	e, _ := newTestEngine(t)
	for _, in := range []string{"password: Winter#2024x", "password: hunter22", "pwd: Abcdef", "password: 123456"} {
		if _, err := e.Tokenize(in); err != nil {
			t.Fatal(err)
		}
	}
	for _, in := range []string{
		"Winter#2024xyz is another string",
		"xWinter#2024x is too",
		"the word hunter22x and myhunter22",
		"a plain 123456 and Abcdef",
	} {
		if out, _ := e.Tokenize(in); out != in {
			t.Errorf("changed:\n  in:  %q\n  out: %q", in, out)
		}
	}
	if out, _ := e.Tokenize("(Winter#2024x) and 'hunter22'"); strings.Contains(out, "Winter#2024x") || strings.Contains(out, "hunter22") {
		t.Errorf("standalone known values next to punctuation not redacted: %q", out)
	}
}

// TestKnownValues_SurviveRestartAndRemoval: the set is rebuilt from the
// store when the proxy restarts, and a removed mapping stops being
// chased.
func TestKnownValues_SurviveRestartAndRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.db")
	store, err := tokenstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e := New(store, DefaultDetectors()...)
	if _, err := e.Tokenize("password: Winter#2024x"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = tokenstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	e = New(store, DefaultDetectors()...)
	const in = "it is still Winter#2024x"
	if out, _ := e.Tokenize(in); strings.Contains(out, "Winter#2024x") {
		t.Fatalf("known value forgotten after reopening the store: %q", out)
	}
	if removed, err := store.Delete("Winter#2024x"); err != nil || !removed {
		t.Fatalf("delete: %v %v", removed, err)
	}
	if out, _ := e.Tokenize(in); out != in {
		t.Fatalf("removed value still redacted without its label: %q", out)
	}
}
