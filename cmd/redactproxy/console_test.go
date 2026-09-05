package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func openConsoleTestStore(t *testing.T) *tokenstore.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestHandleConsoleLine_ShowAndRemove is the core regression test for
// this feature: the interactive console operates on the SAME in-process
// Store a running proxy already has open, so "remove" here must
// actually delete from that live store (no second bbolt.Open, no lock
// contention), exactly what lets an operator fix a false positive
// without stopping (and dropping) a live Claude Code session.
func TestHandleConsoleLine_ShowAndRemove(t *testing.T) {
	store := openConsoleTestStore(t)
	if _, err := store.GetOrCreateToken("widgetcorp-fixture.com", tokenstore.EntityDomain); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		handleConsoleLine(store, "xyz-example-corp", "/fake/tokens.db", "/fake/rules.json", "show")
	})
	if !strings.Contains(out, "widgetcorp-fixture.com") {
		t.Fatalf("expected the minted entry in \"show\" output, got: %s", out)
	}

	captureStdout(t, func() {
		handleConsoleLine(store, "xyz-example-corp", "/fake/tokens.db", "/fake/rules.json", "remove widgetcorp-fixture.com")
	})

	if _, ok := store.LookupToken("widgetcorp-fixture.com"); ok {
		t.Fatal("expected \"remove\" to delete the entry from the SAME live store instance")
	}
}

func TestHandleConsoleLine_RemoveWrongArgCountPrintsUsageNotCrash(t *testing.T) {
	store := openConsoleTestStore(t)
	out := captureStdout(t, func() {
		handleConsoleLine(store, "xyz-example-corp", "/fake/tokens.db", "/fake/rules.json", "remove")
	})
	if !strings.Contains(out, "usage:") {
		t.Errorf("expected a usage hint for \"remove\" with no argument, got: %s", out)
	}
}

func TestHandleConsoleLine_UnknownCommandPrintsHint(t *testing.T) {
	store := openConsoleTestStore(t)
	out := captureStdout(t, func() {
		handleConsoleLine(store, "xyz-example-corp", "/fake/tokens.db", "/fake/rules.json", "bogus")
	})
	if !strings.Contains(out, "unknown command") {
		t.Errorf("expected an unknown-command hint, got: %s", out)
	}
}

func TestHandleConsoleLine_Help(t *testing.T) {
	store := openConsoleTestStore(t)
	out := captureStdout(t, func() {
		handleConsoleLine(store, "xyz-example-corp", "/fake/tokens.db", "/fake/rules.json", "help")
	})
	if !strings.Contains(out, "show") || !strings.Contains(out, "remove") {
		t.Errorf("expected help text to mention show and remove, got: %s", out)
	}
}

func TestHandleConsoleLine_RemoveUnknownValueReportsErrorNotCrash(t *testing.T) {
	store := openConsoleTestStore(t)
	// Errors from removeToken go to stderr via handleConsoleLine, not
	// stdout; this test's only real requirement is that an unknown
	// value doesn't panic the console goroutine (which would silently
	// kill background command handling for the rest of the session).
	handleConsoleLine(store, "xyz-example-corp", "/fake/tokens.db", "/fake/rules.json", "remove never-seen.example.com")
}

// TestStdinIsTerminal_FalseForAPipe pins the underlying check
// stdinIsTerminal relies on: a pipe is never a char device, so this
// must report false. (go test's OWN stdin can itself be a char device
// depending on how the test binary was launched, confirmed true in
// this sandbox, so TestStartConsole_NonTerminalStdinReturnsImmediately
// below stubs os.Stdin explicitly rather than relying on the ambient
// environment.)
func TestStdinIsTerminal_FalseForAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig }()

	if stdinIsTerminal() {
		t.Fatal("expected a pipe to never report as a terminal")
	}
}

// TestStartConsole_NonTerminalStdinReturnsImmediately confirms the
// console doesn't activate (and doesn't block) when stdin isn't a real
// terminal, the case for any nohup/systemd/background launch of the
// real binary, where there's no operator there to type into it.
// os.Stdin is explicitly stubbed to a pipe here rather than relying on
// go test's own (environment-dependent) stdin.
func TestStartConsole_NonTerminalStdinReturnsImmediately(t *testing.T) {
	store := openConsoleTestStore(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig }()

	out := captureStdout(t, func() {
		startConsole(store, "xyz-example-corp", "/fake/tokens.db", "/fake/rules.json")
	})
	if out != "" {
		t.Fatalf("expected no console banner when stdin isn't a terminal, got: %s", out)
	}
}
