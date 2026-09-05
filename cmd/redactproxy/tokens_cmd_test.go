package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

func TestRunTokens_NoArgsPrintsUsageWithoutError(t *testing.T) {
	if err := runTokens(nil); err != nil {
		t.Errorf("expected no error from `redactproxy tokens` with no arguments (just usage), got %v", err)
	}
}

func TestRunTokens_HelpVariantsPrintUsageWithoutError(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-help"}, {"--help"}, {"help"}} {
		if err := runTokens(args); err != nil {
			t.Errorf("runTokens(%v): expected no error (just printed usage), got %v", args, err)
		}
	}
}

func TestRunTokens_UnknownSubcommandStillErrors(t *testing.T) {
	if err := runTokens([]string{"bogus"}); err == nil {
		t.Fatal("expected an error for a genuinely unknown tokens subcommand")
	}
}

func TestTokensDBPathFor(t *testing.T) {
	base := t.TempDir()
	path, err := tokensDBPathFor(base, "xyz-example-corp")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "engagements", "xyz-example-corp", "tokens.db")
	if path != want {
		t.Fatalf("got %q, want %q", path, want)
	}
}

func TestTokensShow_EmptyStoreSucceeds(t *testing.T) {
	// -engagement writes a .redactproxy-engagement marker into the
	// working directory; keep that out of the package source tree.
	t.Chdir(t.TempDir())

	base := t.TempDir()
	if err := tokensShow([]string{"-engagement", "xyz-example-corp", "-data-dir", base}); err != nil {
		t.Fatalf("expected `tokens show` against a fresh, empty store to succeed, got %v", err)
	}
}

// TestTokensShow_OpenFailureForNonLockReasonDoesNotBlameTheProxy checks
// tokensShow's wrapped error message for an Open failure that is NOT
// lock contention (a directory sitting where tokens.db should be a
// file) without paying bbolt's real 5-second lock-wait timeout. Must
// NOT say "already running" -- that hint was, before
// tokenstore.IsLockTimeout existed, shown for every Open failure
// regardless of cause, actively misleading an operator debugging a
// genuinely corrupted or otherwise-broken tokens.db toward hunting for
// a nonexistent second proxy process instead.
func TestTokensShow_OpenFailureForNonLockReasonDoesNotBlameTheProxy(t *testing.T) {
	// -engagement writes a .redactproxy-engagement marker into the
	// working directory; keep that out of the package source tree.
	t.Chdir(t.TempDir())

	base := t.TempDir()
	path, err := tokensDBPathFor(base, "xyz-example-corp")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}

	err = tokensShow([]string{"-engagement", "xyz-example-corp", "-data-dir", base})
	if err == nil {
		t.Fatal("expected an error when the token store fails to open")
	}
	if strings.Contains(err.Error(), "already running") {
		t.Errorf("a non-lock-contention Open failure should not be blamed on the proxy already running, got: %v", err)
	}
}

func TestTokensRemove_RemovesRealMintedEntry(t *testing.T) {
	// -engagement writes a .redactproxy-engagement marker into the
	// working directory; keep that out of the package source tree.
	t.Chdir(t.TempDir())

	base := t.TempDir()
	path, err := tokensDBPathFor(base, "xyz-example-corp")
	if err != nil {
		t.Fatal(err)
	}

	store, err := tokenstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetOrCreateToken("widgetcorp-fixture.com", tokenstore.EntityDomain); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if err := tokensRemove([]string{"-engagement", "xyz-example-corp", "-data-dir", base, "widgetcorp-fixture.com"}); err != nil {
		t.Fatalf("tokensRemove: %v", err)
	}

	reopened, err := tokenstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, ok := reopened.LookupToken("widgetcorp-fixture.com"); ok {
		t.Fatal("expected the mapping to be gone after `tokens remove`")
	}
}

func TestTokensRemove_UnknownValueErrors(t *testing.T) {
	// -engagement writes a .redactproxy-engagement marker into the
	// working directory; keep that out of the package source tree.
	t.Chdir(t.TempDir())

	base := t.TempDir()
	err := tokensRemove([]string{"-engagement", "xyz-example-corp", "-data-dir", base, "never-seen.example.com"})
	if err == nil {
		t.Fatal("expected an error when removing a value that was never minted")
	}
}

func TestTokensRemove_RequiresExactlyOneValueArgument(t *testing.T) {
	// -engagement writes a .redactproxy-engagement marker into the
	// working directory; keep that out of the package source tree.
	t.Chdir(t.TempDir())

	base := t.TempDir()
	if err := tokensRemove([]string{"-engagement", "xyz-example-corp", "-data-dir", base}); err == nil {
		t.Fatal("expected an error with no value argument")
	}
	if err := tokensRemove([]string{"-engagement", "xyz-example-corp", "-data-dir", base, "a", "b"}); err == nil {
		t.Fatal("expected an error with more than one value argument")
	}
}

func TestTokensRemove_FlagAfterValueErrorExplainsOrdering(t *testing.T) {
	// Value-before-flags means the flag package stops parsing at the
	// value, so -engagement is never seen and resolution falls back to
	// this folder's marker. It needs one, or the command fails on "no
	// engagement" long before reaching the argument-ordering check this
	// test is actually about.
	t.Chdir(t.TempDir())
	if err := rememberEngagement("xyz-example-corp"); err != nil {
		t.Fatal(err)
	}

	base := t.TempDir()
	err := tokensRemove([]string{"never-seen.example.com", "-engagement", "xyz-example-corp", "-data-dir", base})
	if err == nil {
		t.Fatal("expected a usage error, got nil")
	}
	if !strings.Contains(err.Error(), "flags must come before the value") {
		t.Errorf("expected the error to explain the ordering rule, got: %v", err)
	}
}

func TestRunTokens_FlagImmediatelyAfterTokensExplainsMissingSubcommand(t *testing.T) {
	// "redactproxy tokens -engagement foo" (forgot the subcommand word
	// entirely) must not be reported as "unknown tokens subcommand
	// \"-engagement\"" -- that reads as if "-engagement" itself were the
	// problem, not that a subcommand was never given.
	err := runTokens([]string{"-engagement", "foo"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "no tokens subcommand given") {
		t.Errorf("expected the error to say no subcommand was given, got: %v", err)
	}
}
