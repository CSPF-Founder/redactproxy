package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// runTokens implements `redactproxy tokens <subcommand>`: inspecting or
// undoing entries in an engagement's already-minted token store.
// Deliberately separate from `redactproxy rules`: rules (block/allow)
// decide what gets tokenized on FUTURE requests; tokens
// show/remove operate on the store's actual, already-minted mappings,
// e.g. undoing a false positive that already happened, or just seeing
// what's been tokenized so far without turning on debug logging.
func runTokens(args []string) error {
	if len(args) == 0 {
		printTokensUsage()
		return nil
	}
	switch args[0] {
	case "show":
		return tokensShow(args[1:])
	case "remove":
		return tokensRemove(args[1:])
	case "-h", "-help", "--help", "help":
		printTokensUsage()
		return nil
	default:
		if strings.HasPrefix(args[0], "-") {
			return fmt.Errorf("no tokens subcommand given (got the flag %q first); the subcommand (show or remove) must come immediately after \"tokens\", before any flags, e.g. \"redactproxy tokens show --engagement foo\"", args[0])
		}
		return fmt.Errorf("unknown tokens subcommand %q (want show or remove; run `redactproxy tokens` with no arguments for details)", args[0])
	}
}

func printTokensUsage() {
	fmt.Println(`redactproxy tokens: inspect or undo entries in an engagement's already-
minted token store (tokens.db). To control what gets tokenized on FUTURE
requests instead, use 'redactproxy rules block/allow'.

This CLI form needs the proxy to NOT be running for this engagement.
bbolt lets only one process hold tokens.db open at a time, the same
limit that stops two proxies sharing one engagement. If the proxy IS
running and you'd rather not stop it (stopping it drops any in-flight
Claude Code request), type "show" or "remove <value>" directly into
that proxy's own terminal instead. It reads simple commands from its
own stdin and applies them to the same store live, no restart needed.

Usage:
  redactproxy tokens show   [--engagement NAME] [--data-dir DIR]
  redactproxy tokens remove [--engagement NAME] [--data-dir DIR] <real-value>

Examples:
  redactproxy tokens show
  redactproxy tokens remove "widgetcorp-fixture.com"`)
}

func tokensShow(args []string) error {
	engagement, path, err := newEngagementFlags("redactproxy tokens show").parse(args, tokensDBPathFor)
	if err != nil {
		return err
	}
	store, err := tokenstore.Open(path)
	if err != nil {
		if tokenstore.IsLockTimeout(err) {
			return fmt.Errorf("open token store: the proxy is already running for this engagement, and only one process can hold tokens.db open at a time; type \"show\" directly into that proxy's own terminal instead: %w", err)
		}
		return fmt.Errorf("open token store at %s: %w", path, err)
	}
	// The command's whole output is produced below and the store is
	// read-only on this path; a close error afterwards changes nothing the
	// caller could act on.
	defer func() { _ = store.Close() }()

	return printTokens(store, engagement, path)
}

// printTokens prints every mapping in store, grouped by entity type.
// Shared between the standalone `redactproxy tokens show` CLI path
// (which opens its own Store, only possible while the proxy isn't
// running for this engagement) and the running proxy's interactive
// console (console.go), which reuses the Store the proxy already has
// open in-process, sidestepping bbolt's single-writer lock entirely,
// so this works without stopping a live session.
func printTokens(store *tokenstore.Store, engagement, path string) error {
	entries, err := store.List()
	if err != nil {
		return err
	}

	fmt.Printf("tokens for engagement %q\n%s\n\n", engagement, path)
	if len(entries) == 0 {
		fmt.Println("(no entries yet)")
		return nil
	}

	byType := map[tokenstore.EntityType][]tokenstore.Entry{}
	for _, e := range entries {
		byType[e.EntityType] = append(byType[e.EntityType], e)
	}
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, string(t))
	}
	slices.Sort(types)

	total := 0
	for _, t := range types {
		group := byType[tokenstore.EntityType(t)]
		fmt.Printf("%s (%d):\n", t, len(group))
		for _, e := range group {
			fmt.Printf("  %-40s -> %s  (first seen %s)\n", e.Real, e.Token, e.FirstSeen.Format("2006-01-02 15:04:05 MST"))
		}
		total += len(group)
	}
	fmt.Printf("\n%d total\n", total)
	return nil
}

func tokensRemove(args []string) error {
	ef := newEngagementFlags("redactproxy tokens remove")
	_, path, err := ef.parse(args, tokensDBPathFor)
	if err != nil {
		return err
	}
	if ef.fs.NArg() != 1 {
		return fmt.Errorf("usage: redactproxy tokens remove [--engagement NAME] [--data-dir DIR] <real-value>; flags must come before the value, e.g. \"tokens remove --engagement foo bar\", not \"tokens remove bar --engagement foo\"")
	}
	real := ef.fs.Arg(0)
	store, err := tokenstore.Open(path)
	if err != nil {
		if tokenstore.IsLockTimeout(err) {
			return fmt.Errorf("open token store: the proxy is already running for this engagement, and only one process can hold tokens.db open at a time; type \"remove %s\" directly into that proxy's own terminal instead: %w", real, err)
		}
		return fmt.Errorf("open token store at %s: %w", path, err)
	}
	// removeToken's deletion is committed by its own transaction before
	// this runs, so a close error here cannot undo it.
	defer func() { _ = store.Close() }()

	return removeToken(store, real, "redactproxy tokens show")
}

// removeToken deletes real's mapping from store and reports the result.
// Shared between the standalone `redactproxy tokens remove` CLI path and
// the running proxy's interactive console (console.go); see
// printTokens for why sharing this way matters. showHint is the exact
// phrase to suggest running to see what's currently stored, phrased
// differently depending on which path is calling (the full CLI command
// vs. the console's bare "show").
func removeToken(store *tokenstore.Store, real, showHint string) error {
	removed, err := store.Delete(real)
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("no mapping found for %q; run `%s` to see what's currently stored", real, showHint)
	}
	fmt.Printf("removed mapping for %q\n", real)
	fmt.Println("this only forgets that one past mapping, it does NOT stop future redaction. If the value")
	fmt.Println("shows up again it gets caught and tokenized again, this time as a NEW, different token,")
	fmt.Printf("since tokens aren't derived from the value itself. To stop %q being redacted at all,\n", real)
	fmt.Printf("use `redactproxy rules allow %q` instead, or as well.\n", real)
	return nil
}
