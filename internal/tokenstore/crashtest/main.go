// crashtest is a test helper, not a shipped binary: it continuously mints
// tokens for a known sequence of real values, printing each one to stdout
// immediately after it commits, so a driver (see
// internal/tokenstore/crash_test.go) can SIGKILL it at an arbitrary point
// and verify every value printed before the kill survives with the same
// token after a fresh Open, proving the token store is genuinely crash-
// consistent, not just safe across a clean Close.
package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

func main() {
	dbPath := os.Args[1]
	store, err := tokenstore.Open(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	out := bufio.NewWriter(os.Stdout)
	defer func() { _ = out.Flush() }()

	i := 0
	for {
		real := fmt.Sprintf("crashtarget%d.example", i)
		tok, err := store.GetOrCreateToken(real, tokenstore.EntityDomain)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mint:", err)
			os.Exit(1)
		}
		// Both checked, and fatal: this helper's contract with the driver
		// is that every line the driver READ is a mint that survived the
		// kill. A line lost in the buffer would surface on the other side
		// as a token the driver never saw, i.e. indistinguishable from the
		// store losing a committed write, which is the exact bug this
		// helper exists to detect.
		if _, err := fmt.Fprintf(out, "%s %s\n", real, tok); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
		if err := out.Flush(); err != nil {
			fmt.Fprintln(os.Stderr, "flush:", err)
			os.Exit(1)
		}
		i++
	}
}
