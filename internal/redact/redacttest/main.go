// Command redacttest is a read-only manual-testing harness: it does not
// modify any redaction logic. It reads a text file, tokenizes it, and
// prints the tokenized output plus a summary of what changed, so a human
// can eyeball real-world sample text against the detector suite. Not part
// of the shipped binary's build graph beyond this standalone command.
package main

import (
	"fmt"
	"os"

	"github.com/CSPF-Founder/redactproxy/internal/redact"
	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: redacttest <file> [storepath]")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}

	storePath := "/tmp/redacttest_store.db"
	if len(os.Args) > 2 {
		storePath = os.Args[2]
	}
	store, err := tokenstore.Open(storePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store open:", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	e := redact.New(store, redact.DefaultDetectors()...)
	out, err := e.Tokenize(string(data))
	if err != nil {
		fmt.Fprintln(os.Stderr, "tokenize error (fail-closed):", err)
		os.Exit(1)
	}

	fmt.Println("=== TOKENIZED OUTPUT ===")
	fmt.Println(out)

	back := e.Detokenize(out)
	orig := string(data)
	if back != orig {
		fmt.Println("\n=== ROUND-TRIP MISMATCH ===")
		fmt.Printf("original len=%d, restored len=%d\n", len(orig), len(back))
		printFirstDiff(orig, back)
	} else {
		fmt.Println("\n=== ROUND-TRIP OK ===")
	}
}

func printFirstDiff(orig, back string) {
	n := min(len(orig), len(back))
	for i := range n {
		if orig[i] != back[i] {
			start := max(i-100, 0)
			end := min(i+100, n)
			fmt.Printf("first diff at byte %d\nORIG: %q\nBACK: %q\n", i, orig[start:end], back[start:min(end, len(back))])
			return
		}
	}
	fmt.Printf("common prefix matches for %d bytes; one string is a prefix of the other\n", n)
	if len(orig) > n {
		fmt.Printf("orig extra tail: %q\n", orig[n:min(n+150, len(orig))])
	}
	if len(back) > n {
		fmt.Printf("back extra tail: %q\n", back[n:min(n+150, len(back))])
	}
}
