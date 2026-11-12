package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// claudeMemorySnippet is the suggested addition to a CLAUDE.md so a
// Claude Code session running through redactproxy understands what it's
// looking at, instead of treating placeholder values as garbage, trying
// to "correct" them, or hesitating to use them in tool calls. Kept
// deliberately short: long enough to inform reasoning, short enough
// that it doesn't get lost/ignored the way a long memory entry would.
//
// The rules come first, numbered, one instruction each with its reason
// in a line, and the shapes list last. An earlier version twice this
// length spread the same rules through long paragraphs; in a side by
// side run of the two (four tasks, two runs each per note) the shorter
// one did no worse on any task, so the length was not buying anything.
//
// The example prefixes below reference the real tokenstore.Token*Prefix
// constants directly (string concatenation, not retyped literals) so
// they're compiler-linked to internal/tokenstore/generator.go's actual
// values, rather than hand-typed literals that could quietly go stale as
// new entity types are added without this snippet being revisited. This
// does NOT auto-discover entirely new entity types added in the future,
// which still need one line added here deliberately (Go has no clean
// way to enumerate "every constant in this package" at compile time),
// but at least what IS shown can never silently go wrong.
const claudeMemorySnippet = `## Redaction proxy active (redactproxy)

A local proxy replaces client-sensitive values with stable placeholders
before your requests reach the API, and restores the real values before
any tool runs and before your reply is shown. You only ever see
placeholders; Bash, Read, Edit and MCP tools act on the real values.

Rules. Check them before every tool call or reply that contains a
placeholder:

1. **Copy placeholders exactly.** Take each one character-for-character
   from where it last appeared; if unsure, re-read it. Never retype from
   memory, shorten, split, or swap in a hand-made stand-in such as
   ` + "`sub.<tld>`" + `. Only an exact, complete placeholder is restored, so
   anything else breaks the command, the edit or the report line.
2. **Treat a placeholder as the real thing.** It is a stable name for
   one real value. A fake IP is still a real target: never discount it
   as test data, and never try to guess or "correct" what is behind it.
3. **Don't comment on placeholders, and never write a partial one.** The
   operator sees real values, so a remark about placeholder ranges or
   shapes means nothing to them. Never write a wildcard or partial
   address (` + "`" + tokenstore.TokenIPNetworkPrefix + "x`" + `, a bare /24): it is not restored. Write complete
   hosts and complete CIDR blocks, exactly as they appear in the source.
4. **An unfamiliar placeholder is not an error.** One in code, a config
   key or a file you re-read is either over-redaction (the proxy can
   misfire on text that only looks like a domain) or working as
   intended. Don't cancel, retry or second-guess a command over it. If a
   result looks wrong, check with Bash or Read: local files are ground
   truth.
5. **Decode on disk, not in your reply.** For base64, hex, URL-encoding
   and the like, write the encoded text to a file, decode it with Bash
   (` + "`base64 -d`" + `, ` + "`xxd -r`" + `), and Read the result. Decoding it yourself
   puts unredacted client data straight into your output.
6. **Never try to recover a real value.** No encoding, splitting or
   other transformation to see behind a placeholder. It is a client
   confidentiality boundary.

Placeholder shapes:
- Domains: ` + "`" + tokenstore.TokenDomainPrefix + "<16 hex>.<real suffix>`" + `, e.g. ` + "`" + tokenstore.TokenDomainPrefix + "1a2b3c4d5e6f7890.com`" + `
- IPv4: ` + "`" + tokenstore.TokenIPNetworkPrefix + "x.x`" + `, ` + "`" + tokenstore.TokenIPNetworkPrefix2 + "x.x`" + `, ` + "`" + tokenstore.TokenIPNetworkOverflowPrefix + "x.x.x`" + ` (real last octet kept)
- IPv6: ` + "`" + tokenstore.TokenIPv6NetworkPrefix + "...`" + `
- Emails: ` + "`" + tokenstore.TokenEmailLocalPrefix + "<hex>@<domain placeholder>`" + `
- Credentials and secrets: ` + "`" + tokenstore.TokenAWSKeyPrefix + "...`, `" + tokenstore.TokenGitHubPrefix + "...`, `" + tokenstore.TokenAWSSecretKeyPrefix + "...`, `" + tokenstore.TokenBearerPrefix + "...`, `" + tokenstore.TokenCustomBlockPrefix + "...`, `" + tokenstore.TokenItsdangerousPrefix + "...`, `" + tokenstore.TokenPasswordHashPrefix + "...`, `" + tokenstore.TokenPasswordPrefix + "...`" + ` and similar
`

func runMemory(args []string) error {
	fs := flag.NewFlagSet("redactproxy memory", flag.ExitOnError)
	setUsage(fs)
	write := fs.String("write", "", "write the snippet to this file instead of printing it (e.g. ./CLAUDE.md); appends if the file already exists")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *write == "" {
		fmt.Print(claudeMemorySnippet)
		fmt.Fprintln(os.Stderr, "\n---")
		fmt.Fprintln(os.Stderr, "Suggestion: add this to the engagement's own project-level ./CLAUDE.md, not the")
		fmt.Fprintln(os.Stderr, "user-level ~/.claude/CLAUDE.md. That one loads for every Claude Code session on")
		fmt.Fprintln(os.Stderr, "this machine, including sessions with no proxy in front of them at all. With the")
		fmt.Fprintln(os.Stderr, "note in place, Claude understands the placeholder values it sees instead of")
		fmt.Fprintln(os.Stderr, "getting confused by them.")
		fmt.Fprintln(os.Stderr, "Run with --write <path> to append it directly, e.g.:")
		fmt.Fprintln(os.Stderr, "  redactproxy memory --write ./CLAUDE.md")
		return nil
	}

	wrote, err := appendClaudeMemoryIfAbsent(*write)
	if err != nil {
		return err
	}
	if wrote {
		fmt.Printf("appended the redactproxy memory snippet to %s\n", *write)
	} else {
		fmt.Printf("%s already has this note, left unchanged\n", *write)
	}
	return nil
}

// claudeMemoryMarker is checked for before appending, so re-running the
// wizard (explicitly supported; see its doc comment) or `memory --write`
// a second time doesn't pile up duplicate copies of the same note.
const claudeMemoryMarker = "Redaction proxy active (redactproxy)"

// appendClaudeMemoryIfAbsent appends claudeMemorySnippet to path unless
// it's already there (by marker, not exact byte match, so a
// hand-tweaked copy still counts as present). wrote is false when the
// marker was already found, not an error, just nothing to do.
func appendClaudeMemoryIfAbsent(path string) (wrote bool, err error) {
	if data, err := os.ReadFile(path); err == nil {
		if strings.Contains(string(data), claudeMemoryMarker) {
			return false, nil
		}
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("read %s: %w", path, err)
	}

	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return false, fmt.Errorf("create directory for %s: %w", path, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	// Checked, not discarded: Close is where a buffered write error (a full
	// disk, an I/O error on a network-mounted home) actually surfaces, so
	// WriteString succeeding is not on its own enough to claim the note
	// reached the file. Reporting wrote=true here would print "appended the
	// redactproxy memory snippet to CLAUDE.md" for a file that never got it,
	// and the operator would have no reason to look again.
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			wrote = false
			err = fmt.Errorf("close %s: %w", path, cerr)
		}
	}()
	if _, err := f.WriteString("\n" + claudeMemorySnippet); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}
