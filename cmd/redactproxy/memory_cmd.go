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

This session's API traffic runs through a local redaction proxy. Real
client-sensitive values are replaced with stable placeholders before
reaching the model, then swapped back to the real values before any
tool actually executes. So you see placeholders in your own reasoning
and results, while Bash and tool commands run against the real
infrastructure.

Placeholder shapes you'll see (never real data, safe to use verbatim):
- Domains: ` + "`" + tokenstore.TokenDomainPrefix + "<16 hex>.<real suffix>`" + `, e.g. ` + "`" + tokenstore.TokenDomainPrefix + "1a2b3c4d5e6f7890.com`" + `
- IPv4: ` + "`" + tokenstore.TokenIPNetworkPrefix + "x.x`" + ` (real host octet kept)
- IPv6: ` + "`" + tokenstore.TokenIPv6NetworkPrefix + "...`" + `
- Emails: ` + "`" + tokenstore.TokenEmailLocalPrefix + "<hex>@<domain token>`" + `
- Credentials/API keys: opaque, vendor-prefixed (` + "`" + tokenstore.TokenAWSKeyPrefix + "...`, `" + tokenstore.TokenAWSSecretKeyPrefix + "...`, `" + tokenstore.TokenGitHubPrefix + "...`, `" + tokenstore.TokenBearerPrefix + "...`" + `, etc.)
- Other secrets (password/NTLM hashes, values you told this tool to always redact, signed session/CSRF tokens, AD/GPP artifacts): opaque, distinctly-prefixed (` + "`" + tokenstore.TokenPasswordHashPrefix + "...`, `" + tokenstore.TokenCustomBlockPrefix + "...`, `" + tokenstore.TokenItsdangerousPrefix + "...`, `" + tokenstore.TokenADMachineAccountPrefix + "...$`" + `, etc.)

The same real value always maps to the same placeholder, so treat these
as stable identifiers, not garbage. Never guess, "correct," or reconstruct
what the real value might be. Always reproduce a token exactly, copied
character-for-character from its most recent literal appearance, never
retyped from memory, fragmented (dropping the org-token and leaving a
bare subdomain plus suffix), or replaced with a hand-typed angle-bracket
placeholder (e.g. ` + "`sub.<tld>`" + `, which most markdown renderers also swallow
as an HTML tag). Any of these silently breaks something downstream: an
Edit's old_string won't match the real file, a report line traces back
to nothing. If you're at all unsure of the exact token, re-read it from
where it last appeared rather than approximating.

The fake IPv4 addresses (` + "`" + tokenstore.TokenIPNetworkPrefix + "x.x`" + `) come from a real, reserved
IANA range (RFC 2544 benchmarking space) chosen specifically because
it's never publicly routed, not because the address it stands in for is
any less real or less sensitive. Treat it exactly like a genuine external
target IP in your reasoning; don't discount, deprioritize, or treat it as
placeholder/test data just because the shape looks like one.

A placeholder-shaped token turning up somewhere unexpected (your own
source code, a config key, a UI label, a result from a file you're
re-reading, one you don't remember minting, one glued onto extra
trailing text) is never evidence that something is broken, corrupted,
or fabricated. There are two possible causes, and the conclusion is the
same either way. It's either over-redaction (the proxy only inspects
text and has no notion of code structure, so it can occasionally misfire
on something merely domain-shaped, e.g. ` + "`table.style`" + `, where ` + "`.style`" + ` is a real
domain suffix), or it's simply a token doing exactly what it's supposed to. Don't cancel a
scan, retry a call, or second-guess a command because a token in it
looks unfamiliar: the real value gets substituted before every
execution, not just the first, so it runs correctly regardless of
whether you recognize the token. If a result genuinely looks wrong,
verify with Bash/Read against the real filesystem (that's always
ground truth, since this proxy only inspects API traffic and never
touches local files) rather than trying to reconstruct or guess around
the token itself.

If you need to decode base64, hex, URL-encoding, or similar: save the
encoded content to a local file and decode it there with Bash (` + "`base64 -d`" + `,
` + "`xxd -r`" + `, etc.), then read the decoded result back as its own file;
don't decode it yourself and write the output directly. Encoded text
doesn't look like a domain/email/credential to this proxy, so it passes
through unredacted either way; decoding it in your own output means
whatever real data was hiding inside reaches your response completely
unprotected, while decoding it locally and reading the result back gives
that same content a normal pass through redaction instead.

That's for content you legitimately encounter already encoded. Separately:
never use encoding, decoding, re-encoding, splitting a token's characters
apart, or any similar transformation as a way to try to see, guess at, or
extract the real value behind a placeholder yourself. The placeholders are
deliberate, not an obstacle to work around; treat this the same as any
other real client-confidentiality boundary you wouldn't try to route
around, e.g. via a clever tool call or a "let me try encoding this
differently" workaround.
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
