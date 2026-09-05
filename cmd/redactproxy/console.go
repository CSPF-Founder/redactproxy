package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// startConsole reads simple admin commands from the proxy's own stdin
// while it keeps running, operating directly on the already-open Store
// and the already-resolved rulesPath: no second process ever needs to
// open tokens.db (sidesteps bbolt's single-writer lock entirely) or
// edit rules.json (which already works live from a separate terminal
// too, since it's a plain polled file, not lock-held; this is purely
// for convenience/parity, not a technical requirement the way the
// token commands are). Either way, editing here means never having to
// stop a live session (which would drop whatever Claude Code request is
// in flight and force it to time out) just to inspect or fix a rule or
// a token mapping.
//
// Only activates when stdin is a real interactive terminal: never for a
// `nohup`/systemd/background launch, both because there's no operator
// there to type into it, and because treating arbitrary redirected or
// piped stdin as commands would be a surprising, unintended side effect
// for a non-interactive launch.
func startConsole(store *tokenstore.Store, engagement, dbPath, rulesPath string) {
	if !stdinIsTerminal() {
		return
	}
	fmt.Fprintln(os.Stderr, `Type here any time without stopping the proxy: "show", "remove <value>", "rules ...", "help".`)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			handleConsoleLine(store, engagement, dbPath, rulesPath, line)
		}
	}()
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func stderrIsTerminal() bool {
	info, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

const (
	ansiRed   = "\x1b[31m"
	ansiReset = "\x1b[0m"
)

// coloredWarnWriter wraps an io.Writer (stderr) and highlights WARN/
// ERROR-level slog lines in red. Plain slog.TextHandler output makes a
// WARN line look exactly like the INFO lines around it at a glance,
// easy to miss the one time it actually matters (e.g. the cwd-leak
// check in warnIfCWDMayLeak, which exists specifically so a human
// notices it). Only ever constructed when stderrIsTerminal() is true
// (see its call site), so this never injects raw ANSI escape codes into
// a redirected log file or piped consumer, the same reasoning
// startConsole already applies to stdin.
//
// slog.TextHandler builds one full formatted line per record and
// issues exactly one Write call for it (a documented stdlib
// implementation detail, not incidental), so checking each Write's
// payload for " level=WARN "/" level=ERROR " correctly identifies
// whole log lines, not arbitrary byte fragments.
type coloredWarnWriter struct {
	w io.Writer
}

func (c coloredWarnWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(" level=WARN ")) || bytes.Contains(p, []byte(" level=ERROR ")) {
		colored := append([]byte(ansiRed), p...)
		colored = append(colored, []byte(ansiReset)...)
		if _, err := c.w.Write(colored); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.w.Write(p)
}

func handleConsoleLine(store *tokenstore.Store, engagement, dbPath, rulesPath, line string) {
	fields := strings.Fields(line)
	switch fields[0] {
	case "show", "tokens":
		if err := printTokens(store, engagement, dbPath); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
	case "remove":
		if len(fields) != 2 {
			fmt.Println(`usage: remove <real-value>`)
			return
		}
		if err := removeToken(store, fields[1], "show"); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
	case "rules":
		handleRulesConsoleLine(engagement, rulesPath, fields[1:])
	case "help":
		fmt.Println(`token commands: show | remove <real-value>
rules commands: rules show | rules enable <category> | rules disable <category>
                | rules block <value> | rules allow <value> | rules remove <value>
  (rules block/allow here don't support --regex/--note; use the standalone
  "redactproxy rules block/allow" command for those)`)
	default:
		fmt.Printf("unknown command %q; type \"help\"\n", fields[0])
	}
}

// handleRulesConsoleLine dispatches the "rules ..." console commands to
// the exact same core functions the standalone `redactproxy rules`
// subcommands use (rules_cmd.go), no separate logic to keep in sync.
// block/allow here are deliberately the simplified form: everything
// after the verb is joined back into one literal value (no --regex/--note
// flag parsing in this quick console syntax); an operator who needs
// those uses the standalone CLI form in a second terminal instead.
func handleRulesConsoleLine(engagement, rulesPath string, args []string) {
	if len(args) == 0 {
		fmt.Println(`usage: rules show | rules enable <category> | rules disable <category> | rules block <value> | rules allow <value> | rules remove <value>`)
		return
	}
	verb, rest := args[0], args[1:]
	var err error
	switch verb {
	case "show":
		err = showRulesCore(engagement, rulesPath)
	case "enable":
		err = requireOneArg(rest, "rules enable <category>", func(v string) error {
			return toggleCategoryCore(rulesPath, v, true)
		})
	case "disable":
		err = requireOneArg(rest, "rules disable <category>", func(v string) error {
			return toggleCategoryCore(rulesPath, v, false)
		})
	case "block":
		err = requireOneArg(rest, "rules block <value>", func(v string) error {
			return addRuleValueCore(rulesPath, ruleAddRequest{Value: v})
		})
	case "allow":
		err = requireOneArg(rest, "rules allow <value>", func(v string) error {
			return addRuleValueCore(rulesPath, ruleAddRequest{Value: v, Allow: true})
		})
	case "remove":
		err = requireOneArg(rest, "rules remove <value>", func(v string) error {
			return removeRuleValueCore(rulesPath, v)
		})
	default:
		fmt.Printf("unknown rules command %q; type \"help\"\n", verb)
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
}

// requireOneArg joins fields back into a single value (so a value with
// spaces, e.g. "Xyz Example Corp", doesn't need console-side quoting rules) and
// calls fn with it, or prints a usage hint if fields is empty.
func requireOneArg(fields []string, usage string, fn func(value string) error) error {
	if len(fields) == 0 {
		fmt.Println("usage:", usage)
		return nil
	}
	return fn(strings.Join(fields, " "))
}
