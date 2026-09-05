// Command redactproxy runs the local HTTP proxy that sits between Claude
// Code and the real Anthropic API, tokenizing real PII out of every
// outbound request and detokenizing it back into every inbound response.
//
// Usage:
//
//	redactproxy --engagement xyz-example-corp
//	ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
//
// Subcommands (see wizard.go / rules_cmd.go / tokens_cmd.go / memory_cmd.go):
//
//	redactproxy wizard --engagement xyz-example-corp
//	redactproxy rules show|validate|enable|disable|block|allow|remove --engagement xyz-example-corp
//	redactproxy tokens show|remove --engagement xyz-example-corp
//	redactproxy memory [--write <path>]
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/CSPF-Founder/redactproxy/internal/debuglog"
	"github.com/CSPF-Founder/redactproxy/internal/proxyserver"
	"github.com/CSPF-Founder/redactproxy/internal/redact"
	"github.com/CSPF-Founder/redactproxy/internal/rules"
	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// rulesReloadInterval is how often the running proxy polls rules.json
// for changes. A config file changes at human-editing/CLI speed, not a
// latency-sensitive hot path, so this stays a simple poll; see
// rules.Watcher's doc comment for why that beats a filesystem-event
// dependency here.
const rulesReloadInterval = 2 * time.Second

// defaultListenAddr is the proxy's default --listen value, shared with
// wizard.go so its own --listen flag default (and the "is this actually
// customized" check in its printed next-steps instructions) can never
// silently drift out of sync with runProxy's own default.
const defaultListenAddr = "127.0.0.1:8787"

// version is stamped in at link time by the release workflow
// (-ldflags "-X main.version=v1.2.3"). It is deliberately left empty for
// an ordinary build rather than defaulting to a hardcoded string: for a
// binary produced by `go install ...@v1.2.3`, which never passes
// ldflags, the module version Go records in the build info is the real
// answer, and a baked-in placeholder would outrank and hide it.
var version string

// versionString reports the release this binary was built from, falling
// back through the three ways that can be known: a linker stamp, then
// Go's own recorded module version ("v1.2.3" for `go install ...@v1.2.3`,
// "(devel)" for a build from a clone), then an honest "unknown".
func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "unknown"
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "redactproxy:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "wizard":
			return runWizard(args[1:])
		case "rules":
			return runRules(args[1:])
		case "tokens":
			return runTokens(args[1:])
		case "memory":
			return runMemory(args[1:])
		case "version", "-version", "--version":
			// Handled here rather than as a runProxy flag so that it
			// answers identically whether it's typed as a subcommand or a
			// flag, and so it never depends on an engagement being
			// resolvable: "which build am I running" has to be answerable
			// from any directory, including in a bug report from someone
			// whose engagement setup is the thing that's broken.
			fmt.Println("redactproxy", versionString())
			return nil
		case "-h", "-help", "--help", "help":
			printTopLevelUsage()
			fmt.Println()
			// Falls through to the proxy's own flag parser so the actual
			// flag list (--debug-level, --listen, --max-concurrent, etc.)
			// still prints below the overview. Go's flag package handles
			// -h itself (prints defaults, os.Exit(0)) rather than this
			// returning before ever showing them, which would leave "-h"
			// showing an overview that told you to run "redactproxy -h"
			// for the flags, the exact command that got you the
			// overview, never the flags themselves.
			return runProxy([]string{"-h"})
		default:
			// A bare word (no leading "-") that isn't one of the known
			// subcommands above is almost always a typo ("rulez" for
			// "rules", "wizrd" for "wizard") rather than an intentional
			// proxy flag; proxy flags all start with "-". Catching this
			// here avoids silently falling through to runProxy with
			// defaults, which in a folder with an existing engagement
			// marker looks like a normal successful start.
			if !strings.HasPrefix(args[0], "-") {
				return fmt.Errorf("unknown subcommand %q (want wizard, rules, tokens, memory, or a proxy flag, which starts with a dash; run 'redactproxy -h' for usage)", args[0])
			}
		}
	}
	return runProxy(args)
}

func printTopLevelUsage() {
	fmt.Println(`redactproxy: local redaction proxy between Claude Code and its upstream API
(Claude/Anthropic by default; z.ai or another provider if configured; see 'redactproxy wizard').

Usage:
  redactproxy [flags]              start the proxy (flags listed below)
  redactproxy wizard [flags]       interactively set up an engagement (customer names/domains,
                                    CLAUDE.md note, .claude/settings.local.json); start here
  redactproxy rules <subcommand>   show|validate|enable|disable|block|allow|remove against a saved rules.json
  redactproxy tokens <subcommand>  show|remove against an engagement's already-minted token store
  redactproxy memory [--write ...] print (or write) the placeholder-value CLAUDE.md note
  redactproxy version              print the build this binary was made from

Run any of the above with -h for its own flags, e.g. 'redactproxy wizard -h'.

Typical first run in a new engagement folder:
  redactproxy wizard --engagement xyz-example-corp
  redactproxy
  claude   (in another shell, or automatically, if the wizard configured .claude/settings.local.json)

You only need to pass --engagement explicitly once per folder. It's remembered
in a local .redactproxy-engagement marker, so later commands run from the same
folder (proxy, wizard, rules) don't have to repeat it.`)
}

// flagDeclLine matches the "  -name" line flag.PrintDefaults writes to
// introduce each flag. Wrapped description lines are indented with four
// spaces and a tab, so this can only ever match a declaration, never
// usage text that happens to begin with a dash.
var flagDeclLine = regexp.MustCompile(`(?m)^  -`)

// setUsage makes fs print its flags as long options ("--name") instead
// of the flag package's own "-name". Parsing is untouched: the flag
// package accepts one or two dashes interchangeably, so this only picks
// which of the two equivalent forms operators are shown, keeping help
// output, error messages, and the README saying the same thing. etcd
// does the same over the same stdlib parser.
//
// The layout is produced by PrintDefaults and then rewritten, rather
// than reimplemented here, so type names, default-value quoting, and
// the rule for omitting zero defaults stay exactly what the flag package
// does, including for flag types this program doesn't use yet.
func setUsage(fs *flag.FlagSet) {
	fs.Usage = func() {
		out := fs.Output()
		var buf bytes.Buffer
		fs.SetOutput(&buf)
		fs.PrintDefaults()
		fs.SetOutput(out)

		// Usage output goes to the same sink flag already writes its own
		// errors to; if that write fails there is nowhere left to report it.
		_, _ = fmt.Fprintf(out, "Usage of %s:\n", fs.Name())
		_, _ = fmt.Fprint(out, flagDeclLine.ReplaceAllString(buf.String(), "  --"))
	}
}

func runProxy(args []string) error {
	fs := flag.NewFlagSet("redactproxy", flag.ExitOnError)
	setUsage(fs)
	var (
		listen         = fs.String("listen", defaultListenAddr, "address to listen on (loopback only, never expose this to the network)")
		engagementFlag = fs.String("engagement", "", "engagement name; each engagement gets its own persistent token store. Remembered per-folder after the first explicit use (see .redactproxy-engagement), so you don't have to repeat it on every run from the same folder.")
		dataDir        = fs.String("data-dir", "", "base directory for engagement data (default: $HOME/.redactproxy)")
		upstream       = fs.String("upstream", "", "the real API base URL to proxy to (default: https://api.anthropic.com, or whatever 'redactproxy wizard' saved for this engagement in upstream.txt under its data dir)")
		maxBodyMB      = fs.Int64("max-body-mb", proxyserver.DefaultMaxBodyBytes>>20, "maximum request/response body size this proxy will buffer, in MiB")
		maxConcurrent  = fs.Int("max-concurrent", proxyserver.DefaultMaxConcurrent, "maximum number of requests actively buffering a body at once")
		disable        = fs.String("disable", "", "comma-separated detector categories/subcategories to disable for this run only, e.g. cloud.aws,network.mac; merged with rules.json's own disabled list, not a replacement for it. For a persisted change, use 'redactproxy rules disable <category>' instead")
		debugLevelStr  = fs.String("debug-level", "off", "debug logging verbosity: off, new (first-seen real values), replacements (every substitution), or full (entire request/response bodies, real and tokenized). Every level above 'off' writes REAL client values to debug.log in plain text. Levels are cumulative: each one includes everything the level before it logs.")
		debugLogMaxMB  = fs.Int64("debug-log-max-mb", debuglog.DefaultMaxLogBytes>>20, "size, in MiB, at which debug.log is gzip-archived as a timestamp-named part (e.g. debug.log.<when>.gz) and a fresh debug.log is started; 'full' level especially can grow large fast, since every logged request body is the whole conversation history so far")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Anything left over here is never a proxy flag or value this command
	// takes (starting the proxy has no positional arguments at all), so
	// it's almost always a subcommand typed in the wrong place: Go's flag
	// package stops parsing flags at the first non-flag argument, so
	// "redactproxy --engagement foo rules show" parses "--engagement foo" as
	// flags and leaves "rules show" as unconsumed positional arguments
	// here rather than ever reaching run()'s own subcommand dispatch.
	// Silently ignoring them (the flag package's own default behavior)
	// would mean that exact typo starts a live, listening proxy instead
	// of running the read-only command the operator actually meant.
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument(s) %v; subcommands must come before flags, e.g. \"redactproxy rules show --engagement foo\", not \"redactproxy --engagement foo rules show\"", fs.Args())
	}

	// Both size flags are validated here, before anything is opened or
	// bound, rather than at their point of use: they're pure input
	// checks, and one of them (--debug-log-max-mb) is otherwise consumed
	// while creating a file.
	if err := checkMiBFlag("--max-body-mb", *maxBodyMB, proxyserver.DefaultMaxBodyBytes>>20); err != nil {
		return err
	}
	if err := checkMiBFlag("--debug-log-max-mb", *debugLogMaxMB, debuglog.DefaultMaxLogBytes>>20); err != nil {
		return err
	}

	engagement, err := resolveEngagement(*engagementFlag)
	if err != nil {
		return err
	}

	logWriter := io.Writer(os.Stderr)
	if stderrIsTerminal() {
		logWriter = coloredWarnWriter{w: os.Stderr}
	}
	logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: slog.LevelInfo}))

	debugLevel, err := debuglog.ParseLevel(*debugLevelStr)
	if err != nil {
		return err
	}

	engagementPath, err := engagementDir(*dataDir, engagement)
	if err != nil {
		return err
	}
	dbPath := filepath.Join(engagementPath, "tokens.db")
	rulesPath := filepath.Join(engagementPath, "rules.json")
	debugLogPath := filepath.Join(engagementPath, "debug.log")
	upstreamPath := filepath.Join(engagementPath, "upstream.txt")

	// --upstream left unset (the common case) falls back to this
	// engagement's own persisted choice (see upstreamPathFor's doc
	// comment) before falling back further to the real Anthropic API.
	// An explicit --upstream always wins outright, matching --disable's
	// same "CLI flag is a this-run-only override" convention.
	if *upstream == "" {
		if persisted, ok, err := readPersistedUpstream(upstreamPath); err != nil {
			return err
		} else if ok {
			*upstream = persisted
		} else {
			*upstream = "https://api.anthropic.com"
		}
	}

	// debug.log contains REAL client values once debug logging is on
	// (see internal/debuglog's doc comment for why that's a deliberate
	// choice, not an oversight): warn loudly, don't silently proceed,
	// if it would end up somewhere a Claude Code session running
	// through this proxy could stumble onto it by just browsing its own
	// working directory.
	if debugLevel != debuglog.Off {
		if cwd, cwdErr := os.Getwd(); cwdErr == nil {
			if rel, relErr := filepath.Rel(cwd, engagementPath); relErr == nil && !strings.HasPrefix(rel, "..") {
				logger.Warn("debug.log will contain real client values, and --data-dir resolves inside the current working directory. If Claude Code runs from here, it may be able to read this file",
					"debug_log", debugLogPath, "cwd", cwd)
			}
		}
	}

	var debugLogger *debuglog.Logger
	if debugLevel != debuglog.Off {
		debugWriter, err := debuglog.NewRotatingWriter(debugLogPath, *debugLogMaxMB<<20)
		if err != nil {
			return fmt.Errorf("open debug log at %s: %w", debugLogPath, err)
		}
		// Logged rather than returned: a debug sink that fails to flush at
		// shutdown means some diagnostics were lost, which is worth telling
		// the operator about but is not a reason to fail a proxy run that
		// otherwise served every request correctly.
		defer func() {
			if err := debugWriter.Close(); err != nil {
				logger.Error("closing debug log failed; the tail of it may be incomplete", "path", debugLogPath, "err", err)
			}
		}()
		debugLogger = debuglog.New(debugLevel, debugWriter)
		logger.Info("debug logging enabled, containing real client values", "level", *debugLevelStr, "path", debugLogPath, "rotate_at_mb", *debugLogMaxMB)
	}

	store, err := tokenstore.Open(dbPath)
	if err != nil {
		if tokenstore.IsLockTimeout(err) {
			return fmt.Errorf("open token store: another redactproxy process is already running for this engagement, and only one process can hold tokens.db open at a time: %w", err)
		}
		return fmt.Errorf("open token store at %s: %w", dbPath, err)
	}
	// Every mapping is committed by its own bbolt transaction as it is
	// minted (see the store's crash-consistency guarantee), so a failure
	// here cannot lose a token that was already handed to the model. It
	// still gets logged: an error releasing tokens.db is the one signal an
	// operator gets that something is wrong with the engagement's storage.
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error("closing the token store failed", "path", dbPath, "err", err)
		}
	}()

	upstreamURL, err := url.Parse(*upstream)
	if err != nil {
		return fmt.Errorf("parse --upstream: %w", err)
	}
	if upstreamURL.Scheme == "" || upstreamURL.Host == "" {
		return fmt.Errorf("--upstream must be an absolute URL, got %q", *upstream)
	}
	// Caught here, at startup, rather than left to surface as a generic
	// "request to provider failed" the first time a real request tries to
	// go out: http.Transport has no support for any other scheme, so a
	// typo'd or copy-pasted-wrong one (ftp://, ws://, a misspelled
	// "htps://") would otherwise start the proxy successfully and only
	// fail once Claude Code actually sends something through it.
	if upstreamURL.Scheme != "http" && upstreamURL.Scheme != "https" {
		return fmt.Errorf("--upstream must use http or https, got scheme %q in %q", upstreamURL.Scheme, *upstream)
	}

	if !isLoopback(*listen) {
		return fmt.Errorf("--listen %q is not a loopback address; refusing to bind; this proxy handles real client PII in transit and must never be reachable from the network", *listen)
	}

	// CLI --disable entries are a one-off addition on top of whatever
	// rules.json already has, not a replacement for it, so a quick
	// "--disable cloud.aws" for this one run doesn't require editing (or
	// clobbering) the persisted file.
	var cliDisabled []string
	if *disable != "" {
		for s := range strings.SplitSeq(*disable, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cliDisabled = append(cliDisabled, s)
			}
		}
	}

	// Load, EnsureAllCategories, and the possible Save all happen under
	// one lock (see rules.WithLock's doc comment); this can race
	// against a concurrently-run `rules` command touching the same
	// file just like any other Load-modify-Save cycle, so it gets the
	// same protection.
	var fileCfg *rules.Config
	if err := rules.WithLock(rulesPath, func() error {
		var loadErr error
		fileCfg, loadErr = rules.Load(rulesPath)
		if loadErr != nil {
			return fmt.Errorf("load %s: %w", rulesPath, loadErr)
		}
		// Make rules.json self-documenting the first time the proxy
		// ever touches an engagement: every known category listed with
		// its enabled state, description, and (for the allowlist.*
		// exceptions) a warning, so someone opening the file by hand
		// can see and edit it directly, not just via `rules`
		// subcommands. Only re-saves when something actually changed
		// (a category added/removed, or its description text updated
		// by a newer binary), so a plain restart with nothing new
		// doesn't rewrite the file every time.
		changed, dropped := fileCfg.EnsureAllCategories(redact.AllCategoryInfo())
		warnDroppedCategories(dropped)
		if changed {
			if err := fileCfg.Save(rulesPath); err != nil {
				return fmt.Errorf("save %s: %w", rulesPath, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	effective := mergeCLIDisabled(fileCfg, cliDisabled)
	compiled, err := effective.Compile()
	if err != nil {
		return fmt.Errorf("%s is invalid: %w. Fix it or remove the bad entry before starting (run `redactproxy rules validate --engagement %s` to check without starting the proxy)", rulesPath, err, engagement)
	}

	engine := redact.New(store, buildDetectors(compiled)...)
	engine.SetAllowPatterns(effectiveAllowPatterns(compiled))
	engine.SetDebugLogger(debugLogger)
	logRulesState(logger, "loaded", nil, compiled)

	if cwd, err := os.Getwd(); err == nil {
		warnIfCWDMayLeak(cwd, compiled, func(matched, pattern string) {
			logger.Warn("current directory matches a block-list pattern and WILL be sent to the upstream API unredacted. Claude Code embeds this path in its own system prompt, which this proxy never scans. Consider running from a differently-named folder",
				"cwd", matched, "matched_pattern", pattern)
		})
	}

	proxy := proxyserver.New(proxyserver.Config{
		Upstream:      upstreamURL,
		Engine:        engine,
		MaxBodyBytes:  *maxBodyMB << 20,
		MaxConcurrent: *maxConcurrent,
		Logger:        logger,
		DebugLogger:   debugLogger,
	})

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           proxy,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}

	// Watch rules.json for changes (edits, `rules block`/`allow`,
	// the wizard, or a hand edit) and apply them live, no restart. CLI
	// --disable entries from this invocation are re-merged on every
	// reload too, so they stay in effect for the life of this process
	// even after a file edit.
	prevCompiled := compiled
	watcher := rules.NewWatcher(rulesPath, rulesReloadInterval, func(cfg *rules.Config) {
		merged := mergeCLIDisabled(cfg, cliDisabled)
		newCompiled, err := merged.Compile()
		if err != nil {
			logger.Error("rules.json reload failed; keeping previous rules active", "path", rulesPath, "error", err)
			return
		}
		engine.SetDetectors(buildDetectors(newCompiled))
		engine.SetAllowPatterns(effectiveAllowPatterns(newCompiled))
		logRulesState(logger, "reloaded", prevCompiled, newCompiled)
		prevCompiled = newCompiled

		// Re-check on every reload too, not just at startup: a newly
		// added block entry (e.g. a customer name added mid-engagement)
		// can start matching a cwd that didn't match before.
		if cwd, err := os.Getwd(); err == nil {
			warnIfCWDMayLeak(cwd, newCompiled, func(matched, pattern string) {
				logger.Warn("current directory matches a block-list pattern and WILL be sent to the upstream API unredacted. Claude Code embeds this path in its own system prompt, which this proxy never scans. Consider running from a differently-named folder",
					"cwd", matched, "matched_pattern", pattern)
			})
		}
	}, func(err error) {
		logger.Error("rules.json watch error", "error", err)
	})
	watcher.Start()
	defer watcher.Stop()

	logger.Info("redactproxy listening",
		"addr", ln.Addr().String(),
		"engagement", engagement,
		"token_store", dbPath,
		"rules_file", rulesPath,
		"upstream", upstreamURL.String(),
	)
	fmt.Fprintln(os.Stderr)
	if projectAlreadyConfiguredFor(ln.Addr().String()) {
		fmt.Fprintln(os.Stderr, "redactproxy is running. This folder's Claude Code is already configured to use it")
		fmt.Fprintln(os.Stderr, "(.claude/settings.local.json), so just run `claude` here, no export needed.")
	} else {
		fmt.Fprintf(os.Stderr, "redactproxy is running. In another shell, run:\n\n  export ANTHROPIC_BASE_URL=http://%s\n  claude\n\n", ln.Addr().String())
		fmt.Fprintln(os.Stderr, "(or run `redactproxy wizard` to set this up automatically next time)")
	}
	if !projectHasClaudeMemoryNote() {
		fmt.Fprintln(os.Stderr, "Tip: the model sees placeholder values (tokens) instead of real ones. Run")
		fmt.Fprintln(os.Stderr, "`redactproxy memory` for a suggested CLAUDE.md note explaining what they mean.")
	}
	if missing := missingSecuritySettings(); len(missing) > 0 {
		fmt.Fprintln(os.Stderr, "WARNING: this folder's Claude Code isn't fully hardened against channels that")
		fmt.Fprintln(os.Stderr, "bypass this proxy entirely. The Artifact tool, for example, publishes straight")
		fmt.Fprintln(os.Stderr, "to claude.ai, completely unredacted. Run `redactproxy wizard` here to fix that")
		fmt.Fprintln(os.Stderr, "automatically, or add the following to .claude/settings.local.json by hand:")
		for _, m := range missing {
			fmt.Fprintf(os.Stderr, "  - %s\n", m)
		}
	}
	fmt.Fprintln(os.Stderr)

	// Started last, after every other startup print: its "type here"
	// hint is meant to read as the final, standing cue that the proxy
	// is ready and listening, not a line buried in the middle of
	// one-time startup noise above it.
	startConsole(store, engagement, dbPath, rulesPath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpServer.Serve(ln)
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}

// engagementFlags is the --engagement/--data-dir pair every `rules` and
// `tokens` subcommand takes, together with the resolution both of them
// then do identically. Factored out because six subcommands each
// repeated the same four steps (declare both flags with the same help
// text, parse, resolve the engagement, build a path under it), and a
// divergence in any one of them, a help string that drifted, a
// resolution step done in the wrong order, is exactly the kind of thing
// that only shows up as a confusing error message months later.
type engagementFlags struct {
	fs         *flag.FlagSet
	engagement *string
	dataDir    *string
}

// newEngagementFlags registers the shared flags on a new FlagSet named
// for the subcommand (e.g. "redactproxy rules show"). Callers add their
// own flags to fs before calling parse.
func newEngagementFlags(command string) *engagementFlags {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	setUsage(fs)
	return &engagementFlags{
		fs:         fs,
		engagement: fs.String("engagement", "", "engagement name (remembered per-folder; see .redactproxy-engagement)"),
		dataDir:    fs.String("data-dir", "", "base directory for engagement data"),
	}
}

// parse parses args and resolves the engagement this command targets.
// fileFor turns the resolved engagement into the file the subcommand
// operates on (rulesPathFor or tokensDBPathFor).
func (e *engagementFlags) parse(args []string, fileFor func(dataDir, engagement string) (string, error)) (engagement, path string, err error) {
	if err := e.fs.Parse(args); err != nil {
		return "", "", err
	}
	engagement, err = resolveEngagement(*e.engagement)
	if err != nil {
		return "", "", err
	}
	path, err = fileFor(*e.dataDir, engagement)
	if err != nil {
		return "", "", err
	}
	return engagement, path, nil
}

// engagementMarkerFile is the per-working-directory marker that lets
// redactproxy/wizard/rules "remember" which engagement this folder is
// for, so --engagement doesn't need to be retyped on every invocation
// once it's been given explicitly once (via wizard or a direct
// --engagement flag), while there is still never a shared default name
// two different clients' folders could silently collide on. See
// resolveEngagement.
const engagementMarkerFile = ".redactproxy-engagement"

// engagementFromMarker reads the per-folder marker without falling back
// to anything else. ok is false when there's simply no marker yet, not
// an error.
func engagementFromMarker() (name string, ok bool, err error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", false, fmt.Errorf("get working directory: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(cwd, engagementMarkerFile))
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read %s: %w", engagementMarkerFile, err)
	}
	name = strings.TrimSpace(string(data))
	return name, name != "", nil
}

// rememberEngagement writes (or updates) the current working directory's
// marker file. Best-effort: a failure here must never block actually
// running, so callers ignore the error.
func rememberEngagement(name string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cwd, engagementMarkerFile), []byte(name+"\n"), 0o600)
}

// resolveEngagement returns the engagement name to use for a
// non-interactive command (the proxy itself, `rules` subcommands):
// explicit if given (remembered to the marker for next time), otherwise
// whatever the marker already says. Returns an error if neither source
// has a name; there is deliberately no fallback default two unrelated
// engagements could collide on by accident. (The wizard, being
// interactive, additionally offers a picker over existing engagements
// when neither of these has an answer; see promptForEngagement in
// wizard.go, rather than just erroring like this does.)
func resolveEngagement(explicit string) (string, error) {
	if explicit != "" {
		// Validate before remembering, not after: engagementDir would
		// catch an invalid name too, but only once something actually
		// tries to build a path from it, and by then rememberEngagement
		// below would already have written the bad value to this
		// folder's marker, breaking every subsequent command run here
		// (with no explicit --engagement) until someone notices and fixes
		// it by hand.
		if !validEngagementNameRe.MatchString(explicit) {
			return "", fmt.Errorf("invalid engagement name %q; must be 1-64 characters, letters/digits/underscore/hyphen only (no \".\", \"/\", or \"\\\")", explicit)
		}
		_ = rememberEngagement(explicit)
		return explicit, nil
	}
	name, ok, err := engagementFromMarker()
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("no --engagement given, and no %s marker found in this folder; pass --engagement explicitly once (it's remembered here for next time), or run `redactproxy wizard` to set one up interactively", engagementMarkerFile)
	}
	return name, nil
}

// listExistingEngagements returns the names of engagements already known
// under dataDir (or its default), sorted. An empty (not missing) slice
// just means none exist yet, not an error.
func listExistingEngagements(dataDir string) ([]string, error) {
	base := dataDir
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("determine home directory: %w", err)
		}
		base = filepath.Join(home, ".redactproxy")
	}
	entries, err := os.ReadDir(filepath.Join(base, "engagements"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	return names, nil
}

// mergeCLIDisabled returns a copy of cfg with cliDisabled entries added
// to its Categories map (Enabled: false), and never mutates cfg itself,
// since cfg may be the value about to be persisted or re-used
// elsewhere. This copy is only ever fed into Compile(), never Save()'d
// or EnsureAllCategories'd, so a bare category name here (e.g.
// "cloud", no subcategory) is stored as-is rather than expanded to
// every "cloud.*" leaf; Compile()/FilterDetectors' existing
// disabled[c.Category] fallback check already treats a bare-category
// key as covering every subcategory under it.
func mergeCLIDisabled(cfg *rules.Config, cliDisabled []string) *rules.Config {
	if len(cliDisabled) == 0 {
		return cfg
	}
	merged := *cfg
	merged.Categories = make(map[string]rules.CategoryState, len(cfg.Categories)+len(cliDisabled))
	for k, v := range cfg.Categories {
		merged.Categories[k] = v
	}
	for _, name := range cliDisabled {
		state := merged.Categories[name]
		state.Enabled = false
		merged.Categories[name] = state
	}
	return &merged
}

// buildDetectors turns a compiled ruleset into the actual detector list
// an Engine should use: every built-in detector not disabled by
// category/subcategory (with the domain detector forced to recognize
// compiled.ForcedDomains even where it would otherwise skip a bare
// mention; see Compiled.ForcedDomains's doc comment), plus a block
// detector for any remaining custom entries.
func buildDetectors(compiled *rules.Compiled) []redact.Detector {
	dets := redact.FilterDetectors(redact.DefaultCategorizedDetectorsWithForcedDomains(compiled.ForcedDomains), compiled.Disabled)
	if len(compiled.Block) > 0 {
		dets = append(dets, redact.NewBlockDetector(compiled.Block))
	}
	return dets
}

// warnIfCWDMayLeak checks whether cwd's full path matches any compiled
// Block pattern, and reports each match via warn if so.
//
// Why this check exists at all: Claude Code embeds its own working
// directory (and a project-memory directory path derived from it,
// e.g. "-home-user-engagements-xyz-example/memory/") into the Messages API
// "system" field on every request. This proxy deliberately never scans
// "system" (see jsonwalk's collectPaths doc comment: real operator
// content lives in "messages", and blanket-scanning Anthropic's own
// tool-description boilerplate there does more harm than good). That
// means an engagement folder named after the client leaks that name to
// the upstream API on every single request, completely bypassing every
// block/allow rule, no matter how thorough the rest of rules.json is;
// the redaction engine never even sees this text. A rule-list match
// alone can't fix this (there's nothing to tokenize a directory path
// against; it isn't part of the request body this proxy edits), so the
// only real fix is not naming the working directory after the client;
// this check exists to make sure that's actually noticed rather than
// silently leaking on every request for the life of the engagement.
func warnIfCWDMayLeak(cwd string, compiled *rules.Compiled, warn func(matched, pattern string)) {
	for _, re := range compiled.Block {
		if re.MatchString(cwd) {
			warn(cwd, re.String())
		}
	}
}

// effectiveAllowPatterns merges rules.json's own Allow entries with the
// built-in curated allowlists (well-known dev platforms, OOB security-
// testing services; see redact.BuiltinAllowPatterns) unless an
// operator disabled one via --disable or `rules disable`
// ("allowlist.wellknown_platforms", "allowlist.security_testing_services",
// or the bare "allowlist" category to drop both). Unlike rules.json's
// own Allow list, the built-in ones aren't persisted anywhere; they're
// re-added fresh on every call, so disabling them takes effect the same
// reload cycle as any other category toggle.
func effectiveAllowPatterns(compiled *rules.Compiled) []*regexp.Regexp {
	return append(append([]*regexp.Regexp(nil), compiled.Allow...), redact.BuiltinAllowPatterns(compiled.Disabled)...)
}

// logRulesState logs the active ruleset at startup (prev == nil) or logs
// what changed on a reload (prev != nil). Added/removed disabled
// categories get their own WARN-level line each, since disabling
// detection is a real reduction in protection an operator should
// actually notice, not something that scrolls by as routine INFO noise.
func logRulesState(logger *slog.Logger, verb string, prev, cur *rules.Compiled) {
	logger.Info("rules "+verb,
		"disabled_count", len(cur.Disabled),
		"block_entries", len(cur.Block),
		"allow_entries", len(cur.Allow),
	)
	prevDisabled := map[string]bool{}
	if prev != nil {
		prevDisabled = prev.Disabled
	}
	for name := range cur.Disabled {
		if !prevDisabled[name] {
			if isAllowlistCategory(name) {
				logger.Warn("allowlist category disabled: values normally exempted by this allowlist will now be redacted instead", "category", name)
			} else {
				logger.Warn("detection category disabled: real values in this category will NOT be redacted", "category", name)
			}
		}
	}
	for name := range prevDisabled {
		if !cur.Disabled[name] {
			logger.Info("detection category re-enabled", "category", name)
		}
	}

	// Same reasoning as above: a rules.json block entry with IsDomain
	// set that doesn't actually resolve to a real domain (a bad manual
	// edit, most likely) falls back to an ordinary literal block value
	// rather than being silently dropped -- see
	// rules.Compiled.UnresolvedDomainEntries's doc comment. There's no
	// interactive CLI to warn through for a hand-edited file, so this
	// is the warning: logged once per newly-appearing case, not on
	// every reload for one that was already there.
	prevUnresolved := map[string]bool{}
	if prev != nil {
		for _, v := range prev.UnresolvedDomainEntries {
			prevUnresolved[v] = true
		}
	}
	for _, v := range cur.UnresolvedDomainEntries {
		if !prevUnresolved[v] {
			logger.Warn(`block entry marked "is_domain" doesn't look like a real domain; treating it as an ordinary literal block value instead`, "value", v)
		}
	}
}

// isAllowlistCategory reports whether name is redact.CategoryAllowlist
// itself or one of its subcategories, the categories where disabling
// makes MORE get redacted rather than less, the opposite of every other
// category, so the disabled-category warning above needs different
// wording for these.
func isAllowlistCategory(name string) bool {
	return name == redact.CategoryAllowlist || strings.HasPrefix(name, redact.CategoryAllowlist+".")
}

// validEngagementNameRe restricts an engagement name to a short,
// unambiguous identifier: letters, digits, underscore, hyphen, 1-64
// chars. Deliberately no ".", "/", or "\": an engagement name (from
// --engagement, a hand-edited .redactproxy-engagement marker, or wizard
// input) containing something like "../../../../tmp/escaped-engagement"
// would otherwise pass straight through filepath.Join in engagementDir
// and land its entire tokens.db/rules.json/debug.log OUTSIDE --data-dir
// entirely, not just a cross-engagement collision, but an
// arbitrary-path write anywhere the process has permission to create
// directories.
var validEngagementNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// engagementDir returns (creating if needed) the per-engagement data
// directory under dataDir (or $HOME/.redactproxy if dataDir is empty).
// The single choke point every other path in this file (rulesPathFor,
// tokensDBPathFor, debugLogPathFor, runProxy's own dbPath) routes
// through, so validating engagement here, before it ever reaches
// filepath.Join, covers all of them at once; see
// validEngagementNameRe's doc comment for what this closes.
func engagementDir(dataDir, engagement string) (string, error) {
	if !validEngagementNameRe.MatchString(engagement) {
		return "", fmt.Errorf("invalid engagement name %q; must be 1-64 characters, letters/digits/underscore/hyphen only (no \".\", \"/\", or \"\\\")", engagement)
	}
	base := dataDir
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("determine home directory: %w", err)
		}
		base = filepath.Join(home, ".redactproxy")
	}
	dir := filepath.Join(base, "engagements", engagement)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create engagement directory: %w", err)
	}
	return dir, nil
}

// rulesPathFor returns the rules.json path for an engagement, creating
// its directory if needed. Shared by the wizard and rules subcommands.
func rulesPathFor(dataDir, engagement string) (string, error) {
	dir, err := engagementDir(dataDir, engagement)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rules.json"), nil
}

// tokensDBPathFor returns the tokens.db path for an engagement, creating
// its directory if needed. Shared by runProxy and the tokens subcommand:
// bbolt allows only one process to hold this file open at a time, so
// `redactproxy tokens show/remove` cannot run concurrently with a
// running proxy for the same engagement (fails fast with bbolt's own
// timeout error, same as running two proxies on one engagement does).
func tokensDBPathFor(dataDir, engagement string) (string, error) {
	dir, err := engagementDir(dataDir, engagement)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tokens.db"), nil
}

// debugLogPathFor returns where this engagement's debug log lives, in the same
// directory as tokens.db/rules.json, deliberately: that directory
// defaults to $HOME/.redactproxy, outside any project working directory,
// and unlike those two files this one contains REAL client values when
// debug logging is enabled (see internal/debuglog's package doc comment
// for why), so it needs the same "not inside a Claude Code session's
// reach" placement, not the working folder the wizard configures
// .claude/settings.local.json for.
func debugLogPathFor(dataDir, engagement string) (string, error) {
	dir, err := engagementDir(dataDir, engagement)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "debug.log"), nil
}

// upstreamPathFor returns where this engagement's persisted --upstream
// override (if any) lives. Same directory as tokens.db/rules.json: an
// engagement talking to a non-Anthropic provider (e.g. z.ai) needs that
// choice to survive across `redactproxy` invocations without retyping
// --upstream every time, the same way rules.json survives without
// retyping --disable. Holds only the bare base URL, never a credential;
// the provider's own auth token is a Claude Code concern (it's sent as
// a header Claude Code already attaches, forwarded through untouched by
// buildUpstreamRequest) and lives in .claude/settings.local.json's env
// block instead, written by offerProjectSettings.
func upstreamPathFor(dataDir, engagement string) (string, error) {
	dir, err := engagementDir(dataDir, engagement)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "upstream.txt"), nil
}

// readPersistedUpstream returns this engagement's saved --upstream value.
// ok is false when there's no file yet (a plain Anthropic engagement
// that never needed one), not an error, mirroring
// engagementFromMarker's convention.
func readPersistedUpstream(path string) (value string, ok bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read %s: %w", path, err)
	}
	value = strings.TrimSpace(string(data))
	return value, value != "", nil
}

// writePersistedUpstream saves (or clears) an engagement's --upstream
// override. An empty value removes the file rather than writing an empty
// one, so switching an engagement back to real Claude leaves no stale
// file for a future reader to wonder about.
func writePersistedUpstream(path, value string) error {
	if value == "" {
		err := os.Remove(path)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	}
	return os.WriteFile(path, []byte(value+"\n"), 0o600)
}

// projectAlreadyConfiguredFor reports whether the current working
// directory's .claude/settings.local.json already points
// ANTHROPIC_BASE_URL at addr, i.e. whether `redactproxy wizard` (or a
// hand edit) already did the job the "export ANTHROPIC_BASE_URL=..."
// startup instructions exist for, so those instructions don't tell the
// operator to do something that's already done. Any error (no such
// file, invalid JSON, no env block) is treated as "not configured":
// the safe default here is to SHOW the manual instructions, never hide
// them based on a guess.
func projectAlreadyConfiguredFor(addr string) bool {
	cwd, err := os.Getwd()
	if err != nil {
		return false
	}
	data, err := os.ReadFile(filepath.Join(cwd, ".claude", "settings.local.json"))
	if err != nil {
		return false
	}
	var settings struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return false
	}
	return settings.Env["ANTHROPIC_BASE_URL"] == "http://"+addr
}

// projectHasClaudeMemoryNote reports whether the current working
// directory's CLAUDE.md already has the redaction-placeholder note (see
// claudeMemoryMarker in memory_cmd.go), so the startup banner's "run
// redactproxy memory" tip doesn't tell the operator to do something
// already done, the same reasoning as projectAlreadyConfiguredFor above.
func projectHasClaudeMemoryNote() bool {
	cwd, err := os.Getwd()
	if err != nil {
		return false
	}
	data, err := os.ReadFile(filepath.Join(cwd, "CLAUDE.md"))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), claudeMemoryMarker)
}

// claudeSecuritySettings is the subset of .claude/settings.local.json
// missingSecuritySettings inspects. A named type, not an anonymous
// struct literal declared inline: the "couldn't parse it, treat every
// setting as absent" path needs to re-zero the value, and with an
// anonymous type that meant repeating the whole field list verbatim, two
// copies to keep identical for the compiler's sake alone.
type claudeSecuritySettings struct {
	DisableRemoteControl  bool              `json:"disableRemoteControl"`
	SkipWebFetchPreflight bool              `json:"skipWebFetchPreflight"`
	Env                   map[string]string `json:"env"`
	Permissions           struct {
		Deny []string `json:"deny"`
	} `json:"permissions"`
}

// missingSecuritySettings reports which of the wizard's protective
// settings (see offerProjectSettings in wizard.go) are absent from the
// current working directory's .claude/settings.local.json, as short,
// user-facing descriptions ready to print; empty if everything's
// already there. Checks against toolDenyRules/quietEnvDefaults directly
// (the same vars offerProjectSettings writes from) rather than a second
// hand-maintained list, so this can't silently fall out of sync with
// what the wizard actually adds.
//
// Someone who never ran `redactproxy wizard` (piped ANTHROPIC_BASE_URL
// in by hand, or copied an older settings file from before one of these
// settings existed) would have no way to know any of these gaps exist
// otherwise; this is what runProxy's startup warning uses to tell them
// exactly what's missing, not just that something might be.
func missingSecuritySettings() []string {
	var missing []string

	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}

	var settings claudeSecuritySettings
	if data, readErr := os.ReadFile(filepath.Join(cwd, ".claude", "settings.local.json")); readErr == nil {
		if json.Unmarshal(data, &settings) != nil {
			// Invalid JSON: same "can't tell, so warn" stance as a
			// missing file. Reset to the zero value rather than
			// returning early (Unmarshal can leave a partially-filled
			// struct behind on error), so every setting below reads as
			// missing and the warning still fires.
			settings = claudeSecuritySettings{}
		}
	}

	for _, rule := range toolDenyRules {
		if !slices.Contains(settings.Permissions.Deny, rule) {
			missing = append(missing, fmt.Sprintf("permissions.deny: %q", rule))
		}
	}
	if !settings.DisableRemoteControl {
		missing = append(missing, "disableRemoteControl: true")
	}
	if !settings.SkipWebFetchPreflight {
		missing = append(missing, "skipWebFetchPreflight: true")
	}
	for k, v := range quietEnvDefaults {
		if settings.Env[k] != v {
			missing = append(missing, fmt.Sprintf("env.%s = %q", k, v))
		}
	}
	slices.Sort(missing)
	return missing
}

// maxMiBFlagValue is the largest value any "size in MiB" flag can take
// before converting it to bytes (value << 20) overflows int64.
const maxMiBFlagValue = math.MaxInt64 >> 20

// checkMiBFlag validates one "size in MiB" flag. Both ends of the range
// matter for the same reason, and it isn't obvious from either: every
// consumer of these values treats a non-positive byte count as "use the
// built-in default" rather than as an error (see proxyserver.New and
// debuglog.NewRotatingWriter), so a negative input, or one large enough
// that shifting it left by 20 wraps past int64 and comes out negative,
// silently starts the proxy with a limit nobody asked for and no sign
// anything was wrong. Rejecting both here is what turns a typo into a
// message instead of a surprise.
func checkMiBFlag(name string, mib, defaultMiB int64) error {
	if mib < 0 {
		return fmt.Errorf("%s must not be negative, got %d; a non-positive value would silently fall back to the %d MiB default instead of erroring", name, mib, defaultMiB)
	}
	if mib > maxMiBFlagValue {
		return fmt.Errorf("%s is too large, got %d (maximum %d); converting it to bytes overflows, which would silently fall back to the %d MiB default instead of erroring", name, mib, int64(maxMiBFlagValue), defaultMiB)
	}
	return nil
}

// isLoopback reports whether addr (a --listen value) resolves to a
// loopback-only bind. An empty host (the shorthand ":8787", one of the
// most common ways to write a listen address in Go/Unix tooling) is
// deliberately NOT treated as loopback: net.Listen("tcp", ":8787")
// genuinely binds every interface: it reports its own address as
// [::]:8787 and accepts connections from other hosts on the network,
// not "unspecified, assume safe." Getting this one check
// wrong defeats the entire point of it; this proxy handles real client
// PII in transit and its own --listen flag help text promises "loopback
// only, never expose this to the network."
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
