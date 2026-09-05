package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/CSPF-Founder/redactproxy/internal/redact"
	"github.com/CSPF-Founder/redactproxy/internal/rules"
)

// runWizard interactively collects customer name variations and domains
// for one engagement and adds them to its block list with high
// confidence: i.e. always redact these, not just "if a built-in
// detector happens to recognize the shape". It's a normal separate
// invocation of this binary (`redactproxy wizard --engagement X`), not
// something that needs a running proxy to talk to: it just edits the
// same rules.json a running proxy for that engagement is already
// watching, so entries apply within a couple of seconds with no
// restart, the SAME mechanism as `rules block`/`allow`, just with an
// interactive prompt instead of one CLI argument at a time. Can
// be re-run at any time, including against an engagement whose proxy is
// already running mid-session.
func runWizard(args []string) error {
	fs := flag.NewFlagSet("redactproxy wizard", flag.ExitOnError)
	setUsage(fs)
	engagementFlag := fs.String("engagement", "", "engagement name (interactive picker if omitted and this folder has no marker yet; see .redactproxy-engagement)")
	dataDir := fs.String("data-dir", "", "base directory for engagement data (default: $HOME/.redactproxy)")
	listen := fs.String("listen", defaultListenAddr, "address the proxy will listen on; used to pre-configure this folder's Claude Code settings, must match what you actually start redactproxy with")
	if err := fs.Parse(args); err != nil {
		return err
	}

	reader := bufio.NewReader(os.Stdin)

	engagement := *engagementFlag
	if engagement == "" {
		name, ok, err := engagementFromMarker()
		if err != nil {
			return err
		}
		if ok {
			engagement = name
		}
	}
	if engagement == "" {
		picked, err := promptForEngagement(reader, *dataDir)
		if err != nil {
			return err
		}
		engagement = picked
	}
	if err := rememberEngagement(engagement); err != nil {
		fmt.Printf("(couldn't remember this folder's engagement for next time: %v)\n", err)
	}

	path, err := rulesPathFor(*dataDir, engagement)
	if err != nil {
		return err
	}

	fmt.Printf("redactproxy setup wizard, engagement %q\n", engagement)
	fmt.Println("Entries you add here are redacted with high confidence: exact")
	fmt.Println("string matches, applied in addition to the built-in detectors.")
	fmt.Println("If redactproxy is already running for this engagement, these apply")
	fmt.Println("automatically within a couple of seconds, no restart needed.")
	fmt.Println()

	dateStr := time.Now().Format("2006-01-02")

	// Collected into a plain local slice, not a *rules.Config loaded up
	// front: prompting here is interactive and can block on user input
	// for as long as someone takes to type, and holding the rules.json
	// lock (see rules.WithLock) for that whole span would block every
	// other command touching this engagement (the proxy's own startup,
	// any `rules` command run from another terminal) for as long as the
	// wizard sits open. Loading fresh and merging these in happens only
	// at the very end, under the lock, for just as long as the actual
	// Save takes.
	//
	// Distinct notes per prompt (not one shared "wizard <date>") so a
	// saved entry's origin and kind stay legible in `rules show` months
	// later without having to guess whether e.g. "XyzExampleCorp" was typed as
	// a customer-name variant or a domain.
	var newEntries []rules.Entry
	total := 0
	total += promptLines(reader, "Customer name variations (legal name, abbreviations, product names, one per line, blank line to move on):", "wizard "+dateStr+", customer name", false, &newEntries)
	// isDomain: true on this prompt specifically. An entry collected here
	// is, by the question asked, a domain, and that's the whole trigger
	// for the structure-preserving domain-token treatment (see
	// rules.Compiled.ForcedDomains): the same token everywhere the domain
	// appears, bare or as a subdomain, in an email, or in a URL, rather
	// than an opaque block token matching only the literal text typed
	// here. Without it, the wizard, the documented main entry point,
	// silently produced weaker entries than `rules block --domain` does
	// for the identical value. Safe to set unconditionally: Compile()
	// falls back to an ordinary literal block entry for anything that
	// doesn't actually resolve to a domain (see Entry.IsDomain), so a
	// non-domain typed at this prompt is still blocked, just without the
	// upgrade.
	total += promptLines(reader, "Domains (one per line, blank line to finish):", "wizard "+dateStr+", domain", true, &newEntries)

	if err := rules.WithLock(path, func() error {
		cfg, err := rules.Load(path)
		if err != nil {
			return err
		}
		// Make rules.json self-documenting from the very first file an
		// engagement gets, not just the first time the proxy happens to
		// run: every known category listed with its enabled state and
		// description (see EnsureAllCategories's doc comment).
		categoriesChanged, dropped := cfg.EnsureAllCategories(redact.AllCategoryInfo())
		warnDroppedCategories(dropped)
		cfg.Block = append(cfg.Block, newEntries...)

		if total == 0 && !categoriesChanged {
			fmt.Println("no entries added, nothing to save")
			return nil
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("internal error building entries: %w", err)
		}
		if err := cfg.Save(path); err != nil {
			return err
		}
		if total > 0 {
			fmt.Printf("\nsaved %d new entr%s to %s\n", total, plural(total), path)
		} else {
			fmt.Printf("\nsaved %s (categories initialized, no block entries added)\n", path)
		}
		return nil
	}); err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	fmt.Println()
	fmt.Println("IMPORTANT: this proxy redacts request/response CONTENT, but Claude Code")
	fmt.Println("also embeds its own working-directory path (and a project-memory")
	fmt.Println("directory name derived from it) into a part of every request this proxy")
	fmt.Println("deliberately never scans. If this folder, or any parent of it, is named")
	fmt.Println("after the client, that name reaches the upstream API unredacted on every")
	fmt.Println("request, regardless of what's in rules.json. If you can, use a generic")
	fmt.Println("folder name instead: an engagement code rather than the client's real name.")
	if reloadedCfg, err := rules.Load(path); err == nil {
		if compiled, err := reloadedCfg.Compile(); err == nil {
			warnIfCWDMayLeak(cwd, compiled, func(matched, pattern string) {
				fmt.Printf("\nWARNING: this folder's path (%q) currently matches your own block-list pattern %q:\nit WILL be sent unredacted on every request from here. Consider a different folder name.\n", matched, pattern)
			})
		}
	}

	debugLogPath, err := debugLogPathFor(*dataDir, engagement)
	if err != nil {
		return err
	}
	upstreamPath, err := upstreamPathFor(*dataDir, engagement)
	if err != nil {
		return err
	}

	fmt.Println()
	currentUpstream, _, err := readPersistedUpstream(upstreamPath)
	if err != nil {
		return err
	}
	newUpstream, providerEnv, removeEnvKeys := offerProviderSettings(reader, currentUpstream)
	if newUpstream != currentUpstream {
		if err := writePersistedUpstream(upstreamPath, newUpstream); err != nil {
			return fmt.Errorf("save %s: %w", upstreamPath, err)
		}
	}
	if newUpstream == "" {
		fmt.Println("this engagement will proxy to real Claude (api.anthropic.com)")
	} else {
		fmt.Printf("this engagement will proxy to %s (saved, no need to pass --upstream again from here)\n", newUpstream)
	}

	fmt.Println()
	wroteMemory := offerClaudeMemory(reader, cwd)
	fmt.Println()
	wroteSettings := offerProjectSettings(reader, cwd, *listen, debugLogPath, providerEnv, removeEnvKeys)

	fmt.Println()
	fmt.Println("Next: start the proxy:")
	if *listen == defaultListenAddr {
		fmt.Println("  redactproxy")
	} else {
		fmt.Printf("  redactproxy --listen %s\n", *listen)
	}
	fmt.Printf("(this folder now remembers engagement %s, so there's no need to pass --engagement again from here)\n", engagement)
	if wroteSettings {
		fmt.Println("Then just run `claude` in this folder; it'll pick up the proxy automatically.")
	} else {
		fmt.Println("Then, in another shell, in this folder:")
		fmt.Printf("  export ANTHROPIC_BASE_URL=http://%s\n  claude\n", *listen)
	}
	if !wroteMemory {
		fmt.Println("(run `redactproxy memory --write ./CLAUDE.md` any time to add the placeholder-value explanation)")
	}
	return nil
}

// offerClaudeMemory asks whether to append the placeholder-value
// explanation (see memory_cmd.go) to this folder's CLAUDE.md, reusing
// the exact same snippet `redactproxy memory` prints, one source of
// truth for the text regardless of which entry point wrote it.
func offerClaudeMemory(r *bufio.Reader, cwd string) bool {
	path := filepath.Join(cwd, "CLAUDE.md")
	if !promptYesNo(r, fmt.Sprintf("Add a CLAUDE.md note explaining the redaction placeholders (%s)?", path), true) {
		return false
	}
	wrote, err := appendClaudeMemoryIfAbsent(path)
	if err != nil {
		fmt.Printf("could not write %s: %v\n", path, err)
		return false
	}
	if wrote {
		fmt.Printf("appended the redaction-placeholder note to %s\n", path)
	} else {
		fmt.Printf("%s already has this note, left unchanged\n", path)
	}
	return true
}

// providerPrimaryModelEnvKeys select the model used for the main
// session: what a fresh launch, /model opus, and /model sonnet all
// resolve to. Per docs.claude.com's env-vars and model-config
// references (checked 2026-08-14):
//   - ANTHROPIC_MODEL is the main session model, and takes precedence
//     over a user's own saved "model" setting; without it, an operator
//     who already has a personal default model pinned globally (from an
//     unrelated Claude project) would have that literal Anthropic model
//     ID sent to this provider on first launch, before any alias
//     resolution below ever applies.
//   - ANTHROPIC_DEFAULT_OPUS_MODEL/_SONNET_MODEL resolve the opus/sonnet
//     aliases (what /model opus and /model sonnet select) to this
//     provider's model.
var providerPrimaryModelEnvKeys = []string{
	"ANTHROPIC_MODEL",
	"ANTHROPIC_DEFAULT_OPUS_MODEL",
	"ANTHROPIC_DEFAULT_SONNET_MODEL",
}

// providerBackgroundModelEnvKeys select the model used for lighter-
// weight work: the haiku alias and Claude Code's own internal
// background calls (see docs.claude.com/docs/en/costs#background-token-usage).
// A provider with tiered models (a cheaper/faster one alongside its main
// model, plausible for the same reason Anthropic offers Haiku alongside
// Opus/Sonnet) may want a different value here than
// providerPrimaryModelEnvKeys; a single-model provider just gets the
// same value in both, which is what offerProviderSettings defaults to
// unless the operator asks to split them.
//
// CLAUDE_CODE_SUBAGENT_MODEL is deliberately NOT here, even though it's
// model-selection-shaped: per docs.claude.com/docs/en/env-vars, it
// "overrides... the subagent definition's model frontmatter"; a
// specific subagent that was deliberately written to need the stronger
// primary-tier model would get silently downgraded to whatever's picked
// here for background work, which is a real behavior change, not a
// values-config choice. z.ai's own published configuration (see
// zaiUpstreamURL's doc comment) doesn't set it either; subagents
// resolve through the ordinary opus/sonnet/haiku alias mechanism
// instead, using whichever tier each subagent's own frontmatter already
// asks for. Still cleaned up on a switch to Claude (see
// providerCleanupOnlyEnvKeys) in case a legacy config set it.
var providerBackgroundModelEnvKeys = []string{
	"ANTHROPIC_DEFAULT_HAIKU_MODEL",
}

// providerModelEnvKeys is every model-selection key offerProviderSettings
// might set, primary and background combined.
var providerModelEnvKeys = append(append([]string{}, providerPrimaryModelEnvKeys...), providerBackgroundModelEnvKeys...)

// providerCleanupOnlyEnvKeys are env keys offerProviderSettings never
// writes going forward, but that a legacy config might still have set;
// see each one's own reasoning: ANTHROPIC_SMALL_FAST_MODEL (deprecated,
// see providerBackgroundModelEnvKeys' sibling reasoning for
// ANTHROPIC_DEFAULT_HAIKU_MODEL replacing it) and CLAUDE_CODE_SUBAGENT_MODEL
// (see providerBackgroundModelEnvKeys' doc comment for why it's no
// longer set). Included in providerEnvKeys purely so a switch back to
// Claude clears them out too, not because anything here still writes
// them.
var providerCleanupOnlyEnvKeys = []string{"ANTHROPIC_SMALL_FAST_MODEL", "CLAUDE_CODE_SUBAGENT_MODEL"}

// providerEnvKeys are every env key a non-Claude provider setup might
// have set: the full set cleared from .claude/settings.local.json when
// an engagement switches back to real Claude, so no stale auth token or
// foreign model name lingers once it no longer applies.
//
// ANTHROPIC_API_KEY is included for a different reason than the rest:
// this wizard doesn't ask for it as provider input, but a non-Claude
// provider choice always blanks it (see offerProviderSettings) as a
// safety measure, so it also needs clearing back out on a later switch
// to Claude; see that same doc comment for why leaving it blank
// matters in the first place.
//
// CLAUDE_CODE_AUTO_COMPACT_WINDOW and API_TIMEOUT_MS are z.ai-specific
// performance tuning (see offerZAISettings) that real Claude has no use
// for, so they're cleared the same way as everything else here.
var providerEnvKeys = append(append([]string{
	"ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY",
	"CLAUDE_CODE_AUTO_COMPACT_WINDOW", "API_TIMEOUT_MS",
}, providerModelEnvKeys...), providerCleanupOnlyEnvKeys...)

// zaiUpstreamURL and the values below are z.ai's own published
// Anthropic-Messages-API-compatible configuration
// (docs.z.ai/devpack/tool/claude#manual-configuration, checked
// 2026-08-14): Bearer auth (ANTHROPIC_AUTH_TOKEN, not ANTHROPIC_API_KEY),
// a DIFFERENT model for the opus/sonnet tier than for haiku/background
// work (not the same value everywhere), and two performance-tuning vars
// a longer request timeout (API_TIMEOUT_MS, milliseconds) and a wider
// auto-compact window (CLAUDE_CODE_AUTO_COMPACT_WINDOW, tokens) than
// Claude Code's own defaults, presumably tuned for z.ai's own latency
// and context-handling characteristics. Hardcoded rather than asked
// for, since z.ai is a known, verified integration, not an arbitrary
// provider; see offerManualProviderSettings for the escape hatch when
// that's not true.
const (
	zaiUpstreamURL       = "https://api.z.ai/api/anthropic"
	zaiPrimaryModel      = "glm-5.2"
	zaiBackgroundModel   = "glm-4.7"
	zaiAPITimeoutMS      = "3000000"
	zaiAutoCompactWindow = "1000000"
)

// manualUpstreamPlaceholder and manualValuePlaceholder mark every value
// offerManualProviderSettings writes as deliberately non-functional;
// see its doc comment.
const (
	manualUpstreamPlaceholder = "https://REPLACE-ME.example.com"
	manualValuePlaceholder    = "REPLACE-ME"
)

// offerProviderSettings asks which API this engagement talks to, and
// returns what runWizard needs to act on that choice: the upstream base
// URL to persist (empty means real Anthropic, no override needed; see
// upstreamPathFor's doc comment), env vars to set, and env vars to
// remove. Re-running the wizard and answering differently switches an
// engagement between choices at any time. EVERY choice (including
// Claude's) returns providerEnvKeys as its removal baseline, not just
// the newly-chosen provider's own set, so a switch in any direction
// (Claude to z.ai, z.ai to Manual, Manual back to Claude, or re-running
// the same choice with a prompt left blank) can never leave a previous
// provider's auth token, model name, or perf-tuning var behind; only
// what the newly-picked choice actually sets survives, everything else
// in that shared key space is cleared.
//
// Only three choices are offered, deliberately, rather than free-text
// prompts for an arbitrary provider's URL/token/model: Claude needs no
// input at all (see below), z.ai is a known, verified integration that
// can be fully auto-configured from one API key, and anything else gets
// a placeholder skeleton rather than a guess (see
// offerManualProviderSettings): a wrong guess at, say, which auth
// header a random provider expects fails silently rather than loudly,
// which is worse than making the operator fill it in themselves. Adding
// another fully-supported provider like z.ai is a code change (a new
// offerXSettings function following the same shape), not a config
// option; see CONTRIBUTING.md's "Adding a provider" section.
//
// No API key is ever asked for real Claude; Claude Code's own existing
// authentication (subscription login, or however it's already
// configured) reaches the upstream exactly as before, since
// buildUpstreamRequest forwards every client header untouched; this
// proxy only ever needs to know an upstream URL for that path, never a
// credential.
//
// That same "every header forwarded untouched" behavior is also why
// picking z.ai or manual unconditionally blanks ANTHROPIC_API_KEY in
// this folder's env block: if the operator (or their shell, or their
// user-level Claude settings) already has a REAL Anthropic API key set
// there, and this folder's ANTHROPIC_BASE_URL now points elsewhere, that
// real Anthropic credential would otherwise go out as a header on every
// request this proxy forwards, straight to that third party, not
// Anthropic. Blanking it here overrides any inherited value for this
// project specifically (matches a real, independently-published z.ai
// manual-configuration reference, which blanks the same key for the
// same reason). Cleared back out, not left blank, on a later switch
// to Claude, so Claude's own normal key resolution isn't permanently
// short-circuited by a leftover empty override.
func offerProviderSettings(r *bufio.Reader, currentUpstream string) (upstream string, envSet map[string]string, envRemove []string) {
	fmt.Println("Which API is this engagement talking to?")
	fmt.Println("  1) Claude (Anthropic): uses whatever Claude Code is already signed in with")
	fmt.Println("  2) z.ai")
	fmt.Println("  3) Manual / another provider: writes a placeholder skeleton to edit by hand")
	switch currentUpstream {
	case "":
		fmt.Println("  (currently: Claude)")
	case zaiUpstreamURL:
		fmt.Println("  (currently: z.ai)")
	default:
		fmt.Printf("  (currently: %s)\n", currentUpstream)
	}
	fmt.Print("> ")
	line, _ := r.ReadString('\n')
	choice := strings.TrimSpace(line)
	switch choice {
	case "2":
		return offerZAISettings(r)
	case "3":
		return offerManualProviderSettings(r)
	case "", "1":
		return "", nil, providerEnvKeys
	default:
		fmt.Printf("  %q not recognized as 1, 2, or 3; using Claude\n", choice)
		return "", nil, providerEnvKeys
	}
}

// offerZAISettings prompts only for the one piece of information z.ai
// itself can't be known in advance (the operator's own API key) and
// hardcodes everything else from z.ai's own published configuration
// (see zaiUpstreamURL's doc comment).
func offerZAISettings(r *bufio.Reader) (upstream string, envSet map[string]string, envRemove []string) {
	fmt.Printf("z.ai: using its published endpoint (%s) and model names\n", zaiUpstreamURL)
	fmt.Printf("(%s for the main model, %s for background/haiku tasks).\n", zaiPrimaryModel, zaiBackgroundModel)
	fmt.Println("Enter your z.ai API key (blank to keep this folder's existing one, if any):")
	fmt.Print("> ")
	token, _ := r.ReadString('\n')
	token = strings.TrimSpace(token)

	env := map[string]string{
		"ANTHROPIC_API_KEY":               "", // see offerProviderSettings' doc comment
		"API_TIMEOUT_MS":                  zaiAPITimeoutMS,
		"CLAUDE_CODE_AUTO_COMPACT_WINDOW": zaiAutoCompactWindow,
	}
	// providerEnvKeys as the removal baseline (not nil) so switching FROM
	// a different provider can't leave that provider's auth token, model
	// names, or performance vars behind; see offerProjectSettings' merge
	// logic: it deletes anything in this list not also present in env, so
	// a key both here and in env above is a no-op, and anything only here
	// gets cleanly cleared.
	remove := providerEnvKeys
	if token != "" {
		env["ANTHROPIC_AUTH_TOKEN"] = token
	} else {
		// ANTHROPIC_AUTH_TOKEN must stay out of the removal set here:
		// including it unconditionally would mean simply re-running the
		// wizard against an already-working z.ai setup (to add a
		// rules.json entry, say) and pressing Enter at this prompt (a
		// completely reasonable "I don't need to retype something
		// already set up" assumption) silently deletes the real,
		// working key with no warning. The engagement's next
		// `redactproxy` start would then send zero auth to z.ai and
		// every request would fail, for a reason nothing in the
		// wizard's own output points to. Leaving ANTHROPIC_AUTH_TOKEN
		// out of the removal set here means "no key typed" means "don't
		// touch it," not "clear it."
		fmt.Println("(no key entered, leaving this folder's existing ANTHROPIC_AUTH_TOKEN, if any, untouched)")
		remove = removeStrings(providerEnvKeys, "ANTHROPIC_AUTH_TOKEN")
	}
	for _, k := range providerPrimaryModelEnvKeys {
		env[k] = zaiPrimaryModel
	}
	for _, k := range providerBackgroundModelEnvKeys {
		env[k] = zaiBackgroundModel
	}
	return zaiUpstreamURL, env, remove
}

// removeStrings returns a new slice with every element of exclude
// removed from all, preserving all's order. Used to carve one or two
// keys out of the shared providerEnvKeys removal baseline when a
// provider-settings function has a specific reason not to touch them
// this run; see offerZAISettings and offerManualInteractiveSettings for
// why "no new credential typed" means "leave the existing one alone,"
// not "clear it."
func removeStrings(all []string, exclude ...string) []string {
	skip := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		skip[e] = true
	}
	out := make([]string, 0, len(all))
	for _, s := range all {
		if !skip[s] {
			out = append(out, s)
		}
	}
	return out
}

// offerManualProviderSettings is the escape hatch for any provider
// without hardcoded support like z.ai's: either walk through the same
// URL/token/model questions z.ai's config answers automatically (see
// offerManualInteractiveSettings), or, when that's more than the
// operator wants to deal with right now (the details aren't at hand,
// or they'd rather just see the shape of what's needed), fall back to a
// placeholder skeleton to fill in by hand later (see
// offerManualSkeletonSettings).
func offerManualProviderSettings(r *bufio.Reader) (upstream string, envSet map[string]string, envRemove []string) {
	fmt.Println("Manual / another provider.")
	if promptYesNo(r, "Enter its base URL, API key, and model names now?", true) {
		return offerManualInteractiveSettings(r)
	}
	return offerManualSkeletonSettings()
}

// offerManualInteractiveSettings collects the same three things z.ai's
// hardcoded config supplies automatically (base URL, auth
// token/header, model name(s)) but from the operator directly rather
// than a known-good published source, so unlike offerZAISettings it
// validates the URL and asks rather than assumes which auth header
// applies (see offerProviderSettings' doc comment for why guessing that
// would be worse than asking).
func offerManualInteractiveSettings(r *bufio.Reader) (upstream string, envSet map[string]string, envRemove []string) {
	fmt.Println("Enter the provider's Anthropic-Messages-API-compatible base URL:")
	var providerURL string
	for {
		fmt.Print("> ")
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			if errors.Is(err, io.EOF) {
				fmt.Println("no URL given; writing a placeholder skeleton instead")
				return offerManualSkeletonSettings()
			}
			fmt.Println("URL can't be empty")
			continue
		}
		parsed, parseErr := url.Parse(line)
		if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
			fmt.Println("that doesn't look like an absolute URL (needs a scheme and host); try again")
			continue
		}
		providerURL = line
		break
	}

	fmt.Println("Enter this provider's API key/auth token (blank to keep this folder's existing one, if any):")
	fmt.Print("> ")
	token, _ := r.ReadString('\n')
	token = strings.TrimSpace(token)

	// See offerProviderSettings' doc comment for why the auth-header
	// choice is asked rather than assumed, and why the unused one is
	// blanked rather than left alone, but only when a NEW token was
	// actually typed. Same constraint as offerZAISettings: with no new
	// credential given, there's no way to know here which of
	// ANTHROPIC_AUTH_TOKEN/ANTHROPIC_API_KEY the operator's already-
	// working config actually uses (that was itself a choice made on
	// an earlier run), so touching either risks deleting the real one:
	// "no token typed" means "don't touch auth at all this run," not
	// "guess, or default to blanking."
	env := map[string]string{}
	preserveAuthKeys := false
	if token != "" {
		if promptYesNo(r, "Send it as an 'Authorization: Bearer' header (ANTHROPIC_AUTH_TOKEN)? That's the common choice, and what z.ai uses. Answer No to send it as an 'X-Api-Key' header (ANTHROPIC_API_KEY) instead. Check your provider's own docs if you're not sure.", true) {
			env["ANTHROPIC_AUTH_TOKEN"] = token
			env["ANTHROPIC_API_KEY"] = ""
		} else {
			env["ANTHROPIC_API_KEY"] = token
			env["ANTHROPIC_AUTH_TOKEN"] = ""
		}
	} else {
		fmt.Println("(no token entered, leaving this folder's existing auth settings untouched)")
		preserveAuthKeys = true
	}

	fmt.Println("Model name this provider expects, used for the main session model")
	fmt.Println("(blank to leave unset):")
	fmt.Print("> ")
	model, _ := r.ReadString('\n')
	model = strings.TrimSpace(model)
	if model != "" {
		for _, k := range providerPrimaryModelEnvKeys {
			env[k] = model
		}
		backgroundModel := model
		if promptYesNo(r, "Use a different model (a cheaper or faster one) for background tasks, the haiku alias and subagents?", false) {
			fmt.Println("Model name for background tasks/subagents (blank to reuse the one above):")
			fmt.Print("> ")
			line, _ := r.ReadString('\n')
			if line = strings.TrimSpace(line); line != "" {
				backgroundModel = line
			}
		}
		for _, k := range providerBackgroundModelEnvKeys {
			env[k] = backgroundModel
		}
	}

	// See offerZAISettings' matching comment: providerEnvKeys as the
	// removal baseline so switching from a different provider (or
	// leaving the model prompt blank here) can't leave that provider's
	// values behind. ANTHROPIC_AUTH_TOKEN/ANTHROPIC_API_KEY are excluded
	// from that baseline specifically when no new token was typed (see
	// preserveAuthKeys above); same reasoning as offerZAISettings.
	remove := providerEnvKeys
	if preserveAuthKeys {
		remove = removeStrings(providerEnvKeys, "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY")
	}
	return providerURL, env, remove
}

// offerManualSkeletonSettings writes a deliberately non-functional
// skeleton: a placeholder upstream URL that can't resolve to anything
// (so starting redactproxy without editing it first fails loudly,
// rather than silently talking to whatever REPLACE-ME.example.com
// happens to be) and placeholder env values marking exactly what needs
// filling in.
func offerManualSkeletonSettings() (upstream string, envSet map[string]string, envRemove []string) {
	fmt.Println("Writing a placeholder skeleton, not a working configuration. Before")
	fmt.Println("starting redactproxy, edit:")
	fmt.Println("  - this engagement's upstream.txt (currently a placeholder URL)")
	fmt.Println("  - .claude/settings.local.json's env block (currently REPLACE-ME")
	fmt.Println("    values) to match your provider's own base URL, auth token, and")
	fmt.Println("    model names")
	fmt.Println("See the README's \"Multiple engagements, multiple providers\" section.")
	env := map[string]string{
		"ANTHROPIC_API_KEY":    "", // see offerProviderSettings' doc comment
		"ANTHROPIC_AUTH_TOKEN": manualValuePlaceholder,
	}
	for _, k := range providerPrimaryModelEnvKeys {
		env[k] = manualValuePlaceholder
	}
	for _, k := range providerBackgroundModelEnvKeys {
		env[k] = manualValuePlaceholder
	}
	// See offerZAISettings' matching comment.
	return manualUpstreamPlaceholder, env, providerEnvKeys
}

// toolDenyRules are Claude Code tools that bypass ANTHROPIC_BASE_URL
// entirely; see offerProjectSettings' doc comment for why each one is
// here. Package-level (not local to offerProjectSettings) so
// missingSecuritySettings in main.go checks against the exact same list
// the wizard writes, rather than a second copy that could drift.
var toolDenyRules = []string{"Artifact", "RemoteTrigger", "PushNotification", "SendUserFile"}

// quietEnvDefaults are env vars that disable telemetry, error reporting,
// and feedback/survey prompts; see offerProjectSettings' doc comment.
// Package-level for the same reason as toolDenyRules.
//
// CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC is a consolidated flag
// covering the same ground as the four named vars below (per
// code.claude.com/docs/en/data-usage, checked 2026-08-14) plus whatever
// else Anthropic later decides counts as "nonessential"; set alongside
// them, not instead of them, since an older Claude Code version might
// not recognize it yet and the four named vars are the more
// long-established mechanism. Setting an env var a given version
// doesn't recognize is a no-op, not an error, so there's no cost to
// carrying both.
var quietEnvDefaults = map[string]string{
	"DISABLE_TELEMETRY":                        "1",
	"DISABLE_ERROR_REPORTING":                  "1",
	"DISABLE_FEEDBACK_COMMAND":                 "1",
	"CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY":      "1",
	"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
}

// offerProjectSettings asks whether to configure this folder's Claude
// Code to point at the proxy automatically, via
// .claude/settings.local.json's "env" block, settings.local.json
// specifically (not settings.json), since that file is meant for
// personal, machine-local settings that should never end up committed
// or shared, which is exactly what a local proxy port is. If the file
// already exists, this merges in just what's needed rather than
// overwriting the file, and shows the user what's there and what will
// change before writing anything.
//
// Also adds a permissions.deny rule blocking Read access to
// debugLogPath (Claude Code's Read deny also covers Bash's
// cat/head/tail/sed on that path, verified against current docs, not
// assumed). debugLogPath may contain real client values once debug
// logging is enabled (see internal/debuglog), and the point of this rule
// is specifically to stop a session from ever loading it into context by
// accident (burning tokens on a file nobody asked it to read), not to
// prevent an operator who explicitly wants a session to analyze it from
// doing so (they can loosen this rule, or just point a separate
// unrestricted session at the file).
//
// Also sets disableRemoteControl: true. Claude Code already disables
// Remote Control on its own whenever ANTHROPIC_BASE_URL points somewhere
// other than api.anthropic.com (confirmed against current docs), so this
// is redundant with the ANTHROPIC_BASE_URL setting above under today's
// behavior; it's set explicitly anyway as a second, independent
// guarantee that doesn't depend on that auto-detection continuing to
// exist in a future Claude Code version, since Remote Control's session
// transcript (real messages, responses, tool activity) is exactly the
// kind of real client data this whole tool exists to keep off a channel
// that bypasses it.
//
// Also adds permissions.deny rules for tools that publish or transmit
// content to a hosted claude.ai URL (or similar) via a separate service
// call rather than a Messages API request; none of these go through
// ANTHROPIC_BASE_URL, so nothing this proxy does can redact content on
// those paths. A bare tool name in a deny rule removes the tool from
// Claude's context entirely rather than just prompting for permission
// each time, which matters here: a permission prompt can still be
// approved by habit, but a tool that was never offered can't leak
// anything. Artifact is a confirmed real leak path (a report published
// to claude.ai/code/artifacts, entirely unredacted); RemoteTrigger,
// PushNotification, and SendUserFile share the same Remote-Control-
// adjacent architecture and are denied for the same reason, as cheap
// defense-in-depth alongside disableRemoteControl below even though
// they're already unreachable once Remote Control itself is off.
//
// Also sets skipWebFetchPreflight: true; WebFetch's safety-check step
// sends the target hostname to Anthropic directly as a preflight, before
// the actual fetch; a domain being reconned is exactly the kind of
// value this tool exists to keep off any channel that bypasses
// tokenization, the same category of leak as Artifact's. Per
// code.claude.com/docs/en/data-usage (checked 2026-08-14), this check
// "runs regardless of which model provider you use", so for an
// engagement pointed at a non-Anthropic provider (see
// offerProviderSettings), leaving this off means the target hostname
// still goes straight to Anthropic, a third company not even otherwise
// in the loop for that engagement.
//
// Also sets a handful of env vars that disable telemetry, error
// reporting, and feedback/survey prompts. None of these are as high-
// stakes as the above (usage metrics and crash reports, not report
// content), but disabling them costs nothing functionally and is
// consistent with keeping every optional channel to Anthropic's
// non-proxied infrastructure closed by default for an engagement. Per
// the same data-usage doc, a plain custom ANTHROPIC_BASE_URL override
// (what every engagement here uses, Claude or otherwise) doesn't get
// these auto-disabled the way recognized integrations like Bedrock or
// Vertex do; it's treated as "Claude API" with telemetry/error-
// reporting/feedback defaulting ON, so this block is doing real
// suppression, not just redundant caution.
//
// providerEnv and removeEnvKeys carry the outcome of the wizard's
// separate "which provider?" prompt (see offerProviderSettings) into
// this same settings write: providerEnv's keys are set (a non-Claude
// provider's auth token and model overrides), removeEnvKeys' are
// deleted if present (cleanup when an engagement switches back to real
// Claude). Both are folded into the same preview/merge/write flow as
// everything else here, so a "this will:" listing always reflects
// every change this run makes in one place, not two separate prompts
// each rewriting the file. Every other setting in this function
// (routing, the deny rules, disableRemoteControl, skipWebFetchPreflight,
// the quiet env defaults) applies unconditionally regardless of which
// provider was chosen; they're Claude Code CLIENT behaviors (what the
// harness itself calls out to, independent of which API answers
// /v1/messages), not something the choice of upstream should gate.
func offerProjectSettings(r *bufio.Reader, cwd, listen, debugLogPath string, providerEnv map[string]string, removeEnvKeys []string) bool {
	settingsPath := filepath.Join(cwd, ".claude", "settings.local.json")
	if !promptYesNo(r, fmt.Sprintf("Configure Claude Code in this folder to use the proxy automatically (writes %s)?", settingsPath), true) {
		return false
	}

	settings := map[string]any{}
	existed := false
	if data, err := os.ReadFile(settingsPath); err == nil {
		existed = true
		if err := json.Unmarshal(data, &settings); err != nil {
			fmt.Printf("%s already exists but isn't valid JSON (%v); leaving it untouched\n", settingsPath, err)
			return false
		}
	} else if !os.IsNotExist(err) {
		fmt.Printf("could not read %s: %v\n", settingsPath, err)
		return false
	}

	env, _ := settings["env"].(map[string]any)
	if env == nil {
		env = map[string]any{}
	}
	prevURL, hadURL := env["ANTHROPIC_BASE_URL"]
	newURL := "http://" + listen

	debugLogDenyRule := fmt.Sprintf("Read(/%s)", filepath.ToSlash(debugLogPath)) // leading "/" doubled with the absolute path's own "/"; see permissions docs on // for filesystem-root-anchored paths
	denyList, _ := settings["permissions"].(map[string]any)
	if denyList == nil {
		denyList = map[string]any{}
	}
	existingDeny, _ := denyList["deny"].([]any)
	hasDenyRule := func(rule string) bool {
		for _, d := range existingDeny {
			if d == rule {
				return true
			}
		}
		return false
	}
	hasDebugLogDenyRule := hasDenyRule(debugLogDenyRule)
	missingToolDenyRules := make([]string, 0, len(toolDenyRules))
	for _, rule := range toolDenyRules {
		if !hasDenyRule(rule) {
			missingToolDenyRules = append(missingToolDenyRules, rule)
		}
	}

	prevRemoteControl, hadRemoteControl := settings["disableRemoteControl"]
	remoteControlAlready := hadRemoteControl && prevRemoteControl == true
	prevSkipPreflight, hadSkipPreflight := settings["skipWebFetchPreflight"]
	skipPreflightAlready := hadSkipPreflight && prevSkipPreflight == true

	var providerEnvChanges []string
	for k, v := range providerEnv {
		if prev, ok := env[k]; !ok || prev != v {
			providerEnvChanges = append(providerEnvChanges, k)
		}
	}
	slices.Sort(providerEnvChanges)
	var providerEnvRemovals []string
	for _, k := range removeEnvKeys {
		if _, ok := providerEnv[k]; ok {
			continue // being set fresh below, not actually removed
		}
		if _, ok := env[k]; ok {
			providerEnvRemovals = append(providerEnvRemovals, k)
		}
	}
	slices.Sort(providerEnvRemovals)

	if existed {
		fmt.Printf("\n%s already exists. Current content:\n", settingsPath)
		if pretty, err := json.MarshalIndent(settings, "  ", "  "); err == nil {
			fmt.Printf("  %s\n", pretty)
		}
		var changes []string
		if hadURL && prevURL != newURL {
			changes = append(changes, fmt.Sprintf("CHANGE env.ANTHROPIC_BASE_URL from %v to %q", prevURL, newURL))
		} else if !hadURL {
			changes = append(changes, fmt.Sprintf("ADD env.ANTHROPIC_BASE_URL = %q", newURL))
		}
		if !hasDebugLogDenyRule {
			changes = append(changes, fmt.Sprintf("ADD a permissions.deny rule keeping Claude Code from reading the debug log (%s)", debugLogDenyRule))
		}
		if len(missingToolDenyRules) > 0 {
			changes = append(changes, fmt.Sprintf("ADD permissions.deny rules blocking %s (bypass this proxy entirely, see this command's own doc comment)", strings.Join(missingToolDenyRules, ", ")))
		}
		if !remoteControlAlready {
			changes = append(changes, "SET disableRemoteControl = true")
		}
		if !skipPreflightAlready {
			changes = append(changes, "SET skipWebFetchPreflight = true (its safety check sends the target hostname to Anthropic directly, unredacted)")
		}
		var missingEnvDefaults []string
		for k := range quietEnvDefaults {
			if _, ok := env[k]; !ok {
				missingEnvDefaults = append(missingEnvDefaults, k)
			}
		}
		if len(missingEnvDefaults) > 0 {
			slices.Sort(missingEnvDefaults)
			changes = append(changes, fmt.Sprintf("ADD env vars disabling telemetry/error-reporting/feedback prompts (%s)", strings.Join(missingEnvDefaults, ", ")))
		}
		if len(providerEnvChanges) > 0 {
			changes = append(changes, fmt.Sprintf("SET provider env vars (%s), values not shown here", strings.Join(providerEnvChanges, ", ")))
		}
		if len(providerEnvRemovals) > 0 {
			changes = append(changes, fmt.Sprintf("REMOVE env vars from a previous non-Claude provider setup (%s)", strings.Join(providerEnvRemovals, ", ")))
		}
		if len(changes) == 0 {
			fmt.Println("Already configured as needed; no change needed.")
		} else {
			fmt.Println("This will:")
			for _, c := range changes {
				fmt.Println("  -", c)
			}
			fmt.Println("Everything else in the file stays as-is.")
		}
		if !promptYesNo(r, "Proceed?", true) {
			fmt.Println("left untouched")
			return false
		}
	}

	if !hasDebugLogDenyRule {
		existingDeny = append(existingDeny, debugLogDenyRule)
	}
	for _, rule := range missingToolDenyRules {
		existingDeny = append(existingDeny, rule)
	}
	denyList["deny"] = existingDeny
	settings["permissions"] = denyList
	settings["disableRemoteControl"] = true
	settings["skipWebFetchPreflight"] = true
	for k, v := range quietEnvDefaults {
		if _, ok := env[k]; !ok {
			env[k] = v
		}
	}
	for _, k := range removeEnvKeys {
		if _, ok := providerEnv[k]; !ok {
			delete(env, k)
		}
	}
	for k, v := range providerEnv {
		env[k] = v
	}
	env["ANTHROPIC_BASE_URL"] = newURL
	settings["env"] = env

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		fmt.Printf("could not create %s: %v\n", filepath.Dir(settingsPath), err)
		return false
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		fmt.Printf("could not encode %s: %v\n", settingsPath, err)
		return false
	}
	data = append(data, '\n')
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		fmt.Printf("could not write %s: %v\n", settingsPath, err)
		return false
	}
	fmt.Printf("wrote %s\n", settingsPath)
	return true
}

// promptForEngagement interactively resolves the engagement name when
// neither --engagement nor this folder's marker had an answer: lists
// engagements already known under dataDir so the operator can pick one
// by number (working the same client from a second folder, say), or
// just type a brand-new name. If a TYPED name happens to already match
// an existing one (not picked by number, which is already an
// unambiguous, deliberate choice), this confirms before proceeding:
// unlike picking by number, a coincidental name collision while typing
// is exactly the kind of accidental-reuse case with no other signal to
// catch it, e.g. two different clients ending up sharing one token
// store because someone forgot they'd already used "xyz-example-corp" before.
func promptForEngagement(r *bufio.Reader, dataDir string) (string, error) {
	existing, err := listExistingEngagements(dataDir)
	if err != nil {
		return "", err
	}
	if len(existing) > 0 {
		fmt.Println("Existing engagements:")
		for i, name := range existing {
			fmt.Printf("  %d) %s\n", i+1, name)
		}
		fmt.Println("Enter a number to use one of these, or type a new engagement name:")
	} else {
		fmt.Println("No existing engagements found. Enter a name for this one:")
	}
	for {
		fmt.Print("> ")
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			if errors.Is(err, io.EOF) {
				return "", fmt.Errorf("no engagement name given")
			}
			fmt.Println("engagement name can't be empty")
			continue
		}
		if n, convErr := strconv.Atoi(line); convErr == nil {
			if n >= 1 && n <= len(existing) {
				return existing[n-1], nil
			}
			fmt.Printf("no engagement #%d in the list above\n", n)
			continue
		}
		if slices.Contains(existing, line) && !promptYesNo(r, fmt.Sprintf("%q already exists as an engagement. Reuse it, sharing its rules and tokens with whatever else uses that name?", line), false) {
			fmt.Println("enter a different name, or a number from the list above")
			continue
		}
		if !validEngagementNameRe.MatchString(line) {
			fmt.Printf("%q isn't a valid engagement name; 1-64 characters, letters/digits/underscore/hyphen only (no \".\", \"/\", or \"\\\")\n", line)
			continue
		}
		return line, nil
	}
}

// promptYesNo asks a yes/no question, defaulting to defaultYes on a bare
// Enter or EOF. Anything else that isn't a recognized y/yes/n/no is
// treated as no (the same safe-by-default direction as before, never
// silently opt in to the write this question is gating) but says so
// explicitly, rather than moving straight to the next question with no
// indication the input wasn't understood.
func promptYesNo(r *bufio.Reader, question string, defaultYes bool) bool {
	hint := "[Y/n]"
	if !defaultYes {
		hint = "[y/N]"
	}
	fmt.Printf("%s %s ", question, hint)
	line, err := r.ReadString('\n')
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)
	if lower == "" || errors.Is(err, io.EOF) {
		return defaultYes
	}
	if lower == "y" || lower == "yes" {
		return true
	}
	if lower != "n" && lower != "no" {
		fmt.Printf("  %q not recognized as yes or no; treating as no\n", trimmed)
	}
	return false
}

// promptLines reads lines from r until a blank line or EOF, appending
// each non-empty one to *entries as a literal (non-regex) block entry
// with the given note. isDomain marks every entry from this prompt as a
// domain (see Entry.IsDomain and runWizard's own call sites).
func promptLines(r *bufio.Reader, prompt, note string, isDomain bool, entries *[]rules.Entry) int {
	fmt.Println(prompt)
	n := 0
	for {
		fmt.Print("> ")
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			*entries = append(*entries, rules.Entry{Value: line, Note: note, IsDomain: isDomain})
			n++
		}
		if line == "" || errors.Is(err, io.EOF) {
			break
		}
	}
	fmt.Println()
	return n
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
