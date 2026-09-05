package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/CSPF-Founder/redactproxy/internal/redact"
	"github.com/CSPF-Founder/redactproxy/internal/rules"
)

// warnDroppedCategories prints a one-line stderr notice for every
// category key EnsureAllCategories dropped from rules.json. A dropped
// key is either a genuinely-retired category (silent-by-design in the
// common case) or a hand-edited case typo on an otherwise-live category:
// the two are indistinguishable here, and a silently-reverted typo on
// a file whose entire premise is "safe to hand-edit" is exactly the
// trap worth flagging. Called from every path that actually persists
// the reconciled result; read-only callers may still call it since it's
// just a stderr note, not a write.
func warnDroppedCategories(dropped []string) {
	for _, key := range dropped {
		fmt.Fprintf(os.Stderr, "note: rules.json had a category %q this build doesn't recognize, so it was dropped. If it was meant to match an existing category, check for a typo (case matters) and run the command again. Otherwise this is expected, and the category was retired in a newer build. See `redactproxy rules show` for the current list.\n", key)
	}
}

// runRules implements `redactproxy rules <subcommand>`. Two clearly
// separate target kinds, kept as separate commands rather than one
// "smart" unified verb that guesses which you mean from the argument:
// enable/disable operate on a named CATEGORY (built-in detectors, and
// the built-in allowlist exceptions; see redact.CategoryAllowlist);
// block/allow/remove operate on a literal VALUE or regex an operator
// adds by hand. Auto-detecting which one an argument is (e.g. "is 'pan'
// a category name or a literal string?") was considered and rejected.
// That ambiguity is exactly the trap matchesKnownCategoryName's note
// guards against: an operator running `block pan` meaning to exempt the
// india_pii.pan detector would otherwise get a literal, dangerously
// over-broad "pan" substring block instead, with nothing flagging the
// mismatch.
func runRules(args []string) error {
	if len(args) == 0 {
		printRulesUsage()
		return nil
	}
	switch args[0] {
	case "show":
		return rulesShow(args[1:])
	case "validate":
		return rulesValidate(args[1:])
	case "enable":
		return rulesToggleCategory(args[1:], true)
	case "disable":
		return rulesToggleCategory(args[1:], false)
	case "block":
		return rulesAdd(args[1:], false)
	case "allow":
		return rulesAdd(args[1:], true)
	case "remove":
		return rulesRemove(args[1:])
	case "-h", "-help", "--help", "help":
		printRulesUsage()
		return nil
	default:
		if strings.HasPrefix(args[0], "-") {
			return fmt.Errorf("no rules subcommand given (got the flag %q first); the subcommand (show, validate, enable, disable, block, allow, or remove) must come immediately after \"rules\", before any flags, e.g. \"redactproxy rules show --engagement foo\"", args[0])
		}
		return fmt.Errorf("unknown rules subcommand %q (want show, validate, enable, disable, block, allow, or remove; run `redactproxy rules` with no arguments for details)", args[0])
	}
}

func printRulesUsage() {
	fmt.Println(`redactproxy rules: inspect or edit a saved rules.json. Changes reach an
already-running proxy for the same engagement within a couple of seconds, with
no restart needed, since rules.json isn't lock-held the way tokens.db is. The
same commands also work typed directly into a running proxy's own console.

There are two kinds of thing you can name here. They're always separate
commands, never guessed from the argument, since guessing wrong would
silently do the wrong thing:

  A CATEGORY: a built-in detector ("cloud.aws") or built-in exception
  ("allowlist.wellknown_platforms"); see the list ` + "`rules show`" + ` prints.
    redactproxy rules enable  [--engagement NAME] [--data-dir DIR] <category>
    redactproxy rules disable [--engagement NAME] [--data-dir DIR] <category>

  A VALUE: a literal string or (--regex) pattern you add by hand.
    redactproxy rules block  [--engagement NAME] [--data-dir DIR] [--regex] [--note "..."] <value>
      always redact this: matches ANY text CONTAINING it (case-insensitive
      substring), so "XyzExampleCorp" also catches "XyzExampleCorporation".
    redactproxy rules allow  [--engagement NAME] [--data-dir DIR] [--regex] [--note "..."] <value>
      never redact this: matches ONLY this EXACT value (case-insensitive),
      deliberately narrower than block since this reduces protection.
    redactproxy rules remove [--engagement NAME] [--data-dir DIR] <value>
      removes the value from block and/or allow, whichever it's in.

Also: ` + "`rules validate`" + ` (checks rules.json without starting the proxy).

An Allow entry always overrides a Block entry for the same value, with no
exception, so ` + "`block`" + `/` + "`allow`" + ` refuse to add a value already covered by the
OTHER list (it would silently have no effect), and ` + "`rules show`" + ` flags any
existing pair like that.

--engagement only needs to be given explicitly once per folder (or via
'redactproxy wizard'); it's then remembered in .redactproxy-engagement.

Examples:
  redactproxy rules disable india_pii.pan
  redactproxy rules block "XyzExampleCorp"
  redactproxy rules block --regex --note "customer VPN range" '10\.42\.\d+\.\d+'
  redactproxy rules allow "mylab.internal"
  redactproxy rules remove "XyzExampleCorp"`)
}

func rulesShow(args []string) error {
	engagement, path, err := newEngagementFlags("redactproxy rules show").parse(args, rulesPathFor)
	if err != nil {
		return err
	}
	return showRulesCore(engagement, path)
}

// showRulesCore is rulesShow's actual work, taking an already-resolved
// engagement/path so it can also be called from the running proxy's
// own console (console.go), which already has both in scope; same
// split as tokens_cmd.go's printTokens/removeToken. Deliberately
// read-only: it runs EnsureAllCategories in memory so what's printed is
// always complete even against a stale/hand-trimmed file, but never
// writes that back to disk, since a "show" command silently rewriting the
// file would be a surprising side effect for something that reads as
// pure inspection.
func showRulesCore(engagement, path string) error {
	cfg, err := rules.Load(path)
	if err != nil {
		return err
	}
	_, dropped := cfg.EnsureAllCategories(redact.AllCategoryInfo())
	warnDroppedCategories(dropped)

	fmt.Printf("rules for engagement %q\n%s\n\n", engagement, path)

	printCategories(cfg.Categories)
	fmt.Println()
	printEntries("Block", cfg.Block, cfg.Allow, true)
	fmt.Println()
	printEntries("Allow", cfg.Allow, cfg.Block, false)
	return nil
}

// printCategories prints every category's current state, description,
// and (where present) warning, a single unified listing, since
// rules.Config.Categories (after EnsureAllCategories) is itself the
// complete source of truth for what's available and what's currently
// on/off.
func printCategories(categories map[string]rules.CategoryState) {
	fmt.Println("Categories:")
	names := make([]string, 0, len(categories))
	for name := range categories {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		state := categories[name]
		mark := "✓ enabled "
		if !state.Enabled {
			mark = "✗ disabled"
		}
		fmt.Printf("  [%s] %-40s %s\n", mark, name, state.Description)
		if state.Warning != "" {
			fmt.Printf("             ⚠ %s\n", state.Warning)
		}
	}
}

// printEntries prints one list's entries. When entries is the Block
// list, flags any entry shadowed by a same-value Allow entry. An
// Allow entry always overrides a Block entry for the same value with
// no exception (see internal/redact's Engine.filterAllowed), so a
// shadowed Block entry currently does nothing at all. This is
// deliberately one-directional: an Allow entry is NEVER shadowed by a
// same-value Block entry (Allow always wins, so it always has its
// intended effect); canShadowedByOpposite is false when printing the
// Allow list for exactly that reason, not a symmetric check. Makes an
// already-stale contradictory pair visible in `rules show` without
// already knowing to look for it.
func printEntries(label string, entries, opposite []rules.Entry, canBeShadowedByOpposite bool) {
	if len(entries) == 0 {
		fmt.Printf("%s: (none)\n", label)
		return
	}
	fmt.Printf("%s:\n", label)
	for _, e := range entries {
		kind := "string"
		if e.Regex {
			kind = "regex"
		}
		line := fmt.Sprintf("  - [%s] %q", kind, e.Value)
		if e.Note != "" {
			line += fmt.Sprintf("  (%s)", e.Note)
		}
		if canBeShadowedByOpposite {
			if _, shadowed := rules.FindEntry(opposite, e.Value); shadowed {
				line += "  ⚠ has NO effect: an Allow entry for the same value always overrides Block"
			}
		}
		fmt.Println(line)
	}
}

func rulesValidate(args []string) error {
	_, path, err := newEngagementFlags("redactproxy rules validate").parse(args, rulesPathFor)
	if err != nil {
		return err
	}
	cfg, err := rules.Load(path)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("INVALID: %w", err)
	}

	known := map[string]bool{}
	for _, info := range redact.AllCategoryInfo() {
		known[info.Name()] = true
	}
	unknown := 0
	for name := range cfg.Categories {
		if !known[name] {
			fmt.Printf("WARNING: %q is not a known category or category.subcategory; it will be removed the next time this file is written\n", name)
			unknown++
		}
	}

	disabledCount := 0
	for _, state := range cfg.Categories {
		if !state.Enabled {
			disabledCount++
		}
	}
	fmt.Printf("OK: %s is valid: %d categor%s (%d disabled), %d block entries, %d allow entries", path, len(cfg.Categories), plural(len(cfg.Categories)), disabledCount, len(cfg.Block), len(cfg.Allow))
	if unknown > 0 {
		fmt.Printf(" (%d unknown category name(s), see warnings above)", unknown)
	}
	fmt.Println()
	return nil
}

// rulesToggleCategory implements `rules enable`/`rules disable`.
func rulesToggleCategory(args []string, enable bool) error {
	verb := "disable"
	if enable {
		verb = "enable"
	}
	ef := newEngagementFlags("redactproxy rules " + verb)
	_, path, err := ef.parse(args, rulesPathFor)
	if err != nil {
		return err
	}
	if ef.fs.NArg() != 1 {
		return fmt.Errorf("usage: redactproxy rules %s <category> (run `redactproxy rules show` for the list of category names); flags must come before the value, e.g. \"rules %s --engagement foo cloud.aws\", not \"rules %s cloud.aws --engagement foo\"", verb, verb, verb)
	}
	return toggleCategoryCore(path, ef.fs.Arg(0), enable)
}

// toggleCategoryCore is rulesToggleCategory's actual work, taking an
// already-resolved path so the console can call it too; see
// showRulesCore's doc comment for why this split exists.
//
// category can be an exact leaf ("cloud.aws", checked first) or a bare
// prefix ("cloud", matched against every "cloud.*" leaf). Toggling a
// bare category affects every subcategory under it in one call, same
// UX this always had, just expanding across the dense Categories map
// instead of appending/removing one sparse string.
func toggleCategoryCore(path, category string, enable bool) error {
	verb := "disable"
	if enable {
		verb = "enable"
	}

	// Whole Load-inspect-modify-Save cycle under one lock; see
	// rules.WithLock's doc comment for the concurrent-writer data-loss
	// this closes.
	return rules.WithLock(path, func() error {
		cfg, err := rules.Load(path)
		if err != nil {
			return err
		}
		_, dropped := cfg.EnsureAllCategories(redact.AllCategoryInfo())
		warnDroppedCategories(dropped)

		var targets []string
		if _, ok := cfg.Categories[category]; ok {
			targets = []string{category}
		} else {
			prefix := category + "."
			for name := range cfg.Categories {
				if strings.HasPrefix(name, prefix) {
					targets = append(targets, name)
				}
			}
			slices.Sort(targets)
		}
		if len(targets) == 0 {
			return fmt.Errorf("%q is not a known category or category.subcategory; run `redactproxy rules show` for the list", category)
		}

		var toggled []string
		for _, name := range targets {
			state := cfg.Categories[name]
			if state.Enabled == enable {
				continue
			}
			state.Enabled = enable
			cfg.Categories[name] = state
			toggled = append(toggled, name)
		}

		if len(toggled) == 0 {
			fmt.Printf("%q is already %sd, nothing to do\n", category, verb)
			return nil
		}

		if err := cfg.Save(path); err != nil {
			return err
		}
		if len(toggled) == 1 && toggled[0] == category {
			fmt.Printf("%sd %q\n", verb, category)
		} else {
			fmt.Printf("%sd %d categor%s under %q: %s\n", verb, len(toggled), plural(len(toggled)), category, strings.Join(toggled, ", "))
		}
		fmt.Println("if redactproxy is already running for this engagement, this applies within a couple of seconds, no restart needed")
		return nil
	})
}

func rulesAdd(args []string, allow bool) error {
	name := "block"
	if allow {
		name = "allow"
	}
	ef := newEngagementFlags("redactproxy rules " + name)
	isRegex := ef.fs.Bool("regex", false, "treat the value as a regular expression instead of a literal string")
	isDomain := ef.fs.Bool("domain", false, "block only: value is a domain, so it gets the same structure-preserving token treatment as any domain this tool finds on its own, everywhere it appears (subdomains, emails, URLs included), not just this exact literal text. Pass the BASE domain only (no \"www.\", no subdomain)")
	note := ef.fs.String("note", "", "optional note explaining why this entry exists")
	_, path, err := ef.parse(args, rulesPathFor)
	if err != nil {
		return err
	}
	if ef.fs.NArg() != 1 {
		// Go's flag package stops parsing flags at the first non-flag
		// argument, so a value typed before its flags (e.g. "rules block
		// widgetcorp.do --domain") leaves "--domain" as a second, unwanted
		// positional argument here rather than being recognized as a
		// flag at all -- NArg() ends up 2, not 1, with no indication of
		// why. Naming the actual ordering rule directly, rather than just
		// repeating the usage string, is the difference between this
		// error teaching the fix and just repeating the same command
		// shape that already failed.
		return fmt.Errorf("usage: redactproxy rules %s [--regex] [--domain] [--note \"...\"] <value>; flags must come before the value, e.g. \"rules %s --domain widgetcorp.do\", not \"rules %s widgetcorp.do --domain\"", name, name, name)
	}
	return addRuleValueCore(path, ruleAddRequest{
		Value:    ef.fs.Arg(0),
		Allow:    allow,
		Regex:    *isRegex,
		IsDomain: *isDomain,
		Note:     *note,
	})
}

// ruleAddRequest is one `rules block`/`rules allow` addition. A struct
// rather than a positional parameter list: the three flags are all bool
// and all optional, so a call site reading (path, value, false, false,
// false, "") said nothing at all about which false meant what, and
// transposing two of them would have compiled cleanly while quietly
// adding the wrong kind of rule.
type ruleAddRequest struct {
	Value string
	// Allow puts the entry on the allow list instead of the block list.
	Allow bool
	// Regex treats Value as a regular expression, not a literal string.
	Regex bool
	// IsDomain requests structure-preserving domain-token treatment;
	// block entries only, see rules.Entry.IsDomain.
	IsDomain bool
	Note     string
}

// addRuleValueCore is rulesAdd's actual work, taking an already-resolved
// path so the console can call it too; see showRulesCore's doc comment
// for why this split exists. The console's simplified "block"/"allow"
// commands leave every optional field zero (no flag parsing there);
// power-user cases (--regex, --domain, --note) stay on the standalone CLI
// form.
func addRuleValueCore(path string, req ruleAddRequest) error {
	value, allow, isRegex, isDomain := req.Value, req.Allow, req.Regex, req.IsDomain
	name := "block"
	if allow {
		name = "allow"
	}
	entry := rules.Entry{Value: value, Regex: isRegex, IsDomain: isDomain, Note: req.Note}
	probe := &rules.Config{Block: []rules.Entry{entry}}
	if allow {
		probe = &rules.Config{Allow: []rules.Entry{entry}}
	}
	if err := probe.Validate(); err != nil {
		return err
	}

	// Whole Load-inspect-modify-Save cycle under one lock; see
	// rules.WithLock's doc comment for the concurrent-writer data-loss
	// this closes. Locking only around Save would still leave the
	// conflict-check window open:
	// two concurrent adds could each Load a snapshot without the
	// other's not-yet-saved entry, both pass the conflict check, and
	// the second Save would silently discard the first's change.
	return rules.WithLock(path, func() error {
		cfg, err := rules.Load(path)
		if err != nil {
			return err
		}
		// Densify Categories here too, not just in toggleCategoryCore/
		// runProxy/wizard -- otherwise an engagement whose first-ever
		// command is `rules block`/`allow` gets a rules.json with a
		// populated Block/Allow list but no categories section at all
		// until some other command happens to touch the file.
		_, dropped := cfg.EnsureAllCategories(redact.AllCategoryInfo())
		warnDroppedCategories(dropped)

		sameList, oppositeList := cfg.Block, cfg.Allow
		sameName, oppositeName := "block", "allow"
		if allow {
			sameList, oppositeList = cfg.Allow, cfg.Block
			sameName, oppositeName = "allow", "block"
		}

		if _, found := rules.FindEntry(sameList, value); found {
			fmt.Printf("%q is already in the %s list, nothing to do\n", value, sameName)
			return nil
		}
		if conflicting, found := rules.FindEntry(oppositeList, value); found {
			return fmt.Errorf("%q already has a%s %s entry (%s). A value can only be in one list at a time, since an Allow entry always overrides a Block entry for the same value, so having both would never mean anything. Run `redactproxy rules remove %q` first, then `rules %s %q` again if that's what you actually want",
				value, aOrAn(oppositeName), oppositeName, describeConflicting(conflicting), value, name, value)
		}
		if cat, ok := matchesKnownCategoryName(value); ok {
			fmt.Printf("note: %q is also the name of a detector category (%s); if you meant to toggle that detector instead of adding a literal value, use `redactproxy rules disable %s` (or `enable`)\n", value, cat, cat)
		}

		if allow {
			cfg.Allow = append(cfg.Allow, entry)
		} else {
			cfg.Block = append(cfg.Block, entry)
		}
		if err := cfg.Save(path); err != nil {
			return err
		}
		fmt.Printf("added to %s list: %q\n", name, value)
		fmt.Println("if redactproxy is already running for this engagement, this applies within a couple of seconds, no restart needed")
		if !allow && !isRegex && isDomain {
			printDomainBlockAdvice(value)
		}
		return nil
	})
}

// printDomainBlockAdvice tells the operator what actually happens when a
// block-list value looks like a domain -- see rules.Compiled.ForcedDomains
// for the mechanism. A bare registrable domain ("widgetcorp-fixture.do") gets upgraded
// to a real domain token everywhere it appears (subdomain, email, URL
// included), not just the literal opaque block token this list normally
// produces. A value that parses as a domain but ISN'T bare (has "www." or
// a subdomain) doesn't get that upgrade -- warn, since that's the
// single most likely mistake here, and the fix is just re-adding the
// bare form.
func printDomainBlockAdvice(value string) {
	registrable, isBare, ok := redact.DomainRegistrablePart(value)
	if ok {
		if isBare {
			fmt.Printf("recognized as a domain: this will be tokenized as a structured domain value (subdomains and the real suffix stay visible to Claude) everywhere %q appears, not just this exact form.\n", value)
			return
		}
		fmt.Printf("note: %q is a subdomain, not the base domain. It resolves to the base domain %q, which gets the full treatment everywhere it appears, so nothing is lost. Enter %q directly next time to skip the extra step.\n", value, registrable, registrable)
		return
	}
	if redact.LooksLikeHostname(value) {
		fmt.Printf("recognized as a domain: %q isn't on any public suffix list, so it looks like an internal-only name such as an AD forest or a private naming scheme. It will still be tokenized as a structured domain value everywhere it appears, trusting that you know it's a real domain in this engagement.\n", value)
		return
	}
	fmt.Printf("warning: %q doesn't look like a real domain at all; added anyway, but it will only work as an ordinary literal block value (no domain-token treatment, matches only this exact text).\n", value)
}

func rulesRemove(args []string) error {
	ef := newEngagementFlags("redactproxy rules remove")
	_, path, err := ef.parse(args, rulesPathFor)
	if err != nil {
		return err
	}
	if ef.fs.NArg() != 1 {
		return fmt.Errorf("usage: redactproxy rules remove [--engagement NAME] [--data-dir DIR] <value>; flags must come before the value, e.g. \"rules remove --engagement foo bar\", not \"rules remove bar --engagement foo\"")
	}
	return removeRuleValueCore(path, ef.fs.Arg(0))
}

// removeRuleValueCore is rulesRemove's actual work, taking an
// already-resolved path so the console can call it too; see
// showRulesCore's doc comment for why this split exists.
func removeRuleValueCore(path, value string) error {
	// Whole Load-modify-Save cycle under one lock; see rules.WithLock's
	// doc comment for the concurrent-writer data-loss bug this closes.
	return rules.WithLock(path, func() error {
		cfg, err := rules.Load(path)
		if err != nil {
			return err
		}
		_, dropped := cfg.EnsureAllCategories(redact.AllCategoryInfo())
		warnDroppedCategories(dropped)

		fromBlock, fromAllow := cfg.RemoveValue(value)
		if !fromBlock && !fromAllow {
			return fmt.Errorf("no block or allow entry found for %q; run `redactproxy rules show` to see what's currently there", value)
		}
		if err := cfg.Save(path); err != nil {
			return err
		}

		switch {
		case fromBlock && fromAllow:
			fmt.Printf("removed %q from both the block and allow lists\n", value)
		case fromBlock:
			fmt.Printf("removed %q from the block list\n", value)
		case fromAllow:
			fmt.Printf("removed %q from the allow list\n", value)
		}
		fmt.Println("if redactproxy is already running for this engagement, this applies within a couple of seconds, no restart needed")
		return nil
	})
}

// matchesKnownCategoryName reports whether value is an exact,
// case-insensitive match for any known category or subcategory name
// (bare subcategory, e.g. "pan" for "india_pii.pan"). Used to hint at
// the likely real intent behind a mistake like `rules block pan` when
// the operator meant to exempt the india_pii.pan detector, not add a
// literal (and dangerously over-broad substring) block for the word
// "pan".
func matchesKnownCategoryName(value string) (string, bool) {
	lower := strings.ToLower(value)
	for _, info := range redact.AllCategoryInfo() {
		if strings.ToLower(info.Subcategory) == lower {
			return info.Name(), true
		}
		if strings.ToLower(info.Category) == lower {
			return info.Category, true
		}
	}
	return "", false
}

func describeConflicting(e rules.Entry) string {
	if e.Note != "" {
		return e.Note
	}
	if e.Regex {
		return "added as a regex"
	}
	return "added as a literal value"
}

// aOrAn returns "n" if s starts with a vowel (so "a"+aOrAn(s)+" "+s reads
// "an allow"), or "" otherwise (so it reads "a block").
func aOrAn(s string) string {
	if len(s) == 0 {
		return ""
	}
	switch s[0] {
	case 'a', 'e', 'i', 'o', 'u':
		return "n"
	default:
		return ""
	}
}
