// Package rules holds the persisted, per-engagement customization on top
// of the built-in redact detector set: which detector categories/
// subcategories are disabled, and custom block/allow entries. It's a
// plain JSON file that a hand edit, the setup wizard, or a CLI
// subcommand can all write, and that the running proxy watches for
// changes so edits apply without a restart. JSON rather than YAML or
// anything else that would need a new dependency: the config surface
// here is small, and the CLI subcommands built on top of it are meant
// to be the main way it gets edited, not hand-authoring.
package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/CSPF-Founder/redactproxy/internal/redact"
)

// Entry is one block-list or allow-list rule: either an exact string
// (Regex: false) or a regular expression (Regex: true), plus an
// optional human-readable reason, recorded so a saved config stays
// auditable months later ("why is this here?"), not just a bare list of
// patterns. Regex entries are compiled with Go's standard regexp
// package (RE2), the same engine every built-in detector uses, so a
// user-authored pattern is exactly as immune to catastrophic
// backtracking as anything else in this codebase.
//
// IsDomain is an explicit, operator-set request (block-list entries
// only, ignored on Regex entries and on Allow) that Value should get
// the domain detector's own structure-preserving token treatment
// instead of the generic opaque block token; see Compiled.ForcedDomains
// for why this needs to be an explicit opt-in rather than
// auto-detected from Value's shape. Settable via `redactproxy rules
// block -domain`, or by hand-editing this field directly in
// rules.json. There's deliberately no separate validation step for
// the hand-edited path: Compile() itself falls back to treating the
// entry as an ordinary literal block value whenever Value doesn't
// actually resolve to a real domain, so a bad or nonsensical IsDomain
// value on a hand-edited file can never silently exclude something
// from being redacted at all.
type Entry struct {
	Value    string `json:"value"`
	Regex    bool   `json:"regex"`
	Note     string `json:"note,omitempty"`
	IsDomain bool   `json:"is_domain,omitempty"`
}

// CategoryState is one category/subcategory's persisted state, keyed
// by "category.subcategory" (e.g. "cloud.aws") in Config.Categories.
// Description and Warning are informational only: EnsureAllCategories
// always overwrites them with current source text on every call, so a
// stale description from an older binary (or a hand-edited one) never
// lingers or drifts from what the code actually does. Only Enabled is
// real, persisted, behavioral state.
type CategoryState struct {
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
	Warning     string `json:"warning,omitempty"`
}

// Config is the full persisted ruleset for one engagement.
type Config struct {
	// Categories holds every known category/subcategory's enabled
	// state, keyed by "category.subcategory" (see
	// redact.CategorizedDetector / redact.CategoryInfo), deliberately
	// dense, not sparse: EnsureAllCategories populates every category
	// this build of the tool knows about, defaulting to Enabled: true,
	// so someone hand-editing rules.json can see every available
	// category, what it does, and its current state without running
	// `redactproxy rules show` first. An absent key is still treated as
	// enabled by Compile; density here is for the file's own
	// readability, not a behavioral requirement.
	Categories map[string]CategoryState `json:"categories,omitempty"`
	// Block entries are always redacted in addition to anything the
	// built-in detectors already catch, e.g. a customer name variant
	// the wizard collected, or a project codename added manually.
	Block []Entry `json:"block,omitempty"`
	// Allow entries are never redacted, even if a built-in detector
	// would otherwise catch them, e.g. the team's own lab domain.
	Allow []Entry `json:"allow,omitempty"`
}

// EnsureAllCategories reconciles cfg.Categories against all (typically
// redact.AllCategoryInfo()): every category in all gets an entry if it
// doesn't already have one (defaulted Enabled: true; a newly-added
// category, e.g. from a future binary version, must not silently start
// disabled just because it didn't exist when this file was first
// written), an existing entry's Enabled value is never touched, and
// Description/Warning are always overwritten with all's current text.
// Any key in cfg.Categories no longer present in all is dropped (a
// detector removed in a future version doesn't leave an orphaned
// entry forever).
//
// This is the mechanism that makes rules.json forward-compatible: a
// file written by today's binary, later opened by a future binary that
// ships a new category, gets that category added automatically on the
// next Load+EnsureAllCategories+Save: no version field, no explicit
// migration step.
//
// Returns whether anything actually changed (a category added, removed,
// or its Description/Warning text updated since last written; Enabled
// values are never touched for pre-existing keys, so they never count
// as a change here), so a caller deciding whether to re-Save can skip a
// pointless rewrite (and the mtime bump that would cause) when nothing
// is actually different from what's already on disk.
//
// Also returns the keys that were dropped (present in c.Categories, not
// present in all), sorted. This package cannot tell a genuinely-retired
// category (expected, silent) apart from a hand-edited case typo on an
// otherwise-live category (a real, easy-to-miss trap, since the typo'd
// key silently reverts to the default Enabled: true instead of erroring);
// both look identical here. Callers that persist the result (unlike a
// read-only `rules show`) are expected to surface this list rather than
// swallow it, so a typo'd hand-edit doesn't silently vanish.
func (c *Config) EnsureAllCategories(all []redact.CategoryInfo) (changed bool, dropped []string) {
	if c.Categories == nil {
		c.Categories = make(map[string]CategoryState, len(all))
	}
	seen := make(map[string]bool, len(all))
	for _, info := range all {
		key := info.Name()
		seen[key] = true
		existing, existed := c.Categories[key]
		enabled := true
		if existed {
			enabled = existing.Enabled
		}
		next := CategoryState{
			Enabled:     enabled,
			Description: info.Description,
			Warning:     info.Warning,
		}
		if !existed || next != existing {
			changed = true
		}
		c.Categories[key] = next
	}
	for key := range c.Categories {
		if !seen[key] {
			delete(c.Categories, key)
			changed = true
			dropped = append(dropped, key)
		}
	}
	slices.Sort(dropped)
	return changed, dropped
}

// lockAcquireTimeout is how long WithLock waits for an already-held
// lock before giving up. A var, not a const, solely so a test can
// shrink it rather than paying this in real wall-clock time to verify
// the "already held" path actually returns rather than hanging forever.
var lockAcquireTimeout = 5 * time.Second

// WithLock serializes an entire Load-inspect-modify-Save cycle against
// path across separate OS processes, acquired via an exclusive
// create-only lock file (path+".lock"), retried with a short backoff up
// to a few seconds, released when fn returns.
//
// Without this lock, two concurrent CLI invocations (e.g. a script
// bulk-adding block entries, or two operators editing the same
// engagement from different terminals at once) each Load a snapshot,
// decide what to change based on it, then Save, and Save always writes
// the WHOLE file, so whichever process saves last silently overwrites
// the other's change in full, not just the one value being added. In a
// redaction tool a silently-dropped block entry means under-redaction,
// not just an annoyance.
//
// Every path in cmd/redactproxy that Loads, decides, and Saves rules.json
// (the `rules` subcommands' core functions, the wizard, and the proxy's
// own startup EnsureAllCategories step) must wrap that whole sequence in
// WithLock; locking only around Save (or only around Load) would still
// leave the decide-based-on-a-stale-read window open.
func WithLock(path string, fn func() error) error {
	lockPath := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return fmt.Errorf("create directory for %s: %w", lockPath, err)
	}
	deadline := time.Now().Add(lockAcquireTimeout)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			// Nothing is ever written to the lock file: its existence is
			// the whole signal, so there is no buffered data a close error
			// could be reporting the loss of.
			_ = f.Close()
			break
		}
		if !os.IsExist(err) {
			return fmt.Errorf("acquire lock %s: %w", lockPath, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s; another redactproxy command may be stuck (or crashed while holding it; if so, delete the lock file manually and retry)", lockPath)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A failed unlock is not something this caller can act on, and the
	// acquire path above already tells an operator how to clear a stale
	// lock by hand.
	defer func() { _ = os.Remove(lockPath) }()
	return fn()
}

// Load reads the config at path. A missing file is NOT an error; it
// returns an empty Config, since a fresh engagement legitimately has
// no rules.json yet until the first edit.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// encoding/json doesn't strip a leading UTF-8 BOM (Go's stdlib treats
	// it as just another invalid-JSON byte) -- Windows Notepad writes one
	// by default, so a rules.json hand-edited there fails to parse with a
	// cryptic "invalid character 'ï'" that gives no hint the file itself
	// looks completely normal in the editor that produced it.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &cfg, nil
}

// Save writes cfg to path as indented JSON, creating parent directories
// if needed. Every CLI subcommand and the wizard funnel through this;
// it's the only writer, so the on-disk shape stays consistent no matter
// which entry point produced the edit.
//
// Writes via a temp file in the same directory, then os.Rename over the
// real path, rather than os.WriteFile directly to path. os.WriteFile
// opens with O_TRUNC: truncate and the subsequent write are two
// separate syscalls, so a concurrent reader (the live proxy's Watcher,
// polling this same file) can observe a truncated/partial file
// mid-write. A torn read like that fails Load's JSON parse, and since
// Watcher.checkOnce records the new mtime before attempting the read, a
// failed reload leaves the running proxy stuck on stale rules
// indefinitely, not just until the write finished, but until some
// LATER edit changes the mtime again (see
// TestWatcher_TornReadDuringWriteLeavesStaleRulesStuck, and the mtime
// handling in watcher.go's checkOnce). Same-directory rename is required
// for atomicity: POSIX rename() is only atomic within one filesystem,
// and the temp file must land on the same one as the real target.
func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory for %s: %w", path, err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".rules-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	// No-op once the rename below succeeds; on any earlier return it is
	// best-effort cleanup of a temp file the caller never learns about.
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // returning the write error, which is the real one
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, path, err)
	}
	return nil
}

// Validate compiles every regex entry (Block and Allow) without
// applying anything, so a typo'd pattern is caught before it's relied
// on rather than silently matching nothing at runtime. Also rejects an
// empty Value on either list -- found live: a malformed rules.json
// (wrong JSON key name, so Value never unmarshaled) produces an Entry
// with Value == "", which compileEntry below turns into the literal
// pattern "(?i)" for a non-regex block entry -- a zero-width match at
// every position in every string, silently block-listing the entire
// engagement's traffic rather than failing loudly. An empty Allow value
// is comparatively harmless (compileEntry anchors it "^$", matching
// only the empty string) but just as clearly not a real rule someone
// meant to write, so it's rejected the same way for consistency.
func (c *Config) Validate() error {
	for i, e := range c.Block {
		if e.Value == "" {
			return fmt.Errorf("block[%d]: empty value -- as a non-regex entry this would match every possible input", i)
		}
		if e.Regex {
			if _, err := regexp.Compile(e.Value); err != nil {
				return fmt.Errorf("block[%d] (%q): invalid regex: %w", i, e.Value, err)
			}
		}
	}
	for i, e := range c.Allow {
		if e.Value == "" {
			return fmt.Errorf("allow[%d]: empty value", i)
		}
		if e.Regex {
			if _, err := regexp.Compile(e.Value); err != nil {
				return fmt.Errorf("allow[%d] (%q): invalid regex: %w", i, e.Value, err)
			}
		}
	}
	return nil
}

// Compiled is the ready-to-use runtime form of a Config: a lookup set
// for disabled categories, compiled regexes for block/allow, and any
// block entries an operator marked IsDomain (see ForcedDomains).
type Compiled struct {
	Disabled map[string]bool
	Block    []*regexp.Regexp
	Allow    []*regexp.Regexp

	// ForcedDomains holds the registrable domain for every non-regex
	// Block entry with IsDomain set that actually resolves to a real
	// domain (redact.DomainRegistrablePart), keyed by that registrable
	// part, not necessarily the entry's own literal Value (an entry
	// marked IsDomain with a subdomain, e.g. "admin.widgetcorp-fixture.do", still
	// resolves to and is keyed by "widgetcorp-fixture.do"). These are deliberately
	// NOT also compiled into Block: pass this to
	// redact.DefaultCategorizedDetectorsWithForcedDomains instead, so
	// the domain detector's own structure-preserving logic handles the
	// value consistently everywhere it appears (bare, subdomain, email,
	// URL) rather than the block detector's fully-opaque token, which
	// would otherwise corrupt the domain detector's own reconstruction
	// of a later subdomain occurrence of the same value (the store's
	// real-value-keyed token lookup can't tell which detector asked
	// first).
	ForcedDomains map[string]bool

	// UnresolvedDomainEntries lists the Value of every Block entry with
	// IsDomain set that DIDN'T resolve to a real domain (not domain-
	// shaped at all, or an RFC-reserved example domain) -- these fall
	// back to being an ordinary literal Block entry rather than being
	// silently dropped or excluded from anything. There's no
	// interactive channel to warn through for a hand-edited rules.json,
	// so the caller (runProxy/reload; see logRulesState) logs a
	// startup/reload WARN for each and continues; this never blocks
	// startup or fails the config.
	UnresolvedDomainEntries []string
}

// Compile turns Config into a Compiled, or returns the first invalid
// regex it finds (same errors Validate would report, but with the
// compiled result on success so callers don't have to call both).
func (c *Config) Compile() (*Compiled, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	out := &Compiled{
		Disabled:      make(map[string]bool, len(c.Categories)),
		ForcedDomains: make(map[string]bool),
	}
	for name, state := range c.Categories {
		if !state.Enabled {
			out.Disabled[name] = true
		}
	}
	for _, e := range c.Block {
		if e.IsDomain && !e.Regex {
			if registrable, _, ok := redact.DomainRegistrablePart(e.Value); ok {
				out.ForcedDomains[registrable] = true
				continue
			}
			if redact.LooksLikeHostname(e.Value) {
				// Not a recognized public suffix, but a real hostname
				// shape -- trust the operator's explicit IsDomain (an
				// internal AD forest name, a purely-internal naming
				// scheme this tool could never validate against a
				// public suffix list). See domainDetector's
				// forcedDomainSuffix fallback for how this is matched.
				out.ForcedDomains[strings.ToLower(e.Value)] = true
				continue
			}
			out.UnresolvedDomainEntries = append(out.UnresolvedDomainEntries, e.Value)
			// falls through -- treated as an ordinary literal Block
			// entry below, same as any value that was never marked
			// IsDomain at all.
		}
		re, err := compileEntry(e, false)
		if err != nil {
			return nil, fmt.Errorf("block entry %q: %w", e.Value, err)
		}
		out.Block = append(out.Block, re)
	}
	for _, e := range c.Allow {
		re, err := compileEntry(e, true)
		if err != nil {
			return nil, fmt.Errorf("allow entry %q: %w", e.Value, err)
		}
		out.Allow = append(out.Allow, re)
	}
	return out, nil
}

// FindEntry returns the entry in entries whose Value case-insensitively
// equals value, and whether one was found. Deliberately a shallow,
// literal-text comparison, not a regex-overlap analysis (which isn't
// generally decidable), so it catches an exact duplicate (including two
// regex entries with identical source text) without pretending to catch
// every way two rules could actually interact at runtime. Used for
// duplicate-add detection within one list and cross-list conflict
// detection between Block and Allow (see cmd/redactproxy/rules_cmd.go).
func FindEntry(entries []Entry, value string) (Entry, bool) {
	if i := indexOfEntry(entries, value); i != -1 {
		return entries[i], true
	}
	return Entry{}, false
}

// RemoveValue removes every entry (across both Block and Allow) whose
// Value case-insensitively equals value, reporting which list(s) it was
// actually found and removed from. Checks both lists unconditionally,
// not just the first match: a value can legitimately be present in
// both at once (e.g. a leftover contradictory pair from before the
// reject-on-conflict check existed), and removal should clear it
// everywhere in one call rather than requiring the operator to know
// which list(s) to target.
func (c *Config) RemoveValue(value string) (removedFromBlock, removedFromAllow bool) {
	if i := indexOfEntry(c.Block, value); i != -1 {
		c.Block = append(c.Block[:i], c.Block[i+1:]...)
		removedFromBlock = true
	}
	if i := indexOfEntry(c.Allow, value); i != -1 {
		c.Allow = append(c.Allow[:i], c.Allow[i+1:]...)
		removedFromAllow = true
	}
	return removedFromBlock, removedFromAllow
}

func indexOfEntry(entries []Entry, value string) int {
	for i, e := range entries {
		if strings.EqualFold(e.Value, value) {
			return i
		}
	}
	return -1
}

// compileEntry turns one Entry into a *regexp.Regexp. Regex entries are
// compiled exactly as written; the user opted into regex mode, so this
// doesn't second-guess their anchoring or case sensitivity. Literal
// (non-regex) entries are always case-insensitive; allow entries are
// additionally anchored to an exact match (^...$) rather than a
// substring, since an allow-list is a "reduce protection" operation and
// should be conservative about what it matches. A block-list entry,
// where the safe failure direction is over-matching, stays a substring
// match so "XyzExampleCorp" catches "XyzExampleCorporation" too.
func compileEntry(e Entry, exactMatch bool) (*regexp.Regexp, error) {
	if e.Regex {
		return regexp.Compile(e.Value)
	}
	pattern := regexp.QuoteMeta(e.Value)
	if exactMatch {
		pattern = "^" + pattern + "$"
	}
	return regexp.Compile("(?i)" + pattern)
}
