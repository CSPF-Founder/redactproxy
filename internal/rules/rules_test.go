package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/CSPF-Founder/redactproxy/internal/redact"
)

func TestLoad_MissingFileReturnsEmptyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error for a missing file, got %v", err)
	}
	if len(cfg.Categories) != 0 || len(cfg.Block) != 0 || len(cfg.Allow) != 0 {
		t.Fatalf("expected an empty config, got %+v", cfg)
	}
}

// TestLoad_StripsLeadingUTF8BOM pins a real, found-via-testing gap:
// encoding/json doesn't strip a leading UTF-8 BOM on its own (it's just
// another invalid-JSON byte as far as the stdlib decoder is concerned),
// and Windows Notepad writes one by default -- a rules.json hand-edited
// there would otherwise fail to parse with a cryptic "invalid character
// 'ï'" that gives no hint the file looks completely normal in the
// editor that produced it.
func TestLoad_StripsLeadingUTF8BOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	data := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"block":[{"value":"BomTestValue"}]}`)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected a BOM-prefixed file to load cleanly, got: %v", err)
	}
	if len(cfg.Block) != 1 || cfg.Block[0].Value != "BomTestValue" {
		t.Fatalf("expected the block entry to survive, got %+v", cfg.Block)
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")

	cfg := &Config{
		Categories: map[string]CategoryState{
			"cloud.aws":   {Enabled: false},
			"network.mac": {Enabled: false},
		},
		Block: []Entry{{Value: "XyzExampleCorp", Note: "customer name"}},
		Allow: []Entry{{Value: "mylab.io"}},
	}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Categories) != 2 || len(loaded.Block) != 1 || len(loaded.Allow) != 1 {
		t.Fatalf("round-trip mismatch: %+v", loaded)
	}
	if loaded.Categories["cloud.aws"].Enabled || loaded.Categories["network.mac"].Enabled {
		t.Fatalf("expected both categories to round-trip as disabled, got %+v", loaded.Categories)
	}
	if loaded.Block[0].Value != "XyzExampleCorp" || loaded.Block[0].Note != "customer name" {
		t.Fatalf("block entry round-trip mismatch: %+v", loaded.Block[0])
	}
}

func TestSave_CreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "rules.json")
	cfg := &Config{Categories: map[string]CategoryState{"cloud.aws": {Enabled: false}}}
	if err := cfg.Save(path); err != nil {
		t.Fatalf("expected Save to create missing parent directories, got %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("expected the saved file to be loadable, got %v", err)
	}
}

func TestValidate_RejectsBadRegex(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
	}{
		{"bad block regex", &Config{Block: []Entry{{Value: "([", Regex: true}}}},
		{"bad allow regex", &Config{Allow: []Entry{{Value: "a(", Regex: true}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

// TestValidate_RejectsEmptyValue is a regression test: a malformed
// rules.json (e.g. the wrong JSON key, so Entry.Value never unmarshals)
// produces an entry with Value == "". For a non-regex block entry, that
// silently compiles to the literal pattern "(?i)" -- matching at every
// position in every string -- rather than failing loudly at load time.
func TestValidate_RejectsEmptyValue(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
	}{
		{"empty block value", &Config{Block: []Entry{{Value: ""}}}},
		{"empty allow value", &Config{Allow: []Entry{{Value: ""}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); err == nil {
				t.Fatal("expected a validation error for an empty value")
			}
			if _, err := tc.cfg.Compile(); err == nil {
				t.Fatal("expected Compile to also reject an empty value")
			}
		})
	}
}

func TestValidate_AcceptsGoodConfig(t *testing.T) {
	cfg := &Config{
		Block: []Entry{{Value: "XyzExampleCorp"}, {Value: `PROJ-\d+`, Regex: true}},
		Allow: []Entry{{Value: "mylab.io"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// TestCompile_IsDomainRoutesToForcedDomains pins the explicit, opt-in
// split between a generic opaque block value and one an operator marked
// IsDomain -- the latter is excluded from Compiled.Block entirely and
// surfaced via ForcedDomains instead (see its doc comment for why:
// avoids the domain detector's structure-preserving template wrapping an
// already-opaque block token and corrupting the result). Domain-shaped
// text WITHOUT IsDomain set never gets this treatment -- it's an
// explicit opt-in, not auto-detected from Value's shape: auto-detection
// would misclassify a URL/email typed as a raw block value, silently
// excluding it from the ordinary block list entirely while resolving to
// a "registrable domain" nothing would ever actually match, making the
// entry completely inert.
func TestCompile_IsDomainRoutesToForcedDomains(t *testing.T) {
	cfg := &Config{Block: []Entry{
		{Value: "widgetcorp-fixture.do", IsDomain: true},
		{Value: "not-marked-widgetcorp-fixture.do"}, // domain-shaped, but IsDomain not set -- stays ordinary
		{Value: "XyzExampleCorp"},
		{Value: `widgetcorp-fixture\.do`, Regex: true, IsDomain: true}, // IsDomain ignored on a regex entry
	}}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.ForcedDomains["widgetcorp-fixture.do"] {
		t.Errorf("expected \"widgetcorp-fixture.do\" in ForcedDomains, got %+v", compiled.ForcedDomains)
	}
	if len(compiled.ForcedDomains) != 1 {
		t.Errorf("expected exactly 1 forced domain, got %+v", compiled.ForcedDomains)
	}
	if len(compiled.Block) != 3 {
		t.Fatalf("expected the other 3 entries to remain ordinary Block patterns, got %d: %+v", len(compiled.Block), compiled.Block)
	}
	if len(compiled.UnresolvedDomainEntries) != 0 {
		t.Errorf("expected no unresolved entries, got %+v", compiled.UnresolvedDomainEntries)
	}
}

// TestCompile_IsDomainOnSubdomainResolvesToBase pins that marking a
// SUBDOMAIN IsDomain (a plausible mistake, or a deliberate CLI-side
// normalization step) still resolves to and is keyed by the base
// registrable domain, not the literal subdomain string -- matching what
// the domain detector's own registrable-part lookup will actually check
// against.
func TestCompile_IsDomainOnSubdomainResolvesToBase(t *testing.T) {
	cfg := &Config{Block: []Entry{{Value: "admin.widgetcorp-fixture.do", IsDomain: true}}}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.ForcedDomains["widgetcorp-fixture.do"] {
		t.Errorf("expected \"widgetcorp-fixture.do\" (the base domain) in ForcedDomains, got %+v", compiled.ForcedDomains)
	}
	if len(compiled.Block) != 0 {
		t.Errorf("expected no ordinary Block entries, got %+v", compiled.Block)
	}
}

// TestCompile_IsDomainOnNonDomainFallsBackSafely is the safety-net case:
// a hand-edited rules.json (or a CLI -domain flag) marking IsDomain on
// something that isn't a real domain at all -- a URL, an email, an
// arbitrary string -- must never be silently dropped or excluded from
// protection. It falls back to an ordinary literal Block entry, exactly
// as if IsDomain had never been set, and is surfaced via
// UnresolvedDomainEntries so the caller can log a warning (there's no
// interactive channel to warn through for a hand-edited file -- see
// logRulesState in cmd/redactproxy/main.go).
func TestCompile_IsDomainOnNonDomainFallsBackSafely(t *testing.T) {
	cfg := &Config{Block: []Entry{
		{Value: "https://widgetcorp-fixture.do", IsDomain: true},
		{Value: "admin@widgetcorp-fixture.do", IsDomain: true},
		{Value: "XyzExampleCorp", IsDomain: true},
	}}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.ForcedDomains) != 0 {
		t.Errorf("expected none of these to resolve as domains, got %+v", compiled.ForcedDomains)
	}
	if len(compiled.Block) != 3 {
		t.Fatalf("expected all 3 to fall back to ordinary Block entries, got %d: %+v", len(compiled.Block), compiled.Block)
	}
	if len(compiled.UnresolvedDomainEntries) != 3 {
		t.Fatalf("expected all 3 surfaced as unresolved, got %+v", compiled.UnresolvedDomainEntries)
	}
	// Each still works as a normal literal substring block, unaffected.
	for i, want := range []string{"visited https://widgetcorp-fixture.do today", "email admin@widgetcorp-fixture.do here", "client is XyzExampleCorp Inc"} {
		if !compiled.Block[i].MatchString(want) {
			t.Errorf("expected Block[%d] to still match %q as an ordinary literal", i, want)
		}
	}
}

// TestCompile_IsDomainOnInternalOnlyTLDStillForced is the third
// classification case: a value that's syntactically a real hostname but
// whose TLD isn't a recognized public suffix (an Active Directory forest
// name, a purely-internal naming scheme) still gets the domain-token
// treatment when explicitly marked IsDomain, trusting the operator over
// public-suffix recognition -- it's neither treated as fully resolved
// (DomainRegistrablePart itself reports ok=false for this) nor as
// unresolved/falls-back-to-literal like a URL or email does.
func TestCompile_IsDomainOnInternalOnlyTLDStillForced(t *testing.T) {
	cfg := &Config{Block: []Entry{{Value: "fileserver.mycorpad", IsDomain: true}}}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.ForcedDomains["fileserver.mycorpad"] {
		t.Errorf("expected \"fileserver.mycorpad\" in ForcedDomains, got %+v", compiled.ForcedDomains)
	}
	if len(compiled.Block) != 0 {
		t.Errorf("expected no ordinary Block entries, got %+v", compiled.Block)
	}
	if len(compiled.UnresolvedDomainEntries) != 0 {
		t.Errorf("expected no unresolved entries, got %+v", compiled.UnresolvedDomainEntries)
	}
}

func TestCompile_BlockEntryIsSubstringCaseInsensitive(t *testing.T) {
	cfg := &Config{Block: []Entry{{Value: "XyzExampleCorp"}}}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.Block[0].MatchString("we work with xyzexamplecorporation") {
		t.Error("expected a case-insensitive substring match")
	}
}

func TestCompile_AllowEntryIsExactMatchCaseInsensitive(t *testing.T) {
	cfg := &Config{Allow: []Entry{{Value: "mylab.io"}}}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Allow[0].MatchString("notmylab.io") {
		t.Error("expected allow entries to be anchored to an exact match, not a substring")
	}
	if compiled.Allow[0].MatchString("mylab.io.evil.com") {
		t.Error("expected allow entries to be anchored to an exact match, not a prefix")
	}
	if !compiled.Allow[0].MatchString("MyLab.IO") {
		t.Error("expected allow entries to be case-insensitive")
	}
}

func TestCompile_RegexEntryUsedAsWritten(t *testing.T) {
	cfg := &Config{Block: []Entry{{Value: `PROJ-\d{4}`, Regex: true}}}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.Block[0].MatchString("ticket PROJ-1234 filed") {
		t.Error("expected the regex entry to match as written")
	}
	if compiled.Block[0].MatchString("ticket proj-1234 filed") {
		t.Error("regex entries are used exactly as written, not forced case-insensitive like literal entries")
	}
}

func TestCompile_DisabledSetPopulated(t *testing.T) {
	cfg := &Config{Categories: map[string]CategoryState{
		"cloud.aws": {Enabled: false},
		"network":   {Enabled: false},
	}}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.Disabled["cloud.aws"] || !compiled.Disabled["network"] {
		t.Fatalf("expected both entries in the compiled Disabled set, got %v", compiled.Disabled)
	}
}

func TestCompile_EnabledCategoryNotInDisabledSet(t *testing.T) {
	cfg := &Config{Categories: map[string]CategoryState{"cloud.aws": {Enabled: true}}}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Disabled["cloud.aws"] {
		t.Fatal("expected an explicitly-enabled category to NOT be in the compiled Disabled set")
	}
}

func TestCompile_AbsentCategoryTreatedAsEnabled(t *testing.T) {
	// A sparse or hand-trimmed Categories map must still behave
	// correctly for anything it doesn't mention; Compile doesn't
	// require EnsureAllCategories to have run first.
	cfg := &Config{}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Disabled["cloud.aws"] {
		t.Fatal("expected an absent category to default to enabled (not in the compiled Disabled set)")
	}
}

// TestSave_ConcurrentReadsNeverSeeATornFile directly exercises the
// atomicity Save now provides (temp file + rename instead of
// os.WriteFile's truncate-then-write): a reader racing many concurrent
// Saves must always see either a complete old config or a complete new
// one, never a parse error from a partially-written file. This is the
// real-world condition TestWatcher_TornReadDuringWriteNoLongerLeavesStaleRulesStuck
// pins down deterministically; this test hits it under genuine
// concurrency instead.
func TestSave_ConcurrentReadsNeverSeeATornFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := (&Config{Categories: map[string]CategoryState{"seed": {Enabled: false}}}).Save(path); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			cfg := &Config{Categories: map[string]CategoryState{fmt.Sprintf("writer-%d", i): {Enabled: false}}}
			if err := cfg.Save(path); err != nil {
				t.Errorf("Save: %v", err)
				return
			}
		}
	})

	readErrs := 0
	for range 500 {
		if _, err := Load(path); err != nil {
			readErrs++
			t.Errorf("Load saw a torn/invalid file: %v", err)
		}
	}
	close(stop)
	wg.Wait()

	if readErrs > 0 {
		t.Fatalf("%d of 500 concurrent reads saw a torn file", readErrs)
	}
}

func TestFindEntry_CaseInsensitiveMatch(t *testing.T) {
	entries := []Entry{{Value: "XyzExampleCorp", Note: "wizard entry"}}
	e, found := FindEntry(entries, "xyzexamplecorp")
	if !found {
		t.Fatal("expected a case-insensitive match")
	}
	if e.Note != "wizard entry" {
		t.Errorf("expected the matched entry's own fields back, got %+v", e)
	}
}

func TestFindEntry_NoMatch(t *testing.T) {
	entries := []Entry{{Value: "XyzExampleCorp"}}
	if _, found := FindEntry(entries, "OtherCorp"); found {
		t.Fatal("expected no match for an unrelated value")
	}
}

func TestRemoveValue_RemovesFromBothListsWhenPresentInBoth(t *testing.T) {
	cfg := &Config{
		Block: []Entry{{Value: "pan"}, {Value: "other"}},
		Allow: []Entry{{Value: "pan"}},
	}
	fromBlock, fromAllow := cfg.RemoveValue("pan")
	if !fromBlock || !fromAllow {
		t.Fatalf("expected removal from both lists, got block=%v allow=%v", fromBlock, fromAllow)
	}
	if len(cfg.Block) != 1 || cfg.Block[0].Value != "other" {
		t.Fatalf("expected only the unrelated block entry to remain, got %+v", cfg.Block)
	}
	if len(cfg.Allow) != 0 {
		t.Fatalf("expected the allow list to be empty, got %+v", cfg.Allow)
	}
}

func TestRemoveValue_OnlyInOneList(t *testing.T) {
	cfg := &Config{Block: []Entry{{Value: "XyzExampleCorp"}}}
	fromBlock, fromAllow := cfg.RemoveValue("XyzExampleCorp")
	if !fromBlock || fromAllow {
		t.Fatalf("expected block=true allow=false, got block=%v allow=%v", fromBlock, fromAllow)
	}
	if len(cfg.Block) != 0 {
		t.Fatalf("expected the block list to be empty, got %+v", cfg.Block)
	}
}

func TestRemoveValue_NotFoundAnywhereReportsFalseFalse(t *testing.T) {
	cfg := &Config{}
	fromBlock, fromAllow := cfg.RemoveValue("never-seen")
	if fromBlock || fromAllow {
		t.Fatalf("expected both false for a value that was never present, got block=%v allow=%v", fromBlock, fromAllow)
	}
}

// TestEnsureAllCategories_AddsCategoryMissingFromOlderFile is the
// forward-compatibility test explicitly asked for: a rules.json written
// before some category existed (simulated here directly, without
// needing an actual older binary) must pick up that category
// automatically, defaulted enabled, the next time it's reconciled,
// never silently missing or silently disabled just because it didn't
// exist when the file was first written.
func TestEnsureAllCategories_AddsCategoryMissingFromOlderFile(t *testing.T) {
	cfg := &Config{Categories: map[string]CategoryState{
		"cloud.aws": {Enabled: false},
	}}
	cfg.EnsureAllCategories([]redact.CategoryInfo{
		{Category: "cloud", Subcategory: "aws", Description: "AWS keys."},
		{Category: "network", Subcategory: "domain", Description: "Domains."}, // "new" category not in the original file
	})
	state, ok := cfg.Categories["network.domain"]
	if !ok {
		t.Fatal("expected the new category to be added")
	}
	if !state.Enabled {
		t.Fatal("expected the new category to default to enabled")
	}
	if state.Description != "Domains." {
		t.Fatalf("expected the new category's description to be populated, got %+v", state)
	}
}

// TestEnsureAllCategories_PrunesCategoryNoLongerKnown covers the other
// direction: a category present in an old file that a newer binary no
// longer defines must not linger forever as an orphaned entry.
func TestEnsureAllCategories_PrunesCategoryNoLongerKnown(t *testing.T) {
	cfg := &Config{Categories: map[string]CategoryState{
		"cloud.aws":          {Enabled: false},
		"some.removed_thing": {Enabled: true},
	}}
	cfg.EnsureAllCategories([]redact.CategoryInfo{
		{Category: "cloud", Subcategory: "aws", Description: "AWS keys."},
	})
	if _, ok := cfg.Categories["some.removed_thing"]; ok {
		t.Fatal("expected the no-longer-known category to be pruned")
	}
	if len(cfg.Categories) != 1 {
		t.Fatalf("expected exactly one remaining category, got %+v", cfg.Categories)
	}
}

// TestEnsureAllCategories_PreservesExistingEnabledState is the
// guardrail against the mechanism above accidentally flipping
// something someone deliberately disabled; Enabled must only ever be
// set by EnsureAllCategories for a genuinely NEW key, never touched
// for one that already existed.
func TestEnsureAllCategories_PreservesExistingEnabledState(t *testing.T) {
	cfg := &Config{Categories: map[string]CategoryState{
		"cloud.aws": {Enabled: false, Description: "stale text"},
	}}
	cfg.EnsureAllCategories([]redact.CategoryInfo{
		{Category: "cloud", Subcategory: "aws", Description: "fresh text"},
	})
	state := cfg.Categories["cloud.aws"]
	if state.Enabled {
		t.Fatal("expected the deliberately-disabled category to stay disabled")
	}
	if state.Description != "fresh text" {
		t.Fatalf("expected Description to be refreshed even though Enabled was preserved, got %+v", state)
	}
}

func TestEnsureAllCategories_ReportsChangedCorrectly(t *testing.T) {
	all := []redact.CategoryInfo{
		{Category: "cloud", Subcategory: "aws", Description: "AWS keys."},
	}
	cfg := &Config{}
	if changed, _ := cfg.EnsureAllCategories(all); !changed {
		t.Fatal("expected the first call (populating a nil/empty map) to report changed=true")
	}
	if changed, _ := cfg.EnsureAllCategories(all); changed {
		t.Fatal("expected a second call with identical input to report changed=false; nothing actually differs")
	}
	// A new category appearing must report changed=true again.
	all = append(all, redact.CategoryInfo{Category: "network", Subcategory: "domain", Description: "Domains."})
	if changed, _ := cfg.EnsureAllCategories(all); !changed {
		t.Fatal("expected adding a new category to report changed=true")
	}
	// Removing one from the source list must also report changed=true.
	all = all[:1]
	if changed, _ := cfg.EnsureAllCategories(all); !changed {
		t.Fatal("expected pruning a category to report changed=true")
	}
}

// TestEnsureAllCategories_ReportsDroppedKeys pins the fix for a real
// gap: write paths (runProxy/wizard/rules subcommands) used to call
// EnsureAllCategories and silently discard which keys got pruned, so a
// hand-edited case typo on an otherwise-live category (e.g.
// "Allowlist.Wellknown_Platforms" instead of
// "allowlist.wellknown_platforms") would silently revert to the
// default-enabled state with no indication anything was dropped. The
// dropped list lets a caller surface that instead of swallowing it.
func TestEnsureAllCategories_ReportsDroppedKeys(t *testing.T) {
	cfg := &Config{Categories: map[string]CategoryState{
		"cloud.aws":          {Enabled: false},
		"some.removed_thing": {Enabled: true},
		"another.gone_thing": {Enabled: true},
	}}
	_, dropped := cfg.EnsureAllCategories([]redact.CategoryInfo{
		{Category: "cloud", Subcategory: "aws", Description: "AWS keys."},
	})
	want := []string{"another.gone_thing", "some.removed_thing"}
	if len(dropped) != len(want) {
		t.Fatalf("dropped = %v, want %v", dropped, want)
	}
	for i, k := range want {
		if dropped[i] != k {
			t.Fatalf("dropped = %v, want %v (sorted)", dropped, want)
		}
	}

	// Nothing dropped when everything still matches.
	_, dropped2 := cfg.EnsureAllCategories([]redact.CategoryInfo{
		{Category: "cloud", Subcategory: "aws", Description: "AWS keys."},
	})
	if len(dropped2) != 0 {
		t.Fatalf("expected no dropped keys on a stable call, got %v", dropped2)
	}
}

func TestEnsureAllCategories_NilCategoriesMapInitialized(t *testing.T) {
	cfg := &Config{}
	cfg.EnsureAllCategories([]redact.CategoryInfo{
		{Category: "cloud", Subcategory: "aws", Description: "AWS keys."},
	})
	if len(cfg.Categories) != 1 {
		t.Fatalf("expected EnsureAllCategories to initialize a nil map, got %+v", cfg.Categories)
	}
}

// TestWithLock_SerializesConcurrentReadModifyWriteCycles confirms
// concurrent read-modify-write cycles through WithLock never lose an
// update: without it, whichever process saves last would completely
// overwrite every other concurrent writer's change, since Save always
// writes the whole file from its own in-memory snapshot. This reproduces
// the pattern in-process (many goroutines, each its own
// Load-append-one-value-Save cycle through WithLock) and asserts zero
// are lost.
func TestWithLock_SerializesConcurrentReadModifyWriteCycles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	const n = 30

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Go(func() {
			err := WithLock(path, func() error {
				cfg, err := Load(path)
				if err != nil {
					return err
				}
				cfg.Block = append(cfg.Block, Entry{Value: fmt.Sprintf("value-%d", i)})
				return cfg.Save(path)
			})
			if err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("WithLock cycle failed: %v", err)
	}

	final, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Block) != n {
		seen := map[string]bool{}
		for _, e := range final.Block {
			seen[e.Value] = true
		}
		var missing []string
		for i := range n {
			v := fmt.Sprintf("value-%d", i)
			if !seen[v] {
				missing = append(missing, v)
			}
		}
		t.Fatalf("expected all %d concurrent writes to survive, got %d, missing: %v", n, len(final.Block), missing)
	}
}

// TestWithLock_ReleasesLockFileAfterUse confirms the lock file doesn't
// linger once fn returns; a leftover lock file would permanently wedge
// every future WithLock call on the same path until someone noticed and
// deleted it by hand.
func TestWithLock_ReleasesLockFileAfterUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := WithLock(path, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("expected the lock file to be removed after WithLock returns, stat err: %v", err)
	}
}

// TestWithLock_ReleasesLockFileEvenOnError confirms the lock is
// released even when fn itself returns an error; otherwise one failed
// operation would permanently wedge the file for everyone after it.
func TestWithLock_ReleasesLockFileEvenOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	sentinel := fmt.Errorf("boom")
	if err := WithLock(path, func() error { return sentinel }); err != sentinel {
		t.Fatalf("expected the sentinel error to propagate, got %v", err)
	}
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("expected the lock file to be removed even after fn errored, stat err: %v", err)
	}
}

// TestWithLock_TimesOutIfAlreadyHeld confirms a second WithLock call on
// an already-locked path fails with a clear error rather than hanging
// forever, important since this is what an operator would hit if a
// previous redactproxy process crashed mid-write and left the lock file
// behind.
func TestWithLock_TimesOutIfAlreadyHeld(t *testing.T) {
	orig := lockAcquireTimeout
	lockAcquireTimeout = 50 * time.Millisecond
	t.Cleanup(func() { lockAcquireTimeout = orig })

	path := filepath.Join(t.TempDir(), "rules.json")
	// Simulate a stale lock left behind by a crashed process.
	if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := WithLock(path, func() error {
		t.Fatal("fn must never run while the lock is already held")
		return nil
	})
	if err == nil {
		t.Fatal("expected an error when the lock is already held")
	}
}
