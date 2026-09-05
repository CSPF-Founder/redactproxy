package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/rules"
)

func rulesTestPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "rules.json")
}

func loadRulesTestConfig(t *testing.T, path string) *rules.Config {
	t.Helper()
	cfg, err := rules.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// --- enable/disable -------------------------------------------------

func TestToggleCategoryCore_DisableThenEnable(t *testing.T) {
	path := rulesTestPath(t)

	if err := toggleCategoryCore(path, "india_pii.pan", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	cfg := loadRulesTestConfig(t, path)
	if cfg.Categories["india_pii.pan"].Enabled {
		t.Fatalf("expected india_pii.pan to be disabled, got %+v", cfg.Categories["india_pii.pan"])
	}

	if err := toggleCategoryCore(path, "india_pii.pan", true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	cfg = loadRulesTestConfig(t, path)
	if !cfg.Categories["india_pii.pan"].Enabled {
		t.Fatalf("expected india_pii.pan to be enabled again, got %+v", cfg.Categories["india_pii.pan"])
	}
}

func TestToggleCategoryCore_AllowlistCategory(t *testing.T) {
	path := rulesTestPath(t)
	if err := toggleCategoryCore(path, "allowlist.wellknown_platforms", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	cfg := loadRulesTestConfig(t, path)
	if cfg.Categories["allowlist.wellknown_platforms"].Enabled {
		t.Fatalf("expected allowlist.wellknown_platforms to be disabled, got %+v", cfg.Categories["allowlist.wellknown_platforms"])
	}
}

func TestToggleCategoryCore_AlreadyDisabledIsNoOp(t *testing.T) {
	path := rulesTestPath(t)
	if err := toggleCategoryCore(path, "india_pii.pan", false); err != nil {
		t.Fatal(err)
	}
	if err := toggleCategoryCore(path, "india_pii.pan", false); err != nil {
		t.Fatalf("second disable should be a no-op, not an error: %v", err)
	}
	cfg := loadRulesTestConfig(t, path)
	disabledCount := 0
	for _, state := range cfg.Categories {
		if !state.Enabled {
			disabledCount++
		}
	}
	if disabledCount != 1 {
		t.Fatalf("expected exactly one disabled category (no duplicate effect), got %d: %+v", disabledCount, cfg.Categories)
	}
}

func TestToggleCategoryCore_AlreadyEnabledIsNoOp(t *testing.T) {
	path := rulesTestPath(t)
	if err := toggleCategoryCore(path, "india_pii.pan", true); err != nil {
		t.Fatalf("enabling an already-enabled category should be a no-op, not an error: %v", err)
	}
	cfg := loadRulesTestConfig(t, path)
	for name, state := range cfg.Categories {
		if !state.Enabled {
			t.Fatalf("expected every category to stay enabled, but %q is disabled", name)
		}
	}
}

func TestToggleCategoryCore_UnknownCategoryErrors(t *testing.T) {
	path := rulesTestPath(t)
	if err := toggleCategoryCore(path, "not_a_real_category", false); err == nil {
		t.Fatal("expected an error for an unknown category name")
	}
}

// TestToggleCategoryCore_BareCategoryExpandsToAllSubcategories covers
// the bare-category case: "cloud" (no subcategory) must disable every
// "cloud.*" leaf in one call.
func TestToggleCategoryCore_BareCategoryExpandsToAllSubcategories(t *testing.T) {
	path := rulesTestPath(t)
	if err := toggleCategoryCore(path, "cloud", false); err != nil {
		t.Fatal(err)
	}
	cfg := loadRulesTestConfig(t, path)
	found := 0
	for name, state := range cfg.Categories {
		if strings.HasPrefix(name, "cloud.") {
			found++
			if state.Enabled {
				t.Errorf("expected %q to be disabled, got %+v", name, state)
			}
		}
	}
	if found < 2 {
		t.Fatalf("expected multiple cloud.* categories to exist and be disabled, found %d", found)
	}
	// Non-cloud categories must be untouched.
	if !cfg.Categories["india_pii.pan"].Enabled {
		t.Fatal("expected an unrelated category to remain enabled")
	}

	// Re-enabling the bare category must restore all of them.
	if err := toggleCategoryCore(path, "cloud", true); err != nil {
		t.Fatal(err)
	}
	cfg = loadRulesTestConfig(t, path)
	for name, state := range cfg.Categories {
		if strings.HasPrefix(name, "cloud.") && !state.Enabled {
			t.Errorf("expected %q to be re-enabled, got %+v", name, state)
		}
	}
}

// --- block/allow ------------------------------------------------------

func TestAddRuleValueCore_BlockAndAllowPersist(t *testing.T) {
	path := rulesTestPath(t)
	if err := addRuleValueCore(path, ruleAddRequest{Value: "XyzExampleCorp", Note: "test note"}); err != nil {
		t.Fatalf("block: %v", err)
	}
	cfg := loadRulesTestConfig(t, path)
	if len(cfg.Block) != 1 || cfg.Block[0].Value != "XyzExampleCorp" || cfg.Block[0].Note != "test note" {
		t.Fatalf("unexpected block list: %+v", cfg.Block)
	}

	if err := addRuleValueCore(path, ruleAddRequest{Value: "mylab.internal", Allow: true}); err != nil {
		t.Fatalf("allow: %v", err)
	}
	cfg = loadRulesTestConfig(t, path)
	if len(cfg.Allow) != 1 || cfg.Allow[0].Value != "mylab.internal" {
		t.Fatalf("unexpected allow list: %+v", cfg.Allow)
	}
}

func TestAddRuleValueCore_DuplicateInSameListIsNoOp(t *testing.T) {
	path := rulesTestPath(t)
	if err := addRuleValueCore(path, ruleAddRequest{Value: "XyzExampleCorp"}); err != nil {
		t.Fatal(err)
	}
	if err := addRuleValueCore(path, ruleAddRequest{Value: "XyzExampleCorp"}); err != nil {
		t.Fatalf("duplicate add should be a no-op, not an error: %v", err)
	}
	cfg := loadRulesTestConfig(t, path)
	if len(cfg.Block) != 1 {
		t.Fatalf("expected exactly one entry (no duplicate), got %+v", cfg.Block)
	}
}

// TestAddRuleValueCore_RejectsCrossListConflict confirms adding a value
// to Block when it's already in Allow (or vice versa) is REJECTED
// outright, not silently accepted and not just warned about, since
// Allow always overrides Block for the same value with no exception,
// letting both exist is never meaningful.
func TestAddRuleValueCore_RejectsCrossListConflict(t *testing.T) {
	t.Run("allow-then-block", func(t *testing.T) {
		path := rulesTestPath(t)
		if err := addRuleValueCore(path, ruleAddRequest{Value: "pan", Allow: true}); err != nil {
			t.Fatal(err)
		}
		err := addRuleValueCore(path, ruleAddRequest{Value: "pan"})
		if err == nil {
			t.Fatal("expected block to be rejected when the value is already in allow")
		}
		cfg := loadRulesTestConfig(t, path)
		if len(cfg.Block) != 0 {
			t.Fatalf("expected the rejected block entry to never be persisted, got %+v", cfg.Block)
		}
		if len(cfg.Allow) != 1 {
			t.Fatalf("expected the original allow entry untouched, got %+v", cfg.Allow)
		}
	})

	t.Run("block-then-allow", func(t *testing.T) {
		path := rulesTestPath(t)
		if err := addRuleValueCore(path, ruleAddRequest{Value: "pan"}); err != nil {
			t.Fatal(err)
		}
		err := addRuleValueCore(path, ruleAddRequest{Value: "pan", Allow: true})
		if err == nil {
			t.Fatal("expected allow to be rejected when the value is already in block")
		}
		cfg := loadRulesTestConfig(t, path)
		if len(cfg.Allow) != 0 {
			t.Fatalf("expected the rejected allow entry to never be persisted, got %+v", cfg.Allow)
		}
		if len(cfg.Block) != 1 {
			t.Fatalf("expected the original block entry untouched, got %+v", cfg.Block)
		}
	})
}

func TestAddRuleValueCore_WarnsButStillAddsOnCategoryNameCollision(t *testing.T) {
	path := rulesTestPath(t)
	out := captureStdout(t, func() {
		if err := addRuleValueCore(path, ruleAddRequest{Value: "pan"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "india_pii.pan") {
		t.Errorf("expected a hint pointing at the india_pii.pan category, got: %s", out)
	}
	cfg := loadRulesTestConfig(t, path)
	if len(cfg.Block) != 1 {
		t.Fatalf("expected the value to still be added despite the warning, got %+v", cfg.Block)
	}
}

func TestAddRuleValueCore_InvalidRegexRejected(t *testing.T) {
	path := rulesTestPath(t)
	if err := addRuleValueCore(path, ruleAddRequest{Value: "(unclosed", Regex: true}); err == nil {
		t.Fatal("expected an invalid regex to be rejected")
	}
}

// --- remove -------------------------------------------------------------

func TestRemoveRuleValueCore_RemovesFromBothListsWhenInBoth(t *testing.T) {
	path := rulesTestPath(t)
	cfg := &rules.Config{
		Block: []rules.Entry{{Value: "pan"}},
		Allow: []rules.Entry{{Value: "pan"}},
	}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}

	if err := removeRuleValueCore(path, "pan"); err != nil {
		t.Fatal(err)
	}
	cfg = loadRulesTestConfig(t, path)
	if len(cfg.Block) != 0 || len(cfg.Allow) != 0 {
		t.Fatalf("expected both lists empty after remove, got block=%+v allow=%+v", cfg.Block, cfg.Allow)
	}
}

func TestRemoveRuleValueCore_NotFoundErrors(t *testing.T) {
	path := rulesTestPath(t)
	if err := removeRuleValueCore(path, "never-added"); err == nil {
		t.Fatal("expected an error removing a value that was never added")
	}
}

// --- matchesKnownCategoryName --------------------------------------------

func TestMatchesKnownCategoryName(t *testing.T) {
	if cat, ok := matchesKnownCategoryName("pan"); !ok || cat != "india_pii.pan" {
		t.Errorf("expected pan -> india_pii.pan, got %q, %v", cat, ok)
	}
	if cat, ok := matchesKnownCategoryName("PAN"); !ok || cat != "india_pii.pan" {
		t.Errorf("expected case-insensitive match, got %q, %v", cat, ok)
	}
	if cat, ok := matchesKnownCategoryName("wellknown_platforms"); !ok || cat != "allowlist.wellknown_platforms" {
		t.Errorf("expected wellknown_platforms -> allowlist.wellknown_platforms, got %q, %v", cat, ok)
	}
	if _, ok := matchesKnownCategoryName("XyzExampleCorp"); ok {
		t.Error("expected no match for an unrelated value")
	}
}

// --- rules show: shadow-flagging -----------------------------------------

func TestShowRulesCore_FlagsShadowedBlockEntry(t *testing.T) {
	path := rulesTestPath(t)
	// Construct this state directly (bypassing addRuleValueCore's own
	// reject-on-conflict check) to simulate a stale pre-existing
	// contradictory pair.
	cfg := &rules.Config{
		Block: []rules.Entry{{Value: "pan"}},
		Allow: []rules.Entry{{Value: "pan"}},
	}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := showRulesCore("test-engagement", path); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "NO effect") {
		t.Errorf("expected the shadowed block entry to be flagged, got: %s", out)
	}
}

// --- rulesAdd usage error ---------------------------------------------

func TestRulesAdd_FlagAfterValueErrorExplainsOrdering(t *testing.T) {
	// Value-before-flags means the flag package stops parsing at the
	// value, so -engagement is never seen and resolution falls back to
	// this folder's marker. It needs one, or the command fails on "no
	// engagement" before reaching the argument-ordering check this test
	// is about.
	t.Chdir(t.TempDir())
	if err := rememberEngagement("ordering-test"); err != nil {
		t.Fatal(err)
	}

	// Go's flag package stops parsing flags at the first non-flag
	// argument, so "-domain" typed after the value is left as a second,
	// unwanted positional argument here rather than being recognized as
	// a flag at all -- the error must name the actual fix (flags before
	// the value), not just repeat the usage string a confused operator
	// already failed to satisfy once.
	err := rulesAdd([]string{"widgetcorp.do", "-domain"}, false)
	if err == nil {
		t.Fatal("expected a usage error, got nil")
	}
	if !strings.Contains(err.Error(), "flags must come before the value") {
		t.Errorf("expected the error to explain the ordering rule, got: %v", err)
	}
}

func TestRulesToggleCategory_FlagAfterValueErrorExplainsOrdering(t *testing.T) {
	// Value-before-flags means the flag package stops parsing at the
	// value, so -engagement is never seen and resolution falls back to
	// this folder's marker. It needs one, or the command fails on "no
	// engagement" before reaching the argument-ordering check this test
	// is about.
	t.Chdir(t.TempDir())
	if err := rememberEngagement("ordering-test"); err != nil {
		t.Fatal(err)
	}

	err := rulesToggleCategory([]string{"cloud.aws", "-engagement", "foo"}, true)
	if err == nil {
		t.Fatal("expected a usage error, got nil")
	}
	if !strings.Contains(err.Error(), "flags must come before the value") {
		t.Errorf("expected the error to explain the ordering rule, got: %v", err)
	}
}

func TestRulesRemove_FlagAfterValueErrorExplainsOrdering(t *testing.T) {
	// Value-before-flags means the flag package stops parsing at the
	// value, so -engagement is never seen and resolution falls back to
	// this folder's marker. It needs one, or the command fails on "no
	// engagement" before reaching the argument-ordering check this test
	// is about.
	t.Chdir(t.TempDir())
	if err := rememberEngagement("ordering-test"); err != nil {
		t.Fatal(err)
	}

	err := rulesRemove([]string{"widgetcorp.do", "-engagement", "foo"})
	if err == nil {
		t.Fatal("expected a usage error, got nil")
	}
	if !strings.Contains(err.Error(), "flags must come before the value") {
		t.Errorf("expected the error to explain the ordering rule, got: %v", err)
	}
}

func TestRunRules_FlagImmediatelyAfterRulesExplainsMissingSubcommand(t *testing.T) {
	// "redactproxy rules -engagement foo" (forgot the subcommand word
	// entirely) must not be reported as "unknown rules subcommand
	// \"-engagement\"" -- that reads as if "-engagement" itself were the
	// problem, not that a subcommand was never given.
	err := runRules([]string{"-engagement", "foo"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "no rules subcommand given") {
		t.Errorf("expected the error to say no subcommand was given, got: %v", err)
	}
}

// --- aOrAn ----------------------------------------------------------------

func TestAOrAn(t *testing.T) {
	if got := aOrAn("allow"); got != "n" {
		t.Errorf("aOrAn(%q) = %q, want %q", "allow", got, "n")
	}
	if got := aOrAn("block"); got != "" {
		t.Errorf("aOrAn(%q) = %q, want %q", "block", got, "")
	}
}
