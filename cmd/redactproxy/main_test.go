package main

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/redact"
	"github.com/CSPF-Founder/redactproxy/internal/rules"
)

func TestEngagementFromMarker_NoMarkerYet(t *testing.T) {
	t.Chdir(t.TempDir())
	_, ok, err := engagementFromMarker()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected ok=false with no marker file present")
	}
}

func TestRememberEngagement_RoundTrip(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := rememberEngagement("xyz-example-corp"); err != nil {
		t.Fatal(err)
	}
	name, ok, err := engagementFromMarker()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || name != "xyz-example-corp" {
		t.Fatalf("expected (\"xyz-example-corp\", true), got (%q, %v)", name, ok)
	}
}

func TestRememberEngagement_OverwritesPreviousValue(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := rememberEngagement("first-client"); err != nil {
		t.Fatal(err)
	}
	if err := rememberEngagement("second-client"); err != nil {
		t.Fatal(err)
	}
	name, _, err := engagementFromMarker()
	if err != nil {
		t.Fatal(err)
	}
	if name != "second-client" {
		t.Fatalf("expected the marker updated to the latest value, got %q", name)
	}
}

func TestResolveEngagement_ExplicitWritesMarkerForNextTime(t *testing.T) {
	t.Chdir(t.TempDir())
	got, err := resolveEngagement("xyz-example-corp")
	if err != nil {
		t.Fatal(err)
	}
	if got != "xyz-example-corp" {
		t.Fatalf("expected xyz-example-corp, got %q", got)
	}
	// A SECOND call with no explicit value should now pick up what the
	// first call remembered -- this is the actual point of the feature.
	got2, err := resolveEngagement("")
	if err != nil {
		t.Fatal(err)
	}
	if got2 != "xyz-example-corp" {
		t.Fatalf("expected the marker to carry over to a call with no explicit -engagement, got %q", got2)
	}
}

func TestResolveEngagement_NoExplicitNoMarker_ErrorsRatherThanDefaulting(t *testing.T) {
	t.Chdir(t.TempDir())
	_, err := resolveEngagement("")
	if err == nil {
		t.Fatal("expected an error rather than silently falling back to some default engagement name")
	}
}

func TestListExistingEngagements_EmptyWhenNoneExist(t *testing.T) {
	names, err := listExistingEngagements(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("expected no engagements, got %v", names)
	}
}

func TestListExistingEngagements_ReturnsSortedNames(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"zebra-corp", "xyz-example-corp", "mid-corp"} {
		if _, err := engagementDir(base, name); err != nil {
			t.Fatal(err)
		}
	}
	names, err := listExistingEngagements(base)
	if err != nil {
		t.Fatal(err)
	}
	// Created in the order zebra, xyz-example, mid above; expected back
	// in lexical order, which is none of insertion, reverse-insertion,
	// or filesystem order, so this still fails if the sort is dropped.
	want := []string{"mid-corp", "xyz-example-corp", "zebra-corp"}
	if len(names) != len(want) {
		t.Fatalf("got %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("got %v, want %v", names, want)
		}
	}
}

// TestRun_TopLevelHelpVariantsPrintUsageAndExitZero runs each help
// variant as a REAL SUBPROCESS, deliberately not calling run(args)
// in-process. All four forms delegate to runProxy(["-h"]) so the actual
// flag list (-debug-level etc.) prints alongside the subcommand
// overview (see run()'s "-h" case), and flag.Parse under ExitOnError
// calls os.Exit(0) directly the moment it sees "-h". Calling that
// in-process would kill the whole `go test` binary, not fail one test
// case, so this MUST stay a subprocess test.
func TestRun_TopLevelHelpVariantsPrintUsageAndExitZero(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "redactproxy_helptest")
	build := exec.Command("go", "build", "-o", bin, "github.com/CSPF-Founder/redactproxy/cmd/redactproxy")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	for _, arg := range []string{"-h", "-help", "--help", "help"} {
		cmd := exec.Command(bin, arg)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("redactproxy %s: expected exit 0, got error %v (output: %s)", arg, err, out)
			continue
		}
		if !strings.Contains(string(out), "redactproxy: local redaction proxy") {
			t.Errorf("redactproxy %s: missing the top-level overview, got: %s", arg, out)
		}
		if !strings.Contains(string(out), "-debug-level string") {
			t.Errorf("redactproxy %s: missing the actual proxy flag list (e.g. -debug-level), got: %s", arg, out)
		}
	}
}

// TestRun_VersionVariantsExitZero pins `version`, `-version`, and
// `--version` as interchangeable and non-erroring. SECURITY.md asks
// reporters to confirm which build they saw a leak on, so this needs to
// answer from any directory, including one with no engagement marker
// (chdir to an empty temp dir below) where starting the proxy itself
// would fail.
func TestRun_VersionVariantsExitZero(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, arg := range []string{"version", "-version", "--version"} {
		if err := run([]string{arg}); err != nil {
			t.Errorf("redactproxy %s: expected no error, got %v", arg, err)
		}
	}
}

// TestVersionString_FallsBackWhenUnstamped covers the ordinary-build
// path, where no -ldflags stamp exists. Under `go test` the build info
// records an empty main module version, so this exercises the final
// fallback rather than returning an empty string to the user.
func TestVersionString_FallsBackWhenUnstamped(t *testing.T) {
	if got := versionString(); got == "" {
		t.Error("versionString() returned an empty string; it should always name something")
	}

	orig := version
	t.Cleanup(func() { version = orig })
	version = "v9.9.9"
	if got := versionString(); got != "v9.9.9" {
		t.Errorf("a linker stamp should win over build info, got %q", got)
	}
}

func TestRunRules_NoArgsPrintsUsageWithoutError(t *testing.T) {
	if err := runRules(nil); err != nil {
		t.Errorf("expected no error from `redactproxy rules` with no arguments (just usage), got %v", err)
	}
}

func TestRunRules_HelpVariantsPrintUsageWithoutError(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-help"}, {"--help"}, {"help"}} {
		if err := runRules(args); err != nil {
			t.Errorf("runRules(%v): expected no error (just printed usage), got %v", args, err)
		}
	}
}

func TestRunRules_UnknownSubcommandStillErrors(t *testing.T) {
	if err := runRules([]string{"bogus"}); err == nil {
		t.Fatal("expected an error for a genuinely unknown rules subcommand")
	}
}

func TestRun_UnknownBareSubcommandErrorsRatherThanStartingProxy(t *testing.T) {
	for _, typo := range []string{"rulez", "wizrd", "tokns", "bogus"} {
		err := run([]string{typo})
		if err == nil {
			t.Errorf("run([%q]): expected an error rather than silently starting the proxy, got nil", typo)
			continue
		}
		if !strings.Contains(err.Error(), typo) {
			t.Errorf("run([%q]): expected error to mention the unrecognized word, got: %v", typo, err)
		}
	}
}

func TestRun_LeadingDashArgFallsThroughToProxyNotTreatedAsUnknownSubcommand(t *testing.T) {
	// A leading "-flag" (not a bare word) must still reach runProxy's own
	// logic rather than being rejected here as an unknown subcommand --
	// this is what distinguishes "redactproxy -engagement ..." (a real
	// flag) from "redactproxy rulez" (a typo'd subcommand). Uses
	// "-engagement" with a path-traversal value so runProxy returns a
	// genuine error (rather than flag.ExitOnError terminating the test
	// process on a truly unrecognized flag name).
	err := run([]string{"-engagement", "../evil"})
	if err == nil {
		t.Fatal("expected an error (path traversal in -engagement), but it should come from runProxy, not the subcommand switch")
	}
	if strings.Contains(err.Error(), "unknown subcommand") {
		t.Errorf("a leading-dash argument should never be reported as an \"unknown subcommand\", got: %v", err)
	}
}

func TestRunProxy_LeftoverPositionalArgsRejectedRatherThanSilentlyStartingProxy(t *testing.T) {
	// A subcommand typed after flags instead of before (e.g. "redactproxy
	// -engagement foo rules show") leaves "rules show" as leftover
	// positional arguments once Go's flag package stops parsing at
	// "-engagement foo" -- run()'s own subcommand switch never sees them,
	// since args[0] here is "-engagement", not "rules". Must error rather
	// than silently starting a live listening proxy for a command the
	// operator meant as a read-only inspection.
	err := run([]string{"-engagement", "leftovertest", "rules", "show"})
	if err == nil {
		t.Fatal("expected an error for leftover positional arguments, got nil")
	}
	if !strings.Contains(err.Error(), "rules") || !strings.Contains(err.Error(), "show") {
		t.Errorf("expected the error to name the leftover arguments, got: %v", err)
	}
}

func TestRunProxy_UpstreamRejectsNonHTTPScheme(t *testing.T) {
	// -engagement writes a .redactproxy-engagement marker into the
	// working directory; keep that out of the package source tree.
	t.Chdir(t.TempDir())

	dir := t.TempDir()
	err := runProxy([]string{"-data-dir", dir, "-engagement", "schematest", "-upstream", "ftp://api.example.com"})
	if err == nil {
		t.Fatal("expected an error for a non-http(s) -upstream scheme, got nil")
	}
	if !strings.Contains(err.Error(), "http or https") {
		t.Errorf("expected the error to explain http/https is required, got: %v", err)
	}
}

// TestCheckMiBFlag_RejectsBothEndsOfTheRange covers the size flags whose
// consumers (proxyserver.New, debuglog.NewRotatingWriter) both treat a
// non-positive byte count as "use the built-in default" rather than as
// an error. That makes a bad value here silent by default, in both
// directions: negative outright, and large enough that << 20 wraps past
// int64 and lands negative. Either way the proxy would start with a
// limit the operator didn't ask for and no indication of it.
func TestCheckMiBFlag_RejectsBothEndsOfTheRange(t *testing.T) {
	const defaultMiB = 64

	for _, tc := range []struct {
		name string
		mib  int64
		want string
	}{
		{"negative", -1, "must not be negative"},
		{"overflows int64 when shifted to bytes", maxMiBFlagValue + 1, "too large"},
		{"max int64, the worst overflow case", math.MaxInt64, "too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMiBFlag("--max-body-mb", tc.mib, defaultMiB)
			if err == nil {
				t.Fatalf("expected %d MiB to be rejected, got nil", tc.mib)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected the error to mention %q, got: %v", tc.want, err)
			}
		})
	}

	// The whole usable range still has to pass, including 0, which
	// legitimately means "use the default".
	for _, mib := range []int64{0, 1, 64, 1024, maxMiBFlagValue} {
		if err := checkMiBFlag("--max-body-mb", mib, defaultMiB); err != nil {
			t.Errorf("expected %d MiB to be accepted, got: %v", mib, err)
		}
		if got := mib << 20; mib > 0 && got <= 0 {
			t.Errorf("%d MiB is accepted but overflows to %d bytes", mib, got)
		}
	}
}

func TestRunProxy_RejectsOverflowingMaxBodyMB(t *testing.T) {
	t.Chdir(t.TempDir())

	err := runProxy([]string{"-data-dir", t.TempDir(), "-engagement", "overflowtest", "-max-body-mb", "9223372036854775807"})
	if err == nil {
		t.Fatal("expected an error rather than a silent fallback to the default body limit")
	}
	if !strings.Contains(err.Error(), "--max-body-mb") {
		t.Errorf("expected the error to name the offending flag, got: %v", err)
	}
}

func TestProjectAlreadyConfiguredFor(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if projectAlreadyConfiguredFor("127.0.0.1:8787") {
		t.Fatal("expected false with no .claude/settings.local.json at all")
	}

	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(dir, ".claude", "settings.local.json")
	if err := os.WriteFile(settingsPath, []byte(`{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:9999"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if projectAlreadyConfiguredFor("127.0.0.1:8787") {
		t.Fatal("expected false when the configured address doesn't match this run's -listen address")
	}
	if !projectAlreadyConfiguredFor("127.0.0.1:9999") {
		t.Fatal("expected true when the configured address matches")
	}

	if err := os.WriteFile(settingsPath, []byte(`not valid json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if projectAlreadyConfiguredFor("127.0.0.1:9999") {
		t.Fatal("expected false (safe default) for invalid JSON, not a crash or a false positive")
	}
}

func TestMissingSecuritySettings(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	missing := missingSecuritySettings()
	wantCount := len(toolDenyRules) + len(quietEnvDefaults) + 2 // + disableRemoteControl + skipWebFetchPreflight
	if len(missing) != wantCount {
		t.Fatalf("expected all %d settings reported missing with no settings.local.json at all, got %d: %+v", wantCount, len(missing), missing)
	}

	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(dir, ".claude", "settings.local.json")
	if err := os.WriteFile(settingsPath, []byte(`{"permissions":{"deny":["Read(/some/path)"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	missing = missingSecuritySettings()
	for _, m := range missing {
		if strings.Contains(m, "Read(/some/path)") {
			t.Fatalf("did not expect an unrelated existing deny rule reported as missing: %+v", missing)
		}
	}
	if len(missing) != wantCount {
		t.Fatalf("expected still all %d settings reported missing (irrelevant deny rule present), got %d: %+v", wantCount, len(missing), missing)
	}

	// A fully wizard-configured file reports nothing missing.
	full := map[string]any{
		"disableRemoteControl":  true,
		"skipWebFetchPreflight": true,
		"permissions":           map[string]any{"deny": toolDenyRules},
		"env":                   quietEnvDefaults,
	}
	data, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if missing := missingSecuritySettings(); len(missing) != 0 {
		t.Fatalf("expected nothing missing for a fully wizard-configured file, got: %+v", missing)
	}

	if err := os.WriteFile(settingsPath, []byte(`not valid json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if missing := missingSecuritySettings(); len(missing) != wantCount {
		t.Fatalf("expected everything reported missing (safe default) for invalid JSON, not a crash, got %d: %+v", len(missing), missing)
	}
}

func TestIsLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8787", true},
		{"localhost:8787", true},
		{"[::1]:8787", true},
		{":8787", false}, // empty host binds ALL interfaces (net.Listen("tcp", ":8787") -> reports its own addr as [::]:8787, confirmed live, reachable from other hosts) -- must never be treated as loopback-safe, this is the exact bug that shipped when it was
		{"0.0.0.0:8787", false},
		{"[::]:8787", false},
		{"192.168.1.5:8787", false},
		{"8.8.8.8:8787", false},
	}
	for _, tc := range cases {
		if got := isLoopback(tc.addr); got != tc.want {
			t.Errorf("isLoopback(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestMergeCLIDisabled_AddsWithoutMutatingOriginal(t *testing.T) {
	orig := &rules.Config{Categories: map[string]rules.CategoryState{"cloud.aws": {Enabled: false}}}
	merged := mergeCLIDisabled(orig, []string{"network.mac"})

	if len(orig.Categories) != 1 {
		t.Fatalf("mergeCLIDisabled must not mutate its input, but orig.Categories is now %v", orig.Categories)
	}
	if len(merged.Categories) != 2 {
		t.Fatalf("expected 2 categories in the merged config, got %v", merged.Categories)
	}
	if merged.Categories["network.mac"].Enabled {
		t.Fatalf("expected the CLI-disabled category to be disabled, got %+v", merged.Categories["network.mac"])
	}
}

func TestMergeCLIDisabled_EmptyCLIListReturnsSameConfig(t *testing.T) {
	orig := &rules.Config{Categories: map[string]rules.CategoryState{"cloud.aws": {Enabled: false}}}
	merged := mergeCLIDisabled(orig, nil)
	if merged != orig {
		t.Fatal("expected the exact same Config pointer back when there's nothing to merge")
	}
}

func TestBuildDetectors_RespectsDisabledAndBlockList(t *testing.T) {
	compiled := &rules.Compiled{
		Disabled: map[string]bool{"cloud.aws": true},
	}
	cfg := &rules.Config{Block: []rules.Entry{{Value: "XyzExampleCorp"}}}
	c, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	compiled.Block = c.Block

	dets := buildDetectors(compiled)

	// One fewer than the full default set (AWS disabled) plus one block detector.
	wantCount := len(redact.DefaultDetectors()) - 1 + 1
	if len(dets) != wantCount {
		t.Fatalf("expected %d detectors, got %d", wantCount, len(dets))
	}
}

func TestWarnIfCWDMayLeak_MatchingPathReportsEachMatch(t *testing.T) {
	cfg := &rules.Config{Block: []rules.Entry{
		{Value: "WidgetCorp"},
		{Value: "Widget"}, // deliberately also matches (substring of WidgetCorp), to confirm every match is reported, not just the first
		{Value: "Unrelated"},
	}}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	warnIfCWDMayLeak("/home/user/engagements/Widgetcorp", compiled, func(matched, pattern string) {
		if matched != "/home/user/engagements/Widgetcorp" {
			t.Errorf("matched = %q, want the cwd passed in", matched)
		}
		got = append(got, pattern)
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 matching patterns (WidgetCorp, Widget), got %d: %v", len(got), got)
	}
}

func TestWarnIfCWDMayLeak_NoMatchNoWarning(t *testing.T) {
	cfg := &rules.Config{Block: []rules.Entry{{Value: "XyzExampleCorp"}}}
	compiled, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}

	called := false
	warnIfCWDMayLeak("/home/user/engagements/case-4471", compiled, func(matched, pattern string) {
		called = true
	})
	if called {
		t.Fatal("expected no warning for a cwd that matches nothing in the block list")
	}
}

func TestWarnIfCWDMayLeak_EmptyBlockListNoWarning(t *testing.T) {
	compiled := &rules.Compiled{}
	called := false
	warnIfCWDMayLeak("/home/user/engagements/anything", compiled, func(matched, pattern string) {
		called = true
	})
	if called {
		t.Fatal("expected no warning when there are no block entries at all")
	}
}

func TestEngagementDir_CreatesDirectory(t *testing.T) {
	base := t.TempDir()
	dir, err := engagementDir(base, "xyz-example-corp")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "engagements", "xyz-example-corp")
	if dir != want {
		t.Fatalf("got %q, want %q", dir, want)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("expected the directory to have been created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected a directory, not a file")
	}
}

// TestEngagementDir_RejectsPathTraversal confirms an engagement name
// like "../../../../tmp/escaped-engagement" is rejected rather than
// passed straight through filepath.Join, which would land its entire
// tokens.db/rules.json/debug.log OUTSIDE -data-dir entirely: not a
// cross-engagement collision, an arbitrary-path write anywhere the
// process has permission to create directories.
func TestEngagementDir_RejectsPathTraversal(t *testing.T) {
	base := t.TempDir()
	cases := []string{
		"../../../../tmp/escaped-engagement",
		"../sibling",
		"a/b",
		`a\b`,
		"..",
		".",
		"",
		"/etc/passwd",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := engagementDir(base, name); err == nil {
				t.Fatalf("expected engagementDir to reject %q, got no error", name)
			}
		})
	}
}

func TestEngagementDir_AcceptsOrdinaryNames(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"xyz-example-corp", "vapt_test1", "A1", "client-2026"} {
		if _, err := engagementDir(base, name); err != nil {
			t.Errorf("expected %q to be accepted, got %v", name, err)
		}
	}
}

// TestResolveEngagement_RejectsPathTraversalBeforeWritingMarker checks
// the second half of the same fix: resolveEngagement must reject an
// invalid name BEFORE calling rememberEngagement, not after; writing
// a bad name to .redactproxy-engagement first would break every
// subsequent command run from this folder (with no explicit
// -engagement) until someone noticed and fixed the marker by hand.
func TestResolveEngagement_RejectsPathTraversalBeforeWritingMarker(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if _, err := resolveEngagement("../../evil"); err == nil {
		t.Fatal("expected resolveEngagement to reject a path-traversal engagement name")
	}
	if _, err := os.Stat(filepath.Join(dir, engagementMarkerFile)); !os.IsNotExist(err) {
		t.Fatalf("expected no marker file to have been written for a rejected name, stat err: %v", err)
	}
}

func TestRulesPathFor(t *testing.T) {
	base := t.TempDir()
	path, err := rulesPathFor(base, "xyz-example-corp")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "engagements", "xyz-example-corp", "rules.json")
	if path != want {
		t.Fatalf("got %q, want %q", path, want)
	}
}

func TestRunMemory_WriteAppendsSnippetToNewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CLAUDE.md")
	if err := runMemory([]string{"-write", path}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Redaction proxy active") {
		t.Fatalf("expected the snippet's heading in the written file, got: %s", data)
	}
	if !strings.Contains(string(data), "tok1a2b3c4d5e6f7890.com") {
		t.Fatalf("expected the domain token example in the written file, got: %s", data)
	}
}

func TestRunMemory_WriteAppendsRatherThanOverwritesExistingContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CLAUDE.md")
	existing := "# Project notes\n\nSome existing content that must survive.\n"
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMemory([]string{"-write", path}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Some existing content that must survive.") {
		t.Fatalf("expected existing content preserved, got: %s", data)
	}
	if !strings.Contains(string(data), "Redaction proxy active") {
		t.Fatalf("expected the snippet appended, got: %s", data)
	}
}

func TestRunMemory_PrintModeDoesNotError(t *testing.T) {
	if err := runMemory(nil); err != nil {
		t.Fatal(err)
	}
}

func TestIsAllowlistCategory(t *testing.T) {
	cases := map[string]bool{
		"allowlist":                           true,
		"allowlist.wellknown_platforms":       true,
		"allowlist.security_testing_services": true,
		"cloud.aws":                           false,
		"contact.phone":                       false,
		"allowlisted_but_not_actually":        false,
	}
	for name, want := range cases {
		if got := isAllowlistCategory(name); got != want {
			t.Errorf("isAllowlistCategory(%q) = %v, want %v", name, got, want)
		}
	}
}
