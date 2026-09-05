package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/rules"
)

func TestPromptForEngagement_NoExisting_AcceptsTypedName(t *testing.T) {
	dataDir := t.TempDir()
	r := bufio.NewReader(strings.NewReader("xyz-example-corp\n"))
	got, err := promptForEngagement(r, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "xyz-example-corp" {
		t.Fatalf("expected xyz-example-corp, got %q", got)
	}
}

// TestPromptForEngagement_RejectsPathTraversalThenRetries is the
// wizard-side half of the path-traversal fix: typing something like
// "../../evil" must be rejected with a re-prompt, not accepted and
// passed downstream to engagementDir (which would also reject it, but
// only after rememberEngagement already wrote the bad value to this
// folder's marker).
func TestPromptForEngagement_RejectsPathTraversalThenRetries(t *testing.T) {
	dataDir := t.TempDir()
	r := bufio.NewReader(strings.NewReader("../../evil\nxyz-example-corp\n"))
	got, err := promptForEngagement(r, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "xyz-example-corp" {
		t.Fatalf("expected the invalid name to be rejected and the retry accepted, got %q", got)
	}
}

func TestPromptForEngagement_PicksExistingByNumber(t *testing.T) {
	dataDir := t.TempDir()
	for _, name := range []string{"xyz-example-corp", "globex-corp"} {
		if _, err := engagementDir(dataDir, name); err != nil {
			t.Fatal(err)
		}
	}
	r := bufio.NewReader(strings.NewReader("2\n"))
	got, err := promptForEngagement(r, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	// The picker lists existing engagements sorted (see
	// listExistingEngagements), not in creation order, so entry #2 is
	// the lexically later of the two regardless of which was made first.
	if got != "xyz-example-corp" {
		t.Fatalf("expected xyz-example-corp (entry #2), got %q", got)
	}
}

func TestPromptForEngagement_OutOfRangeNumberRetries(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := engagementDir(dataDir, "xyz-example-corp"); err != nil {
		t.Fatal(err)
	}
	// "5" is out of range (only 1 entry) -- should re-prompt, then accept
	// the next line as a typed new name.
	r := bufio.NewReader(strings.NewReader("5\nbrand-new-client\n"))
	got, err := promptForEngagement(r, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "brand-new-client" {
		t.Fatalf("expected the retry to fall through to the typed name, got %q", got)
	}
}

func TestPromptForEngagement_TypedNameCollidingWithExisting_ConfirmReuses(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := engagementDir(dataDir, "xyz-example-corp"); err != nil {
		t.Fatal(err)
	}
	// Types the SAME name as the existing one (not picked by number),
	// then confirms "y" to the reuse prompt.
	r := bufio.NewReader(strings.NewReader("xyz-example-corp\ny\n"))
	got, err := promptForEngagement(r, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "xyz-example-corp" {
		t.Fatalf("expected xyz-example-corp after confirming reuse, got %q", got)
	}
}

func TestPromptForEngagement_TypedNameCollidingWithExisting_DeclineRetries(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := engagementDir(dataDir, "xyz-example-corp"); err != nil {
		t.Fatal(err)
	}
	// Types the existing name, declines the reuse confirmation ("n"),
	// then types a genuinely different name -- must fall through to that.
	r := bufio.NewReader(strings.NewReader("xyz-example-corp\nn\nbrand-new-client\n"))
	got, err := promptForEngagement(r, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "brand-new-client" {
		t.Fatalf("expected the retry after declining reuse to accept the next typed name, got %q", got)
	}
}

func TestPromptForEngagement_CanTypeNewNameEvenWithExistingList(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := engagementDir(dataDir, "xyz-example-corp"); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(strings.NewReader("totally-new-client\n"))
	got, err := promptForEngagement(r, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "totally-new-client" {
		t.Fatalf("expected the typed name to win over the existing list, got %q", got)
	}
}

func TestAppendClaudeMemoryIfAbsent_FirstCallWrites_SecondIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CLAUDE.md")

	wrote, err := appendClaudeMemoryIfAbsent(path)
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("expected the first call to write the snippet")
	}

	wrote, err = appendClaudeMemoryIfAbsent(path)
	if err != nil {
		t.Fatal(err)
	}
	if wrote {
		t.Fatal("expected the second call to be a no-op (already present)")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), claudeMemoryMarker); n != 1 {
		t.Fatalf("expected exactly 1 copy of the marker after two calls, got %d", n)
	}
}

func TestAppendClaudeMemoryIfAbsent_PreservesExistingContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CLAUDE.md")
	existing := "# Project notes\n\nSome content that must survive.\n"
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := appendClaudeMemoryIfAbsent(path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Some content that must survive.") {
		t.Fatalf("expected existing content preserved, got: %s", data)
	}
	if !strings.Contains(string(data), claudeMemoryMarker) {
		t.Fatalf("expected the snippet appended, got: %s", data)
	}
}

func TestOfferProjectSettings_FreshFile_WritesEnvBlock(t *testing.T) {
	cwd := t.TempDir()
	r := bufio.NewReader(strings.NewReader("y\n"))

	if !offerProjectSettings(r, cwd, "127.0.0.1:9999", filepath.Join(t.TempDir(), "debug.log"), nil, nil) {
		t.Fatal("expected offerProjectSettings to report success")
	}

	data, err := os.ReadFile(filepath.Join(cwd, ".claude", "settings.local.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	env, _ := settings["env"].(map[string]any)
	if env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:9999" {
		t.Fatalf("expected ANTHROPIC_BASE_URL set, got %+v", settings)
	}
	if settings["disableRemoteControl"] != true {
		t.Fatalf("expected disableRemoteControl: true, got %+v", settings)
	}
	if settings["skipWebFetchPreflight"] != true {
		t.Fatalf("expected skipWebFetchPreflight: true, got %+v", settings)
	}
	for _, want := range []string{"DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING", "DISABLE_FEEDBACK_COMMAND", "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"} {
		if env[want] != "1" {
			t.Fatalf("expected env.%s = \"1\", got %+v", want, env)
		}
	}
	perms, _ := settings["permissions"].(map[string]any)
	deny, _ := perms["deny"].([]any)
	for _, want := range []string{"Artifact", "RemoteTrigger", "PushNotification", "SendUserFile"} {
		found := false
		for _, d := range deny {
			if d == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a %s deny rule, got %+v", want, deny)
		}
	}
}

func TestOfferProjectSettings_ExistingFile_MergesWithoutClobbering(t *testing.T) {
	cwd := t.TempDir()
	settingsDir := filepath.Join(cwd, ".claude")
	if err := os.MkdirAll(settingsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := `{"env":{"SOME_OTHER_VAR":"keep-me"},"permissions":{"allow":["Bash(ls:*)"]}}`
	settingsPath := filepath.Join(settingsDir, "settings.local.json")
	if err := os.WriteFile(settingsPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(strings.NewReader("y\ny\n")) // one "already exists" prompt + one "proceed?" prompt
	if !offerProjectSettings(r, cwd, "127.0.0.1:9999", filepath.Join(t.TempDir(), "debug.log"), nil, nil) {
		t.Fatal("expected offerProjectSettings to report success")
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	env, _ := settings["env"].(map[string]any)
	if env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:9999" {
		t.Fatalf("expected ANTHROPIC_BASE_URL added, got %+v", settings)
	}
	if env["SOME_OTHER_VAR"] != "keep-me" {
		t.Fatalf("expected existing env entry preserved, got %+v", env)
	}
	perms, _ := settings["permissions"].(map[string]any)
	if perms == nil {
		t.Fatalf("expected existing permissions block preserved, got %+v", settings)
	}
	allow, _ := perms["allow"].([]any)
	if len(allow) != 1 || allow[0] != "Bash(ls:*)" {
		t.Fatalf("expected the existing allow rule preserved, got %+v", perms)
	}
	deny, _ := perms["deny"].([]any)
	if len(deny) != 5 {
		t.Fatalf("expected exactly five deny rules added (debug log + 4 tool rules), got %+v", perms)
	}
	sawDebugLogRule := false
	sawToolRule := map[string]bool{}
	for _, d := range deny {
		rule, _ := d.(string)
		if strings.HasPrefix(rule, "Read(//") && strings.HasSuffix(rule, "debug.log)") {
			sawDebugLogRule = true
		}
		sawToolRule[rule] = true
	}
	if !sawDebugLogRule {
		t.Fatalf("expected a Read(//<absolute path>) deny rule for the debug log, got %+v", deny)
	}
	for _, want := range []string{"Artifact", "RemoteTrigger", "PushNotification", "SendUserFile"} {
		if !sawToolRule[want] {
			t.Fatalf("expected a %s deny rule, got %+v", want, deny)
		}
	}
}

func TestOfferProjectSettings_RerunDoesNotDuplicateDenyRule(t *testing.T) {
	cwd := t.TempDir()
	debugLog := filepath.Join(t.TempDir(), "debug.log")

	r1 := bufio.NewReader(strings.NewReader("y\n"))
	if !offerProjectSettings(r1, cwd, "127.0.0.1:9999", debugLog, nil, nil) {
		t.Fatal("expected first run to succeed")
	}
	r2 := bufio.NewReader(strings.NewReader("y\ny\n"))
	if !offerProjectSettings(r2, cwd, "127.0.0.1:9999", debugLog, nil, nil) {
		t.Fatal("expected second run to succeed")
	}

	data, err := os.ReadFile(filepath.Join(cwd, ".claude", "settings.local.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	perms, _ := settings["permissions"].(map[string]any)
	deny, _ := perms["deny"].([]any)
	if len(deny) != 5 {
		t.Fatalf("expected exactly five deny rules after re-running the wizard twice, got %d: %+v", len(deny), deny)
	}
}

func TestOfferProjectSettings_DeclineAtTopLevel_LeavesFileUntouched(t *testing.T) {
	cwd := t.TempDir()
	r := bufio.NewReader(strings.NewReader("n\n"))

	if offerProjectSettings(r, cwd, "127.0.0.1:9999", filepath.Join(t.TempDir(), "debug.log"), nil, nil) {
		t.Fatal("expected offerProjectSettings to report declined")
	}
	if _, err := os.Stat(filepath.Join(cwd, ".claude", "settings.local.json")); !os.IsNotExist(err) {
		t.Fatal("expected no settings file to be created when declined")
	}
}

func TestOfferProviderSettings_BareEnterDefaultsToClaudeNoUpstream(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("\n")) // bare Enter -> default (option 1, Claude)
	upstream, env, remove := offerProviderSettings(r, "")
	if upstream != "" {
		t.Fatalf("expected empty upstream for real Claude, got %q", upstream)
	}
	if env != nil {
		t.Fatalf("expected no env vars to set for real Claude, got %+v", env)
	}
	if len(remove) == 0 {
		t.Fatal("expected picking Claude to return the provider env keys for cleanup")
	}
}

func TestOfferProviderSettings_ExplicitClaudeChoice(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("1\n"))
	upstream, env, remove := offerProviderSettings(r, zaiUpstreamURL)
	if upstream != "" {
		t.Fatalf("expected empty upstream for real Claude, got %q", upstream)
	}
	if env != nil {
		t.Fatalf("expected no env vars to set for real Claude, got %+v", env)
	}
	if len(remove) == 0 {
		t.Fatal("expected picking Claude to return the provider env keys for cleanup")
	}
}

func TestOfferProviderSettings_UnrecognizedChoiceWarnsAndDefaultsToClaude(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("99999\n"))
	var upstream string
	var remove []string
	out := captureStdout(t, func() {
		upstream, _, remove = offerProviderSettings(r, "")
	})
	if upstream != "" {
		t.Fatalf("expected empty upstream (Claude default) for an unrecognized choice, got %q", upstream)
	}
	if len(remove) == 0 {
		t.Fatal("expected the Claude default's env cleanup keys")
	}
	if !strings.Contains(out, `"99999"`) || !strings.Contains(out, "not recognized") {
		t.Errorf("expected a visible warning naming the unrecognized input, got: %s", out)
	}
}

func TestPromptYesNo_BareEnterUsesDefaultSilently(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("\n"))
	var got bool
	out := captureStdout(t, func() {
		got = promptYesNo(r, "question?", true)
	})
	if !got {
		t.Fatal("expected bare Enter to use the default (true)")
	}
	if strings.Contains(out, "not recognized") {
		t.Errorf("bare Enter is expected input, not unrecognized -- should not warn: %s", out)
	}
}

func TestPromptYesNo_UnrecognizedInputWarnsAndTreatsAsNo(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("abc\n"))
	var got bool
	out := captureStdout(t, func() {
		got = promptYesNo(r, "question?", true)
	})
	if got {
		t.Fatal("expected unrecognized input to be treated as no, even with defaultYes=true")
	}
	if !strings.Contains(out, `"abc"`) || !strings.Contains(out, "not recognized") {
		t.Errorf("expected a visible warning naming the unrecognized input, got: %s", out)
	}
}

func TestPromptYesNo_ExplicitNoDoesNotWarn(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("n\n"))
	var got bool
	out := captureStdout(t, func() {
		got = promptYesNo(r, "question?", true)
	})
	if got {
		t.Fatal("expected explicit 'n' to be no")
	}
	if strings.Contains(out, "not recognized") {
		t.Errorf("explicit 'n' is a recognized answer -- should not warn: %s", out)
	}
}

func TestOfferProviderSettings_ZAI_HardcodesEverythingButTheKey(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("2\nsecret-token\n"))
	upstream, env, remove := offerProviderSettings(r, "")
	if upstream != zaiUpstreamURL {
		t.Fatalf("expected the hardcoded z.ai upstream, got %q", upstream)
	}
	if env["ANTHROPIC_AUTH_TOKEN"] != "secret-token" {
		t.Fatalf("expected the typed token as ANTHROPIC_AUTH_TOKEN, got %+v", env)
	}
	if env["ANTHROPIC_API_KEY"] != "" {
		t.Fatalf("expected ANTHROPIC_API_KEY blanked, got %+v", env)
	}
	for _, k := range providerPrimaryModelEnvKeys {
		if env[k] != zaiPrimaryModel {
			t.Fatalf("expected primary key %s = %s, got %+v", k, zaiPrimaryModel, env)
		}
	}
	for _, k := range providerBackgroundModelEnvKeys {
		if env[k] != zaiBackgroundModel {
			t.Fatalf("expected background key %s = %s, got %+v", k, zaiBackgroundModel, env)
		}
	}
	if env["API_TIMEOUT_MS"] != zaiAPITimeoutMS {
		t.Fatalf("expected API_TIMEOUT_MS = %s, got %+v", zaiAPITimeoutMS, env)
	}
	if env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] != zaiAutoCompactWindow {
		t.Fatalf("expected CLAUDE_CODE_AUTO_COMPACT_WINDOW = %s, got %+v", zaiAutoCompactWindow, env)
	}
	if _, ok := env["CLAUDE_CODE_SUBAGENT_MODEL"]; ok {
		t.Fatalf("expected CLAUDE_CODE_SUBAGENT_MODEL NOT set (not in z.ai's own published config, and it overrides subagent frontmatter), got %+v", env)
	}
	if len(remove) != len(providerEnvKeys) {
		t.Fatalf("expected picking z.ai to return providerEnvKeys as its removal baseline too (so switching from a different provider can't leave stale values), got %+v", remove)
	}
}

// TestOfferProviderSettings_ZAI_BlankKeyPreservesExistingToken is a
// regression test: re-running the wizard against an already-working
// z.ai setup and leaving the key prompt blank (a reasonable "I don't
// need to retype something already configured" assumption) used to
// silently include ANTHROPIC_AUTH_TOKEN in the removal set regardless,
// deleting a real working credential with no warning -- the next
// `redactproxy` start would send zero auth to z.ai.
func TestOfferProviderSettings_ZAI_BlankKeyPreservesExistingToken(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("2\n\n")) // z.ai, blank key
	_, env, remove := offerProviderSettings(r, zaiUpstreamURL)
	if _, ok := env["ANTHROPIC_AUTH_TOKEN"]; ok {
		t.Fatalf("expected no ANTHROPIC_AUTH_TOKEN in envSet when no key was typed, got %+v", env)
	}
	for _, k := range remove {
		if k == "ANTHROPIC_AUTH_TOKEN" {
			t.Fatalf("expected ANTHROPIC_AUTH_TOKEN excluded from the removal set when no key was typed (must preserve an existing one), got remove=%+v", remove)
		}
	}
	// Everything else z.ai always sets/removes should be unaffected.
	if env["ANTHROPIC_API_KEY"] != "" {
		t.Fatalf("expected ANTHROPIC_API_KEY still blanked regardless, got %+v", env)
	}
	foundModelRemoval := false
	for _, k := range remove {
		if k == "ANTHROPIC_DEFAULT_OPUS_MODEL" {
			foundModelRemoval = true
		}
	}
	if !foundModelRemoval {
		t.Fatalf("expected the rest of providerEnvKeys still present in the removal set, got %+v", remove)
	}
}

// TestOfferProjectSettings_ZAI_BlankKeyRerun_ActuallyPreservesFileOnDisk
// is the same regression, exercised end-to-end through offerProjectSettings
// against a real settings file, confirming the on-disk credential
// survives a blank-key wizard re-run rather than just checking the
// returned maps in isolation.
func TestOfferProjectSettings_ZAI_BlankKeyRerun_ActuallyPreservesFileOnDisk(t *testing.T) {
	cwd := t.TempDir()

	r1 := bufio.NewReader(strings.NewReader("2\nreal-working-key\n"))
	_, env1, remove1 := offerProviderSettings(r1, "")
	if !offerProjectSettings(bufio.NewReader(strings.NewReader("y\n")), cwd, "127.0.0.1:9999", filepath.Join(t.TempDir(), "debug.log"), env1, remove1) {
		t.Fatal("expected the first (real key) run to succeed")
	}

	r2 := bufio.NewReader(strings.NewReader("2\n\n")) // re-run, z.ai again, blank key
	_, env2, remove2 := offerProviderSettings(r2, zaiUpstreamURL)
	if !offerProjectSettings(bufio.NewReader(strings.NewReader("y\ny\n")), cwd, "127.0.0.1:9999", filepath.Join(t.TempDir(), "debug.log"), env2, remove2) {
		t.Fatal("expected the second (blank key) run to succeed")
	}

	data, err := os.ReadFile(filepath.Join(cwd, ".claude", "settings.local.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	env, _ := settings["env"].(map[string]any)
	if env["ANTHROPIC_AUTH_TOKEN"] != "real-working-key" {
		t.Fatalf("expected the real key from the first run to survive a blank-key re-run, got %+v", env)
	}
}

func TestOfferProviderSettings_Manual_BlankTokenPreservesExistingAuth(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("3\ny\nhttps://api.example.com\n\nsome-model\n")) // manual, interactive, blank token
	_, env, remove := offerProviderSettings(r, "https://api.example.com")
	if _, ok := env["ANTHROPIC_AUTH_TOKEN"]; ok {
		t.Fatalf("expected no ANTHROPIC_AUTH_TOKEN in envSet when no token was typed, got %+v", env)
	}
	if _, ok := env["ANTHROPIC_API_KEY"]; ok {
		t.Fatalf("expected no ANTHROPIC_API_KEY in envSet when no token was typed, got %+v", env)
	}
	for _, k := range remove {
		if k == "ANTHROPIC_AUTH_TOKEN" || k == "ANTHROPIC_API_KEY" {
			t.Fatalf("expected both auth keys excluded from the removal set when no token was typed, got remove=%+v", remove)
		}
	}
}

func TestOfferProviderSettings_Manual_InteractiveCollectsURLTokenAndModel(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("3\ny\nhttps://api.example.com\nsecret-token\n\nsome-model\n"))
	upstream, env, remove := offerProviderSettings(r, "")
	if upstream != "https://api.example.com" {
		t.Fatalf("expected the typed upstream URL, got %q", upstream)
	}
	if env["ANTHROPIC_AUTH_TOKEN"] != "secret-token" {
		t.Fatalf("expected the typed token as ANTHROPIC_AUTH_TOKEN (default: Bearer), got %+v", env)
	}
	if env["ANTHROPIC_API_KEY"] != "" {
		t.Fatalf("expected ANTHROPIC_API_KEY blanked when Bearer is chosen, got %+v", env)
	}
	for _, k := range providerModelEnvKeys {
		if env[k] != "some-model" {
			t.Fatalf("expected %s = some-model, got %+v", k, env)
		}
	}
	if len(remove) != len(providerEnvKeys) {
		t.Fatalf("expected picking manual to return providerEnvKeys as its removal baseline too, got %+v", remove)
	}
}

func TestOfferProviderSettings_Manual_InteractiveXApiKeyHeader(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("3\ny\nhttps://api.example.com\nsecret-token\nn\n\n"))
	_, env, _ := offerProviderSettings(r, "")
	if env["ANTHROPIC_API_KEY"] != "secret-token" {
		t.Fatalf("expected the typed token as ANTHROPIC_API_KEY when X-Api-Key is chosen, got %+v", env)
	}
	if env["ANTHROPIC_AUTH_TOKEN"] != "" {
		t.Fatalf("expected ANTHROPIC_AUTH_TOKEN blanked when X-Api-Key is chosen (no stale Bearer credential), got %+v", env)
	}
}

func TestOfferProviderSettings_Manual_InteractiveRejectsInvalidURLThenRetries(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("3\ny\nnot-a-url\nhttps://api.example.com\ntok\n\n\n"))
	upstream, env, _ := offerProviderSettings(r, "")
	if upstream != "https://api.example.com" {
		t.Fatalf("expected the invalid URL rejected and the retry accepted, got %q", upstream)
	}
	if env["ANTHROPIC_AUTH_TOKEN"] != "tok" {
		t.Fatalf("expected the token collected, got %+v", env)
	}
	if _, ok := env["ANTHROPIC_DEFAULT_OPUS_MODEL"]; ok {
		t.Fatalf("expected no model override when the model prompt is left blank, got %+v", env)
	}
}

func TestOfferProviderSettings_Manual_InteractiveSplitBackgroundModel(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("3\ny\nhttps://api.example.com\ntok\n\nmain-model\ny\nbg-model\n"))
	_, env, _ := offerProviderSettings(r, "")
	for _, k := range providerPrimaryModelEnvKeys {
		if env[k] != "main-model" {
			t.Fatalf("expected primary key %s = main-model, got %+v", k, env)
		}
	}
	for _, k := range providerBackgroundModelEnvKeys {
		if env[k] != "bg-model" {
			t.Fatalf("expected background key %s = bg-model, got %+v", k, env)
		}
	}
}

func TestOfferProviderSettings_Manual_InteractiveSplitBackgroundModel_BlankReusesPrimary(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("3\ny\nhttps://api.example.com\ntok\n\nmain-model\ny\n\n"))
	_, env, _ := offerProviderSettings(r, "")
	for _, k := range providerModelEnvKeys {
		if env[k] != "main-model" {
			t.Fatalf("expected %s = main-model (blank background model reuses primary), got %+v", k, env)
		}
	}
}

func TestOfferProviderSettings_Manual_DeclineInteractiveWritesSkeleton(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("3\nn\n"))
	upstream, env, _ := offerProviderSettings(r, "")
	if upstream != manualUpstreamPlaceholder {
		t.Fatalf("expected the placeholder upstream, got %q", upstream)
	}
	if env["ANTHROPIC_AUTH_TOKEN"] != manualValuePlaceholder {
		t.Fatalf("expected a placeholder ANTHROPIC_AUTH_TOKEN, got %+v", env)
	}
	if env["ANTHROPIC_API_KEY"] != "" {
		t.Fatalf("expected ANTHROPIC_API_KEY blanked, got %+v", env)
	}
	for _, k := range providerModelEnvKeys {
		if env[k] != manualValuePlaceholder {
			t.Fatalf("expected placeholder %s, got %+v", k, env)
		}
	}
}

func TestOfferProviderSettings_Manual_EOFAtURLPromptFallsBackToSkeleton(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("3\ny\n"))
	upstream, _, _ := offerProviderSettings(r, "")
	if upstream != manualUpstreamPlaceholder {
		t.Fatalf("expected EOF at the URL prompt to fall back to the placeholder skeleton, got %q", upstream)
	}
}

func TestOfferProjectSettings_SwitchToClaude_RemovesBlankedAPIKey(t *testing.T) {
	cwd := t.TempDir()
	// Simulate a prior run that picked a non-Claude provider (blanked
	// ANTHROPIC_API_KEY, set an auth token).
	r1 := bufio.NewReader(strings.NewReader("y\n"))
	providerEnv := map[string]string{"ANTHROPIC_API_KEY": "", "ANTHROPIC_AUTH_TOKEN": "tok-123"}
	if !offerProjectSettings(r1, cwd, "127.0.0.1:9999", filepath.Join(t.TempDir(), "debug.log"), providerEnv, nil) {
		t.Fatal("expected first run to succeed")
	}

	// Now switch back to Claude: providerEnvKeys (including
	// ANTHROPIC_API_KEY) should be removed entirely, not left blank.
	r2 := bufio.NewReader(strings.NewReader("y\ny\n"))
	if !offerProjectSettings(r2, cwd, "127.0.0.1:9999", filepath.Join(t.TempDir(), "debug.log"), nil, providerEnvKeys) {
		t.Fatal("expected second run to succeed")
	}
	data, err := os.ReadFile(filepath.Join(cwd, ".claude", "settings.local.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	env, _ := settings["env"].(map[string]any)
	if _, ok := env["ANTHROPIC_API_KEY"]; ok {
		t.Fatalf("expected ANTHROPIC_API_KEY removed (not left blank) after switching back to Claude, got %+v", env)
	}
	if _, ok := env["ANTHROPIC_AUTH_TOKEN"]; ok {
		t.Fatalf("expected ANTHROPIC_AUTH_TOKEN removed after switching back to Claude, got %+v", env)
	}
}

func TestOfferProjectSettings_ZAIThenSwitchToClaude_CleansUpEverything(t *testing.T) {
	cwd := t.TempDir()

	r1 := bufio.NewReader(strings.NewReader("2\nzai-key\ny\n"))
	_, zaiEnv, _ := offerProviderSettings(r1, "")
	if !offerProjectSettings(bufio.NewReader(strings.NewReader("y\n")), cwd, "127.0.0.1:9999", filepath.Join(t.TempDir(), "debug.log"), zaiEnv, nil) {
		t.Fatal("expected the z.ai settings write to succeed")
	}

	r2 := bufio.NewReader(strings.NewReader("1\n"))
	_, _, removeKeys := offerProviderSettings(r2, zaiUpstreamURL)
	if !offerProjectSettings(bufio.NewReader(strings.NewReader("y\ny\n")), cwd, "127.0.0.1:9999", filepath.Join(t.TempDir(), "debug.log"), nil, removeKeys) {
		t.Fatal("expected the switch-to-Claude write to succeed")
	}

	data, err := os.ReadFile(filepath.Join(cwd, ".claude", "settings.local.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	env, _ := settings["env"].(map[string]any)
	for _, leftover := range []string{
		"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
		"ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL",
		"API_TIMEOUT_MS", "CLAUDE_CODE_AUTO_COMPACT_WINDOW",
	} {
		if _, ok := env[leftover]; ok {
			t.Fatalf("expected %s removed after switching from z.ai back to Claude, got %+v", leftover, env)
		}
	}
	if env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:9999" {
		t.Fatalf("expected ANTHROPIC_BASE_URL to still point at the proxy, got %+v", env)
	}
}

func TestOfferProjectSettings_ProviderEnv_SetAndRemoved(t *testing.T) {
	cwd := t.TempDir()
	r := bufio.NewReader(strings.NewReader("y\n"))
	providerEnv := map[string]string{"ANTHROPIC_AUTH_TOKEN": "tok-123", "ANTHROPIC_DEFAULT_OPUS_MODEL": "glm-5.2"}
	if !offerProjectSettings(r, cwd, "127.0.0.1:9999", filepath.Join(t.TempDir(), "debug.log"), providerEnv, nil) {
		t.Fatal("expected offerProjectSettings to report success")
	}
	data, err := os.ReadFile(filepath.Join(cwd, ".claude", "settings.local.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	env, _ := settings["env"].(map[string]any)
	if env["ANTHROPIC_AUTH_TOKEN"] != "tok-123" || env["ANTHROPIC_DEFAULT_OPUS_MODEL"] != "glm-5.2" {
		t.Fatalf("expected provider env vars set, got %+v", env)
	}

	// Re-run "switching back to Claude" -- removeEnvKeys should clear
	// what the previous run set, leaving no stale provider auth/model
	// behind.
	r2 := bufio.NewReader(strings.NewReader("y\ny\n"))
	if !offerProjectSettings(r2, cwd, "127.0.0.1:9999", filepath.Join(t.TempDir(), "debug.log"), nil, providerEnvKeys) {
		t.Fatal("expected second run to succeed")
	}
	data, err = os.ReadFile(filepath.Join(cwd, ".claude", "settings.local.json"))
	if err != nil {
		t.Fatal(err)
	}
	settings = nil
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	env, _ = settings["env"].(map[string]any)
	if _, ok := env["ANTHROPIC_AUTH_TOKEN"]; ok {
		t.Fatalf("expected ANTHROPIC_AUTH_TOKEN removed after switching back to Claude, got %+v", env)
	}
	if _, ok := env["ANTHROPIC_DEFAULT_OPUS_MODEL"]; ok {
		t.Fatalf("expected ANTHROPIC_DEFAULT_OPUS_MODEL removed after switching back to Claude, got %+v", env)
	}
}

func TestUpstreamPersistence_RoundTripAndClear(t *testing.T) {
	dataDir := t.TempDir()
	path, err := upstreamPathFor(dataDir, "xyz-example-corp")
	if err != nil {
		t.Fatal(err)
	}

	if _, ok, err := readPersistedUpstream(path); err != nil || ok {
		t.Fatalf("expected no persisted upstream yet, got ok=%v err=%v", ok, err)
	}

	if err := writePersistedUpstream(path, "https://api.z.ai/api/anthropic"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := readPersistedUpstream(path)
	if err != nil || !ok || got != "https://api.z.ai/api/anthropic" {
		t.Fatalf("expected round-tripped upstream, got %q ok=%v err=%v", got, ok, err)
	}

	if err := writePersistedUpstream(path, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := readPersistedUpstream(path); err != nil || ok {
		t.Fatalf("expected clearing to remove the file, got ok=%v err=%v", ok, err)
	}
}

// TestPromptLines_DomainPromptMarksEntriesAsDomains pins that the
// wizard's domain question produces DOMAIN entries, not opaque literal
// ones. The distinction is the whole of rules.Compiled.ForcedDomains:
// an IsDomain entry gets the structure-preserving domain token
// everywhere the domain appears (bare, as a subdomain, inside an email,
// inside a URL), while a plain literal entry only ever matches the exact
// text typed. The wizard is the documented way to set an engagement up,
// so it must not quietly produce weaker entries than
// `rules block -domain` does for the same value.
func TestPromptLines_DomainPromptMarksEntriesAsDomains(t *testing.T) {
	var entries []rules.Entry
	r := bufio.NewReader(strings.NewReader("widgetcorp-fixture.com\n\n"))
	if n := promptLines(r, "Domains:", "note", true, &entries); n != 1 {
		t.Fatalf("expected 1 entry collected, got %d", n)
	}
	if len(entries) != 1 || !entries[0].IsDomain {
		t.Fatalf("expected the collected entry to be marked IsDomain, got %+v", entries)
	}
}

// TestPromptLines_NamePromptDoesNotMarkEntriesAsDomains is the other
// half: a customer NAME ("XyzExampleCorp") is not a domain, and marking it one
// would send it down a resolution path it can never satisfy.
func TestPromptLines_NamePromptDoesNotMarkEntriesAsDomains(t *testing.T) {
	var entries []rules.Entry
	r := bufio.NewReader(strings.NewReader("XyzExampleCorp\n\n"))
	if n := promptLines(r, "Names:", "note", false, &entries); n != 1 {
		t.Fatalf("expected 1 entry collected, got %d", n)
	}
	if len(entries) != 1 || entries[0].IsDomain {
		t.Fatalf("expected the collected entry NOT to be marked IsDomain, got %+v", entries)
	}
}
