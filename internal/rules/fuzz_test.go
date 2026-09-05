package rules

import (
	"encoding/json"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/redact"
)

// rules.json is the one input in this whole proxy that's routinely
// hand-edited by an operator rather than only ever produced by this
// tool's own code -- every other fuzz target in this repo covers
// upstream API traffic (still untrusted, but machine-generated and
// JSON-API-shaped); this one covers a config file a person edits in a
// text editor, which is a meaningfully different risk shape (typos,
// copy-paste mistakes, a stray unescaped character, a badly-remembered
// regex). Fuzzes json.Unmarshal straight into a Config plus the
// Validate/Compile pipeline that runs on every Load, never through
// Load's own file-reading wrapper, since that part is a thin, boring
// os.ReadFile call not worth spending fuzz iterations on.
//
// Go's regexp package already rejects large repeat counts outright
// ("invalid repeat count") and RE2's linear-time guarantee means none
// of the classic catastrophic-backtracking shapes (nested "(a*)*",
// alternation-of-identical-branches, etc.) cause a compile-time or
// match-time blowup the way they would against a
// backtracking engine -- so a malicious/mistyped regex entry in
// rules.json is not a realistic hang/OOM vector here, and this target
// is not specifically hunting for one.
func FuzzRulesLoadCompile(f *testing.F) {
	for _, seed := range rulesFuzzSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var cfg Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			return // malformed JSON -- rejected on purpose, not a bug
		}

		// Validate and Compile independently rather than relying on
		// Compile's own internal call to Validate, so a real disagreement
		// between the two (Compile succeeding on something Validate
		// would reject, or vice versa) shows up directly instead of
		// being masked by Compile always deferring to Validate first.
		validateErr := cfg.Validate()
		compiled, compileErr := cfg.Compile()
		if (validateErr == nil) != (compileErr == nil) {
			t.Fatalf("Validate and Compile disagree on whether this config is valid:\n  data: %s\n  validate_err: %v\n  compile_err:  %v", data, validateErr, compileErr)
		}
		if compileErr != nil {
			return
		}
		if compiled == nil {
			t.Fatalf("Compile returned (nil, nil) -- callers assume a nil error means a usable *Compiled:\n  data: %s", data)
		}

		// Every compiled regex must actually be usable -- MatchString
		// itself is what would panic on a malformed compiled program if
		// compileEntry's error handling ever let something bad through.
		for _, re := range compiled.Block {
			re.MatchString("")
			re.MatchString("probe text with admin@widgetcorp-fixture.com and more")
		}
		for _, re := range compiled.Allow {
			re.MatchString("")
			re.MatchString("probe text with admin@widgetcorp-fixture.com and more")
		}

		// Compiling the identical config twice must produce the same
		// disabled-category set and the same number of compiled
		// block/allow entries and forced domains -- Compile has no
		// external state (unlike Engine.Tokenize/jsonwalk.Tokenize
		// against a store), so this should hold trivially; a violation
		// would mean something in Compile depends on unintended
		// ambient state (map iteration order feeding into something
		// order-sensitive, for one concrete way this could break).
		compiled2, err2 := cfg.Compile()
		if err2 != nil {
			t.Fatalf("Compile succeeded once then failed on the identical config: %v", err2)
		}
		if len(compiled.Block) != len(compiled2.Block) || len(compiled.Allow) != len(compiled2.Allow) {
			t.Fatalf("Compile(cfg) is not deterministic in entry counts:\n  data: %s\n  first:  block=%d allow=%d\n  second: block=%d allow=%d", data, len(compiled.Block), len(compiled.Allow), len(compiled2.Block), len(compiled2.Allow))
		}
		if len(compiled.Disabled) != len(compiled2.Disabled) || len(compiled.ForcedDomains) != len(compiled2.ForcedDomains) {
			t.Fatalf("Compile(cfg) is not deterministic in disabled/forced-domain counts:\n  data: %s", data)
		}
	})
}

// FuzzEnsureAllCategories fuzzes EnsureAllCategories against an
// arbitrary starting Categories map (decoded from fuzzer JSON), reusing
// the real, current redact.AllCategoryInfo() as the reconciliation
// target -- exactly what every real caller (runProxy, the wizard, every
// `rules` subcommand) passes. Checks the three guarantees its own doc
// comment makes explicitly: every known category ends up present, no
// unknown key survives, and an existing entry's Enabled value is never
// altered by reconciliation.
func FuzzEnsureAllCategories(f *testing.F) {
	all := redact.AllCategoryInfo()

	for _, seed := range rulesFuzzSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var cfg Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			return
		}
		before := make(map[string]CategoryState, len(cfg.Categories))
		for k, v := range cfg.Categories {
			before[k] = v
		}

		cfg.EnsureAllCategories(all)

		for _, info := range all {
			key := info.Name()
			state, ok := cfg.Categories[key]
			if !ok {
				t.Fatalf("EnsureAllCategories left known category %q missing", key)
			}
			if prior, existed := before[key]; existed && state.Enabled != prior.Enabled {
				t.Fatalf("EnsureAllCategories changed Enabled for pre-existing category %q: was %v, now %v", key, prior.Enabled, state.Enabled)
			}
		}
		known := make(map[string]bool, len(all))
		for _, info := range all {
			known[info.Name()] = true
		}
		for key := range cfg.Categories {
			if !known[key] {
				t.Fatalf("EnsureAllCategories left unknown category %q in place", key)
			}
		}
	})
}

// rulesFuzzSeeds covers: empty/degenerate JSON, a realistic dense
// Categories block, every Entry shape (regex and literal, Block and
// Allow, IsDomain in every combination the doc comments call out --
// resolves to a real domain, a hostname-shaped-but-not-public-suffix
// value, and neither), an empty Value on each list (the exact case
// Validate's own doc comment exists to reject), an invalid regex
// pattern, duplicate entries, very large repeat counts and deeply
// nested quantifiers (see this file's own doc comment for why these
// are expected to be rejected/harmless rather than a hang risk), and
// non-UTF-8 bytes inside a JSON string escape.
var rulesFuzzSeeds = [][]byte{
	[]byte(``),
	[]byte(`{}`),
	[]byte(`null`),
	[]byte(`[]`),
	[]byte(`{"categories":{"cloud.aws":{"enabled":false}},"block":[{"value":"widgetcorp-fixture","note":"customer name"}],"allow":[{"value":"widgetcorp-fixture.com"}]}`),
	[]byte(`{"block":[{"value":"^admin@.*\\.com$","regex":true}]}`),
	[]byte(`{"block":[{"value":"widgetcorp-fixture.net.net","is_domain":true}]}`),
	[]byte(`{"block":[{"value":"internal-ad-forest.corp","is_domain":true}]}`),
	[]byte(`{"block":[{"value":"not a domain at all !!","is_domain":true}]}`),
	[]byte(`{"block":[{"value":"","note":"empty value"}]}`),
	[]byte(`{"allow":[{"value":""}]}`),
	[]byte(`{"block":[{"value":"(unterminated","regex":true}]}`),
	[]byte(`{"block":[{"value":"a{5000}","regex":true}]}`),
	[]byte(`{"block":[{"value":"((((((((((a*)*)*)*)*)*)*)*)*)*)*b","regex":true}]}`),
	[]byte(`{"block":[{"value":"dup"},{"value":"dup"},{"value":"DUP"}]}`),
	[]byte(`{"block":[{"value":"same"}],"allow":[{"value":"same"}]}`),
	[]byte("{\"block\":[{\"value\":\"caf\xc3\xa9.com\"}]}"),
	[]byte(`{"categories":{"":{"enabled":true},"unknown.made.up":{"enabled":false}}}`),
	[]byte(`{"block": "not an array"}`),
	[]byte(`{"block":[{"value":123}]}`),
	[]byte(`{"block":[{"value":"🔥émoji-café-🎉.com","is_domain":true}]}`),
}
