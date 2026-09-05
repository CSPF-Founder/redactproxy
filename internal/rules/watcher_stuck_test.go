package rules

import (
	"os"
	"testing"
	"time"
)

// A torn read (the watcher's poll landing mid-write, when a writer isn't
// atomic: a hand edit, a disk hiccup, anything other than this
// package's own Save, which IS atomic via temp file + rename) must never
// leave the live proxy stuck on stale rules indefinitely. This is
// guarded two ways, both exercised here: (1) Config.Save's atomic write
// means this codebase's own writes can never produce a torn read at
// all; (2) checkOnce only advances lastMod on a SUCCESSFUL load, so a
// failure from any other cause self-heals on the very next poll tick
// instead of waiting for some unrelated future edit to change the mtime
// again.
func TestWatcher_TornReadDuringWriteNoLongerLeavesStaleRulesStuck(t *testing.T) {
	path := "/tmp/watcher_stuck_test_rules.json"
	defer os.Remove(path)

	if err := (&Config{Categories: map[string]CategoryState{"cloud.aws": {Enabled: false}}}).Save(path); err != nil {
		t.Fatal(err)
	}

	var changes []*Config
	var errs []error
	w := NewWatcher(path, time.Second, func(c *Config) { changes = append(changes, c) }, func(e error) { errs = append(errs, e) })

	// Simulate a torn read from some non-atomic writer (not this
	// package's own Save, which is now atomic) -- the file's mtime has
	// moved on but its content is invalid at the instant checkOnce reads it.
	future := time.Now().Add(time.Hour)
	if err := os.WriteFile(path, []byte(`{"disabled": [`), 0o600); err != nil { // truncated/invalid JSON
		t.Fatal(err)
	}
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	w.checkOnce()
	if len(errs) != 1 {
		t.Fatalf("expected exactly one onError call for the torn/invalid read, got %d", len(errs))
	}
	if len(changes) != 0 {
		t.Fatalf("expected no onChange call for invalid JSON, got %d", len(changes))
	}

	// The write "finishes" -- valid content, and (worst case for the
	// fix) the SAME mtime as the failed read saw, simulating the write
	// completing within the same timestamp granularity.
	if err := (&Config{Categories: map[string]CategoryState{"cloud.aws": {Enabled: false}, "network.mac": {Enabled: false}}}).Save(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	// The very next poll tick, with NO further edit needed, must recover.
	w.checkOnce()
	if len(changes) != 1 {
		t.Fatalf("expected the watcher to recover on the very next checkOnce, got %d changes (errs=%d)", len(changes), len(errs))
	}
	if len(changes[0].Categories) != 2 {
		t.Fatalf("expected the corrected 2-entry config to load, got %+v", changes[0])
	}
}
