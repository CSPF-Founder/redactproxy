package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testPollInterval = 30 * time.Millisecond
const testWaitTimeout = 2 * time.Second

func TestWatcher_DetectsFileCreatedAfterStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	changes := make(chan *Config, 10)

	w := NewWatcher(path, testPollInterval, func(c *Config) { changes <- c }, nil)
	w.Start()
	defer w.Stop()

	cfg := &Config{Categories: map[string]CategoryState{"cloud.aws": {Enabled: false}}}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}

	select {
	case c := <-changes:
		if len(c.Categories) != 1 {
			t.Fatalf("unexpected change payload: %+v", c)
		}
	case <-time.After(testWaitTimeout):
		t.Fatal("watcher did not detect file creation in time")
	}
}

func TestWatcher_NoSpuriousFireWithoutAChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	cfg := &Config{Categories: map[string]CategoryState{"cloud.aws": {Enabled: false}}}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}

	changes := make(chan *Config, 10)
	// Constructed AFTER the file already exists: the watcher should
	// seed its "last known mtime" from the existing file, not treat it
	// as a change on the first poll.
	w := NewWatcher(path, testPollInterval, func(c *Config) { changes <- c }, nil)
	w.Start()
	defer w.Stop()

	select {
	case c := <-changes:
		t.Fatalf("unexpected spurious change for an already-existing, unmodified file: %+v", c)
	case <-time.After(5 * testPollInterval):
	}
}

func TestWatcher_DetectsSubsequentEdit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := (&Config{Categories: map[string]CategoryState{"cloud.aws": {Enabled: false}}}).Save(path); err != nil {
		t.Fatal(err)
	}

	changes := make(chan *Config, 10)
	w := NewWatcher(path, testPollInterval, func(c *Config) { changes <- c }, nil)
	w.Start()
	defer w.Stop()

	// Let it settle past the initial no-spurious-fire window, then edit.
	time.Sleep(3 * testPollInterval)
	if err := (&Config{Categories: map[string]CategoryState{"cloud.aws": {Enabled: false}, "network.mac": {Enabled: false}}}).Save(path); err != nil {
		t.Fatal(err)
	}

	select {
	case c := <-changes:
		if len(c.Categories) != 2 {
			t.Fatalf("expected the edited config (2 disabled), got %+v", c)
		}
	case <-time.After(testWaitTimeout):
		t.Fatal("watcher did not detect the edit in time")
	}
}

func TestWatcher_FileRemovalReloadsToEmptyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := (&Config{Categories: map[string]CategoryState{"cloud.aws": {Enabled: false}}}).Save(path); err != nil {
		t.Fatal(err)
	}

	changes := make(chan *Config, 10)
	w := NewWatcher(path, testPollInterval, func(c *Config) { changes <- c }, nil)
	w.Start()
	defer w.Stop()

	time.Sleep(3 * testPollInterval)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	select {
	case c := <-changes:
		if len(c.Categories) != 0 {
			t.Fatalf("expected an empty config after the file was removed, got %+v", c)
		}
	case <-time.After(testWaitTimeout):
		t.Fatal("watcher did not detect the file removal in time")
	}
}

func TestWatcher_StopEndsPolling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	changes := make(chan *Config, 10)
	w := NewWatcher(path, testPollInterval, func(c *Config) { changes <- c }, nil)
	w.Start()
	w.Stop() // must return promptly, not block forever

	if err := (&Config{Categories: map[string]CategoryState{"cloud.aws": {Enabled: false}}}).Save(path); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-changes:
		t.Fatalf("expected no changes to be delivered after Stop, got %+v", c)
	case <-time.After(5 * testPollInterval):
	}
}
