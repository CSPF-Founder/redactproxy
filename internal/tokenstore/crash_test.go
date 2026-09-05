package tokenstore

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestCrashConsistency_SIGKILLMidWriteNeverLosesOrChangesACommittedToken
// verifies real crash consistency, not just clean-Close persistence
// (TestPersistenceAcrossReopen only covers that). A helper process
// (./crashtest) mints tokens in a tight loop, printing each real value
// and its token to stdout immediately after the mint commits. The test
// SIGKILLs the helper at an arbitrary point (no clean Close, no
// deferred cleanup runs), then reopens the same store fresh and checks
// every value the helper confirmed as committed still maps to the exact
// same token. Repeated multiple times so the kill lands at a different
// point in bbolt's write cycle each run (page allocation, mmap growth,
// fsync, etc. are all timing-dependent), matching the project's own
// established lesson that this class of bug only surfaces under
// repeated fresh runs, not a single pass (see the FUSE-layer write bug
// documented in this project's history).
func TestCrashConsistency_SIGKILLMidWriteNeverLosesOrChangesACommittedToken(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real subprocesses repeatedly; skip in -short")
	}

	helperBin := buildCrashtestHelper(t)

	const iterations = 8
	for iter := range iterations {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "tokens.db")

		cmd := exec.Command(helperBin, dbPath)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}

		confirmed := make(map[string]string)
		lineCh := make(chan [2]string)
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				parts := strings.Fields(scanner.Text())
				if len(parts) == 2 {
					lineCh <- [2]string{parts[0], parts[1]}
				}
			}
			close(lineCh)
		}()

		// Let it mint for a short, varying amount of time -- varying by
		// iteration count alone is enough; process/OS scheduling jitter
		// naturally lands the kill at a different point in bbolt's
		// internal write cycle each run.
		deadline := time.After(time.Duration(5+iter*3) * time.Millisecond)
	collect:
		for {
			select {
			case line, ok := <-lineCh:
				if !ok {
					break collect
				}
				confirmed[line[0]] = line[1]
			case <-deadline:
				break collect
			}
		}

		if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		cmd.Wait() // reap; ignore the (expected) killed-process error

		// Drain any lines that were already buffered before the kill
		// landed, so we don't undercount what was actually committed.
		for line := range lineCh {
			confirmed[line[0]] = line[1]
		}

		if len(confirmed) == 0 {
			t.Logf("iter %d: helper minted nothing before the kill landed (too fast a kill) -- not a failure, just nothing to check this round", iter)
			continue
		}

		store, err := Open(dbPath)
		if err != nil {
			t.Fatalf("iter %d: reopen after SIGKILL failed (corruption?): %v", iter, err)
		}

		for real, wantTok := range confirmed {
			gotTok, err := store.GetOrCreateToken(real, EntityDomain)
			if err != nil {
				t.Errorf("iter %d: GetOrCreateToken(%q) after crash: %v", iter, real, err)
				continue
			}
			if gotTok != wantTok {
				t.Errorf("iter %d: token for %q changed across crash: had %q, now %q", iter, real, wantTok, gotTok)
			}
		}
		t.Logf("iter %d: verified %d tokens survived the crash unchanged", iter, len(confirmed))
		store.Close()
	}
}

func buildCrashtestHelper(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "crashtest_helper")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/CSPF-Founder/redactproxy/internal/tokenstore/crashtest")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build crashtest helper: %v", err)
	}
	return bin
}
