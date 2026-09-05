package debuglog

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRotatingWriter_RotatesAtThreshold_ArchivesGzippedPart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "debug.log")

	rw, err := NewRotatingWriter(path, 20) // tiny threshold to force rotation quickly
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()

	// Each write is well under the threshold on its own, but the
	// running total crosses it partway through.
	lines := []string{"first-line\n", "second-line\n", "third-line\n"}
	for _, l := range lines {
		if _, err := rw.Write([]byte(l)); err != nil {
			t.Fatal(err)
		}
	}

	gzPath := waitForGlob(t, dir, "debug.log.*.gz")
	archived := readGzip(t, gzPath)
	if !strings.HasPrefix(archived, "first-line\n") {
		t.Fatalf("expected the archived part to start with the pre-rotation content, got %q", archived)
	}

	// No leftover uncompressed rotated file once compression succeeds.
	uncompressed := strings.TrimSuffix(gzPath, ".gz")
	if _, err := os.Stat(uncompressed); !os.IsNotExist(err) {
		t.Fatalf("expected the uncompressed rotated file removed after compression, got err=%v", err)
	}

	// Whatever pushed the size over the threshold started a fresh file.
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(current) == 0 {
		t.Fatal("expected the active debug.log to have received the write that triggered rotation")
	}
}

func TestRotatingWriter_ResumeAfterRestart_NoCollisionWithPreviousArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "debug.log")

	rw1, err := NewRotatingWriter(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	rw1.Write([]byte("aaaaaaaaaaaaaaaa\n")) // forces one rotation
	firstArchive := waitForGlob(t, dir, "debug.log.*.gz")
	rw1.Close()

	// Simulate a proxy restart: a fresh RotatingWriter over the same
	// path must not clobber the existing archive when it rotates again.
	rw2, err := NewRotatingWriter(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer rw2.Close()
	rw2.Write([]byte("bbbbbbbbbbbbbbbb\n")) // forces another rotation

	deadline := time.Now().Add(2 * time.Second)
	var secondArchive string
	for time.Now().Before(deadline) {
		matches, _ := filepath.Glob(filepath.Join(dir, "debug.log.*.gz"))
		for _, m := range matches {
			if m != firstArchive {
				secondArchive = m
			}
		}
		if secondArchive != "" {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if secondArchive == "" {
		t.Fatal("timed out waiting for the second run's archive to appear as a distinct file")
	}

	if _, err := os.Stat(firstArchive); err != nil {
		t.Fatalf("expected the first run's archive to survive untouched, got %v", err)
	}
	firstContent := readGzip(t, firstArchive)
	if !strings.Contains(firstContent, "aaaaaaaaaaaaaaaa") {
		t.Fatalf("expected the first run's archive to still hold its own content, got %q", firstContent)
	}
	secondContent := readGzip(t, secondArchive)
	if !strings.Contains(secondContent, "bbbbbbbbbbbbbbbb") {
		t.Fatalf("expected the second run's archive to hold its own content, got %q", secondContent)
	}
}

func TestRotatingWriter_OpenAlreadyOverThreshold_RotatesImmediately(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "debug.log")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 100), 0o600); err != nil {
		t.Fatal(err)
	}

	rw, err := NewRotatingWriter(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()

	waitForGlob(t, dir, "debug.log.*.gz")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected a fresh, empty debug.log after opening an already-oversized file, got size %d", info.Size())
	}
}

func TestLogger_BeginRoundTrip_RotatesBeforeNextEventNotMidEvent(t *testing.T) {
	// Measure one real logged line's size first, rather than guessing a
	// threshold against encoding/json's exact output -- the point of
	// this test is the ROTATION TIMING, not the log format, so it
	// shouldn't be coupled to the latter by a hardcoded byte count.
	var probe bytes.Buffer
	New(Full, &probe).Replacement("tokenize", "domain", "widgetcorp.example", "tok-abc")
	lineSize := probe.Len()

	dir := t.TempDir()
	path := filepath.Join(dir, "debug.log")

	// Comfortably more than one line, less than two -- so two
	// same-sized events in a row cross it cumulatively, but neither
	// alone does.
	threshold := int64(lineSize + lineSize/2)
	rw, err := NewRotatingWriter(path, threshold)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	l := New(Full, rw)

	// First event: fits comfortably under threshold, no rotation yet.
	// Checked by line count and content, not exact byte length --
	// RFC3339Nano trims trailing zero digits from the timestamp, so two
	// lines logged a moment apart can legitimately differ in length by
	// a few bytes even with identical field values.
	l.Replacement("tokenize", "domain", "widgetcorp.example", "tok-abc")
	afterFirst, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertOneWellFormedLine(t, afterFirst, "widgetcorp.example", "tok-abc")

	// A second event without an intervening BeginRoundTrip: Write's own
	// reactive check still fires (a safety net for a single oversized
	// round trip -- see MaybeRotate's doc comment) and rotates
	// immediately after this write lands, archiving both lines
	// together -- but it can only rotate AFTER the write completes,
	// never split it. Check the ARCHIVED copy for that, not the active
	// file: by the time this call returns, rotation has already
	// emptied the active file back out.
	l.Replacement("tokenize", "domain", "widgetcorp.example", "tok-abc")
	gzPath := waitForGlob(t, dir, "debug.log.*.gz")
	archived := readGzip(t, gzPath)
	for _, line := range strings.Split(strings.TrimRight(archived, "\n"), "\n") {
		if !strings.HasSuffix(line, "}") {
			t.Fatalf("found a truncated/split log line in the archived part (rotation must never cut a line in half): %q", line)
		}
	}
	if got := strings.Count(archived, "\n"); got != 2 {
		t.Fatalf("expected both pre-rotation lines archived together, got %d lines: %q", got, archived)
	}

	// Now the file is back to empty (rotated after the second write).
	// A fresh round trip beginning here, with BeginRoundTrip called
	// explicitly first, must not need to rotate again mid-round-trip:
	// its own event should land whole in what's already a fresh file.
	l.BeginRoundTrip()
	beforeThird, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if beforeThird.Size() != 0 {
		t.Fatalf("expected the file already rotated to empty before this round trip's first event, got starting size %d", beforeThird.Size())
	}
	l.Replacement("tokenize", "domain", "widgetcorp.example", "tok-abc")
	afterThird, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertOneWellFormedLine(t, afterThird, "widgetcorp.example", "tok-abc")
}

// assertOneWellFormedLine checks data is exactly one complete,
// non-truncated JSON log line containing every wantSubstr, without
// depending on its exact byte length (see the timestamp-length note at
// this function's call sites).
func assertOneWellFormedLine(t *testing.T, data []byte, wantSubstrs ...string) {
	t.Helper()
	if got := bytes.Count(data, []byte("\n")); got != 1 {
		t.Fatalf("expected exactly one line, got %d: %q", got, data)
	}
	line := string(bytes.TrimRight(data, "\n"))
	if !strings.HasSuffix(line, "}") {
		t.Fatalf("found a truncated/split log line: %q", line)
	}
	for _, want := range wantSubstrs {
		if !strings.Contains(line, want) {
			t.Fatalf("expected line to contain %q, got %q", want, line)
		}
	}
}

func TestRotatingWriter_ActiveFileDeletedMidRun_SelfHealsOnNextRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "debug.log")

	rw, err := NewRotatingWriter(path, 10_000_000) // large threshold -- deletion, not size, drives this
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()

	if _, err := rw.Write([]byte("before-deletion\n")); err != nil {
		t.Fatal(err)
	}

	// Simulate an operator manually deleting the active log mid-run.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("setup failed: expected the file to actually be gone")
	}

	// The writer doesn't notice instantly (that's the documented
	// tradeoff -- detection happens on the round-trip boundary, not on
	// every Write), but MaybeRotate must recover it promptly rather
	// than continuing to grow an orphaned, invisible file forever.
	rw.MaybeRotate()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected a fresh debug.log to exist after deletion recovery, got %v", err)
	}

	if _, err := rw.Write([]byte("after-recovery\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "after-recovery\n" {
		t.Fatalf("expected only post-recovery content in the fresh file (pre-deletion content is unrecoverable, by design), got %q", data)
	}
}

func TestRotatingWriter_Close_WaitsForInFlightCompression_NoOrphanedTmpFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "debug.log")

	rw, err := NewRotatingWriter(path, 20)
	if err != nil {
		t.Fatal(err)
	}
	// Force several rotations back to back so it's overwhelmingly likely
	// at least one background compression is still in flight the moment
	// Close is called immediately after -- this is exactly the shutdown
	// timing (SIGTERM, Ctrl-C) that used to leave orphaned .tmp files
	// and uncompressed originals behind.
	for i := range 20 {
		rw.Write(fmt.Appendf(nil, "line-%d-with-some-padding-to-cross-the-threshold\n", i))
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("expected no orphaned .tmp files after Close waits for in-flight compression, found %s", e.Name())
		}
		if strings.HasPrefix(e.Name(), "debug.log.") && !strings.HasSuffix(e.Name(), ".gz") {
			t.Fatalf("expected every rotated part compressed by the time Close returns, found uncompressed leftover %s", e.Name())
		}
	}
}

// TestRotatingWriter_CloseConcurrentWithLateWrites_NoWaitGroupMisuse
// hammers Write/MaybeRotate concurrently with Close under -race,
// checking for crashes, panics, or data races when calls are still in
// flight (e.g. a slow request outliving ServeHTTP's own shutdown grace
// period) as Close runs. It's general concurrent-load coverage, not a
// reliable reproduction of one specific narrow scenario: Write/MaybeRotate
// calls reaching rotateLocked (and so rw.archived.Go, a WaitGroup.Add)
// concurrently with or after Close's own Wait call would be a real
// WaitGroup misuse (see the rw.f = nil guard in Close's own doc
// comment), but that exact race window is too narrow for this test to
// hit deterministically even across many runs, guard present or not.
// The guard is correct by construction regardless (it removes the
// possibility outright rather than relying on timing to avoid it), so
// this test's job is just "nothing else broke," not "prove the guard
// matters."
func TestRotatingWriter_CloseConcurrentWithLateWrites_NoWaitGroupMisuse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "debug.log")

	rw, err := NewRotatingWriter(path, 20)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					rw.Write([]byte("racing-write-padded-out\n"))
					rw.MaybeRotate()
				}
			}
		}()
	}

	// Let the racers run for a moment, then close while they're still
	// actively hammering Write/MaybeRotate.
	time.Sleep(20 * time.Millisecond)
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
	close(stop)
	wg.Wait()
}

func TestLogger_BeginRoundTrip_NilLoggerAndNonRotatingWriterAreNoOps(t *testing.T) {
	var nilLogger *Logger
	nilLogger.BeginRoundTrip() // must not panic

	var buf bytes.Buffer
	l := New(Full, &buf)
	l.BeginRoundTrip() // bytes.Buffer doesn't implement rotator -- must not panic
}

// readGzip decompresses a gzip file and returns its contents as a
// string, failing the test on any error.
func readGzip(t *testing.T, path string) string {
	t.Helper()
	gz, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("gzip.NewReader on %s: %v", path, err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decompress %s: %v", path, err)
	}
	return string(data)
}

// waitForGlob polls briefly for exactly one file matching pattern
// (relative to dir) to appear, since gzip compression runs in a
// background goroutine and rotated files are timestamp-named rather
// than a predictable fixed path.
func waitForGlob(t *testing.T, dir, pattern string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		if len(matches) == 1 {
			return matches[0]
		}
		if len(matches) > 1 {
			t.Fatalf("expected exactly one match for %s, got %v", pattern, matches)
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for a file matching %s in %s", pattern, dir)
	return ""
}
