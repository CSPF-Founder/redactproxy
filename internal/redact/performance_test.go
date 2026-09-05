package redact

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// This file is the regression guard against collectDetections running
// every active detector's full-text regex pass sequentially: Tokenize's
// cost would grow roughly linearly with the number of registered
// detector categories, meaning every new category added to this package
// makes EVERY Tokenize call on EVERY request slower, forever, regardless
// of whether the new category ever matches anything. collectDetections
// parallelizes across goroutines instead (see its doc comment in
// engine.go), biggest win on the "nothing matches" case, which is the
// common case for most of any request's text.
//
// TestCollectDetections_ScalesSublinearlyWithDetectorCount below is a
// ratio test, not an absolute wall-clock ceiling. That's deliberate, since
// absolute timing assertions are flaky across CI/dev-machine speed
// differences. Instead it compares Tokenize's cost with a SMALL detector
// set against the FULL detector set on the same text: if detector
// execution ever regresses back to sequential (someone "simplifies"
// collectDetections, or a future refactor accidentally serializes it
// again), the full set's cost relative to the small set's cost jumps
// from "close to 1x" (parallel work overlapping on available cores) to
// "close to (detector count ratio)x" (sequential), which this test
// catches regardless of how fast or slow the machine it runs on happens
// to be.

func perfEngine(t *testing.T, detectors []Detector) *Engine {
	t.Helper()
	dir := t.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return New(store, detectors...)
}

// timeTokenize runs Tokenize repeatedly for at least minRuns iterations
// or 200ms, whichever is longer, and returns the mean duration: enough
// repetition to average out scheduler/GC noise on a shared CI machine
// without making this test slow.
func timeTokenize(t *testing.T, e *Engine, text string) time.Duration {
	t.Helper()
	const minRuns = 5
	start := time.Now()
	runs := 0
	for runs < minRuns || time.Since(start) < 200*time.Millisecond {
		if _, err := e.Tokenize(text); err != nil {
			t.Fatal(err)
		}
		runs++
	}
	return time.Since(start) / time.Duration(runs)
}

func TestCollectDetections_ScalesSublinearlyWithDetectorCount(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive, skipped in -short")
	}

	text := buildBenchText(20) // ~20KB of realistic mixed report text

	small := []Detector{emailDetector{}, domainDetector{}, ipv4Detector{}}
	full := DefaultDetectors()

	if len(full) < len(small)*5 {
		t.Fatalf("expected the full detector set (%d) to be at least 5x the small set (%d) for this ratio to be meaningful; did DefaultDetectors() shrink drastically?", len(full), len(small))
	}

	smallDur := timeTokenize(t, perfEngine(t, small), text)
	fullDur := timeTokenize(t, perfEngine(t, full), text)

	detectorRatio := float64(len(full)) / float64(len(small))
	timeRatio := float64(fullDur) / float64(smallDur)

	t.Logf("small set: %d detectors, %v/call", len(small), smallDur)
	t.Logf("full set:  %d detectors, %v/call", len(full), fullDur)
	t.Logf("detector count ratio: %.1fx, wall-clock time ratio: %.1fx", detectorRatio, timeRatio)

	// A generous threshold, not a tight one: true sequential execution
	// would put timeRatio close to detectorRatio (~12x here). Parallel
	// execution on any machine with a handful of spare cores should keep
	// timeRatio well under half of detectorRatio. This only needs to
	// catch "did this regress back to fully sequential," not measure
	// exactly how parallel it is.
	threshold := detectorRatio / 2
	if timeRatio > threshold {
		t.Errorf("detector execution appears to have regressed toward sequential: "+
			"%d detectors took %.1fx longer than %d detectors (expected well under %.1fx if still parallelized); "+
			"see collectDetections in engine.go", len(full), timeRatio, len(small), threshold)
	}
}
