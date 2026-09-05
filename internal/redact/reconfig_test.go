package redact

import (
	"regexp"
	"strings"
	"sync"
	"testing"
)

func TestEngine_SetDetectors_TakesEffectForSubsequentCalls(t *testing.T) {
	e, _ := newCorpusEngine(t)

	// Starts with the full default set: domain gets caught.
	out, err := e.Tokenize("visit widgetcorp-fixture.com")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "widgetcorp-fixture.com") {
		t.Fatalf("domain should be redacted before SetDetectors: %q", out)
	}

	// Swap to an empty detector set: nothing should be caught anymore.
	e.SetDetectors(nil)
	out2, err := e.Tokenize("visit widgetcorp-fixture.com again")
	if err != nil {
		t.Fatal(err)
	}
	if out2 != "visit widgetcorp-fixture.com again" {
		t.Fatalf("expected no redaction with an empty detector set, got %q", out2)
	}
}

func TestEngine_SetAllowPatterns_TakesEffectForSubsequentCalls(t *testing.T) {
	e, _ := newCorpusEngine(t)

	e.SetAllowPatterns([]*regexp.Regexp{regexp.MustCompile(`^mylab-fixture\.io$`)})

	out, err := e.Tokenize("target widgetcorp-fixture.com, our lab mylab-fixture.io")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "mylab-fixture.io") {
		t.Errorf("allow-listed domain should stay literal, got %q", out)
	}
	if strings.Contains(out, "widgetcorp-fixture.com") {
		t.Errorf("non-allow-listed domain leaked: %q", out)
	}

	// Clearing the allow-list re-enables redaction for it.
	e.SetAllowPatterns(nil)
	out2, err := e.Tokenize("our lab mylab-fixture.io")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out2, "mylab-fixture.io") {
		t.Errorf("expected redaction to resume after clearing the allow-list, got %q", out2)
	}
}

// TestEngine_AllowList_EmailWholeDetectionDropped confirms the
// documented whole-detection semantics: allow-listing a domain that's
// also part of an email address leaves the WHOLE email untouched (local
// part included), not just the domain portion. See SetAllowPatterns's
// doc comment for why (a Format function assumes every one of its
// Lookups resolved to a real token; partially resolving one and not the
// other isn't representable).
func TestEngine_AllowList_EmailWholeDetectionDropped(t *testing.T) {
	e, _ := newCorpusEngine(t)
	e.SetAllowPatterns([]*regexp.Regexp{regexp.MustCompile(`^mylab-fixture\.io$`)})

	out, err := e.Tokenize("contact admin@mylab-fixture.io for access")
	if err != nil {
		t.Fatal(err)
	}
	if out != "contact admin@mylab-fixture.io for access" {
		t.Fatalf("expected the whole email untouched when its domain is allow-listed, got %q", out)
	}
}

// TestEngine_ConcurrentReloadDuringTokenize stress-tests the atomic-
// pointer swap under -race: many goroutines calling Tokenize while
// SetDetectors/SetAllowPatterns are called concurrently from another
// goroutine, simulating the real proxy's request-serving goroutines
// running alongside its background rules-file watcher.
func TestEngine_ConcurrentReloadDuringTokenize(t *testing.T) {
	e, _ := newCorpusEngine(t)
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if _, err := e.Tokenize("visit widgetcorp-fixture.com and 10.0.0.5"); err != nil {
						t.Error(err)
					}
				}
			}
		}()
	}

	for i := 0; i < 50; i++ {
		e.SetDetectors(DefaultDetectors())
		e.SetAllowPatterns([]*regexp.Regexp{regexp.MustCompile(`^somelab-fixture\.io$`)})
	}
	close(stop)
	wg.Wait()
}
