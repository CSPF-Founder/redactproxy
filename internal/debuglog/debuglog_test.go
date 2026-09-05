package debuglog

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"":             Off,
		"off":          Off,
		"new":          NewValues,
		"replacements": Replacements,
		"full":         Full,
	}
	for s, want := range cases {
		got, err := ParseLevel(s)
		if err != nil {
			t.Fatalf("ParseLevel(%q): %v", s, err)
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", s, got, want)
		}
	}
	if _, err := ParseLevel("bogus"); err == nil {
		t.Error("expected an error for an unknown level")
	}
}

func TestLogger_CumulativeVerbosity(t *testing.T) {
	var buf bytes.Buffer
	l := New(Replacements, &buf)

	l.NewValue("domain", "xyzexample.com", "tok1", "tok1.com")
	l.Replacement("tokenize", "domain", "xyzexample.com", "tok1")
	l.FullBody("request", "/v1/messages", []byte(`{"a":"xyzexample.com"}`), []byte(`{"a":"tok1"}`))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 events at Replacements level (NewValue + Replacement, not FullBody), got %d: %v", len(lines), lines)
	}
}

func TestLogger_OffLogsNothing(t *testing.T) {
	var buf bytes.Buffer
	l := New(Off, &buf)
	l.NewValue("domain", "xyzexample.com", "tok1", "tok1.com")
	l.Replacement("tokenize", "domain", "xyzexample.com", "tok1")
	l.FullBody("request", "/v1/messages", []byte("real"), []byte("tok"))
	l.FullSSEFrame("/v1/messages", "upstream", "content_block_delta", "{}")
	if buf.Len() != 0 {
		t.Fatalf("expected no output at Off level, got: %s", buf.String())
	}
}

func TestLogger_FullLevelIncludesEverything(t *testing.T) {
	var buf bytes.Buffer
	l := New(Full, &buf)
	l.NewValue("domain", "xyzexample.com", "tok1", "tok1.com")
	l.Replacement("tokenize", "domain", "xyzexample.com", "tok1")
	l.FullBody("request", "/v1/messages", []byte("real"), []byte("tok"))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected all 3 events at Full level, got %d: %v", len(lines), lines)
	}
}

func TestLogger_NilLoggerIsSafeNoOp(t *testing.T) {
	var l *Logger
	l.NewValue("domain", "xyzexample.com", "tok1", "tok1.com") // must not panic
	l.Replacement("tokenize", "domain", "xyzexample.com", "tok1")
	l.FullBody("request", "/v1/messages", []byte("real"), []byte("tok"))
	if l.Enabled(Full) {
		t.Error("a nil logger must never report itself as enabled")
	}
}

func TestLogger_FullBody_ContainsBothRealAndTokenizedForms(t *testing.T) {
	var buf bytes.Buffer
	l := New(Full, &buf)
	l.FullBody("request", "/v1/messages", []byte(`{"content":"xyzexample.com"}`), []byte(`{"content":"tok1a2b3c"}`))

	var event map[string]any
	if err := json.Unmarshal(buf.Bytes(), &event); err != nil {
		t.Fatalf("expected valid JSON, got error %v for: %s", err, buf.String())
	}
	if !strings.Contains(event["real"].(string), "xyzexample.com") {
		t.Errorf("expected the real form present, got: %+v", event)
	}
	if !strings.Contains(event["tokenized"].(string), "tok1a2b3c") {
		t.Errorf("expected the tokenized form present, got: %+v", event)
	}
	if event["event"] != "full_body" {
		t.Errorf("unexpected event shape: %+v", event)
	}
}

func TestLogger_NewValue_ContainsRealAndToken(t *testing.T) {
	var buf bytes.Buffer
	l := New(NewValues, &buf)
	l.NewValue("domain", "xyzexample.com", "tok1a2b3c", "tok1a2b3c.com")

	var event map[string]any
	if err := json.Unmarshal(buf.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event["real"] != "xyzexample.com" || event["token"] != "tok1a2b3c" {
		t.Errorf("expected real+token in the event, got: %+v", event)
	}
	if event["wire_value"] != "tok1a2b3c.com" {
		t.Errorf("expected the actual wire-visible substitution in wire_value, got: %+v", event)
	}
}
