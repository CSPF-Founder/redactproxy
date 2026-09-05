package jsonwalk

import "testing"

func TestFindDuplicateKey_TopLevel(t *testing.T) {
	raw := []byte(`{"messages":"first","messages":"second"}`)
	dup, err := findDuplicateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if dup != "messages" {
		t.Fatalf("got %q, want %q", dup, "messages")
	}
}

func TestFindDuplicateKey_NestedInsideObject(t *testing.T) {
	raw := []byte(`{"messages":[{"role":"user","content":"a","content":"b"}]}`)
	dup, err := findDuplicateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if dup != "content" {
		t.Fatalf("got %q, want %q", dup, "content")
	}
}

func TestFindDuplicateKey_DuplicateAcrossDifferentObjectsIsFine(t *testing.T) {
	// The SAME key name appearing in two SIBLING objects (different
	// array elements, or different nesting branches) is completely
	// normal JSON and must never be flagged -- only a duplicate within
	// the SAME object is the actual gjson/encoding/json divergence.
	raw := []byte(`{"messages":[{"role":"user","content":"a"},{"role":"user","content":"b"}]}`)
	dup, err := findDuplicateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if dup != "" {
		t.Fatalf("false positive: flagged %q on a body with no real duplicate", dup)
	}
}

func TestFindDuplicateKey_RepeatedValueDifferentKeysIsFine(t *testing.T) {
	// The same real VALUE appearing twice (e.g. a client mentioned an
	// email address in two different messages) is unrelated to this
	// check -- it only cares about duplicate KEYS, never values.
	raw := []byte(`{"messages":[{"role":"user","content":"admin@fixture.com"},{"role":"assistant","content":"admin@fixture.com"}]}`)
	dup, err := findDuplicateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if dup != "" {
		t.Fatalf("false positive on repeated VALUE (not key): %q", dup)
	}
}

func TestFindDuplicateKey_NoFalsePositiveOnRealWorldShape(t *testing.T) {
	raw := []byte(`{"model":"claude-mock","max_tokens":100,"system":[{"type":"text","text":"sys"}],"messages":[{"role":"user","content":[{"type":"tool_use","id":"t1","name":"n","input":{"a":1,"b":{"c":2}}}]}]}`)
	dup, err := findDuplicateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if dup != "" {
		t.Fatalf("false positive on ordinary well-formed body: %q", dup)
	}
}

func TestTokenize_BlocksBodyWithDuplicateKey(t *testing.T) {
	raw := []byte(`{"model":"x","messages":"redact-me","messages":"me-too-but-different-copy"}`)
	_, err := Tokenize(raw, markTransform)
	if err == nil {
		t.Fatal("expected Tokenize to block a body with a duplicate top-level key, got nil error")
	}
}
