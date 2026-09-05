package jsonwalk

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// findDuplicateKey walks raw token-by-token and returns an error naming
// the first duplicate key found within any single JSON object, at any
// nesting depth (top level, inside a message, inside a tool_use.input,
// anywhere). Returns "" if none.
//
// This exists because of a real, confirmed divergence between gjson
// (which collectPaths uses to locate what to redact) and encoding/json
// (the standard library's own decoder, and the convention essentially
// every other JSON parser follows, almost certainly including whatever
// the real upstream API server parses the request with): given a
// duplicate key, gjson resolves to the FIRST occurrence, while
// encoding/json resolves to the LAST. A body containing
// `"messages":[...real content...],"messages":[...same real content,
// unredacted...]` gets its first (dead, overridden) copy correctly
// redacted while the second (the one an ordinary "last key wins" parser,
// and so almost certainly the real API, actually processes) reaches
// upstream in full plaintext; collectPaths never even looked at it.
//
// A normal Claude Code request can never contain a duplicate key (struct
// marshaling can't produce one), so this should never fire in ordinary
// use. This exists purely as a fail-closed backstop against a
// malformed or deliberately adversarial body, the same principle already
// applied to gzip-encoded/invalid-JSON bodies: block rather than risk a
// parser-resolution mismatch silently under-redacting.
func findDuplicateKey(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	return walkForDuplicateKey(dec)
}

func walkForDuplicateKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return "", nil // a scalar value, nothing to recurse into
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return "", err
			}
			key, ok := keyTok.(string)
			if !ok {
				return "", fmt.Errorf("expected object key, got %v", keyTok)
			}
			if seen[key] {
				return key, nil
			}
			seen[key] = true
			if dup, err := walkForDuplicateKey(dec); err != nil || dup != "" {
				return dup, err
			}
		}
		_, err := dec.Token() // consume closing '}'
		return "", err
	case '[':
		for dec.More() {
			if dup, err := walkForDuplicateKey(dec); err != nil || dup != "" {
				return dup, err
			}
		}
		_, err := dec.Token() // consume closing ']'
		return "", err
	}
	return "", nil
}
