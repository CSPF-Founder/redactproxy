package redact

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// categoriesDocPath is the manual page listing every detector category.
// Relative to this package's directory, which is where `go test` runs.
const categoriesDocPath = "../../docs/src/reference/categories.md"

// docCountRe matches the page's own "There are N detector categories."
// sentence, the one number a reader is most likely to trust without
// counting the tables themselves.
var docCountRe = regexp.MustCompile(`There are (\d+) detector categories`)

// TestCategoriesDocIsCurrent keeps docs/src/reference/categories.md in
// step with AllCategoryInfo. The page is hand-written prose around a
// generated-looking table, and the failure mode it guards against is
// the quiet one: someone adds a detector, `rules show` picks it up
// automatically, and the published manual silently stops being the
// complete list it claims to be.
//
// Skips rather than fails when the file is absent, so the package still
// tests cleanly in a checkout or module cache that carries the code
// without the docs tree.
func TestCategoriesDocIsCurrent(t *testing.T) {
	data, err := os.ReadFile(categoriesDocPath)
	if os.IsNotExist(err) {
		t.Skipf("%s not present, skipping", categoriesDocPath)
	}
	if err != nil {
		t.Fatalf("read %s: %v", categoriesDocPath, err)
	}
	doc := string(data)

	infos := AllCategoryInfo()

	var missing []string
	for _, info := range infos {
		if !strings.Contains(doc, "`"+info.Name()+"`") {
			missing = append(missing, info.Name())
		}
	}
	if len(missing) > 0 {
		abs, _ := filepath.Abs(categoriesDocPath)
		t.Errorf("%d categor%s missing from %s: %s\nAdd a row for each to the matching table (see `redactproxy rules show` for the description text).",
			len(missing), categoryPlural(len(missing)), abs, strings.Join(missing, ", "))
	}

	m := docCountRe.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("%s no longer states a category count; the %q sentence is what this test keeps honest", categoriesDocPath, "There are N detector categories")
	}
	stated, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse stated category count %q: %v", m[1], err)
	}
	if stated != len(infos) {
		t.Errorf("%s says there are %d detector categories, but AllCategoryInfo returns %d", categoriesDocPath, stated, len(infos))
	}
}

// categoryPlural is spelled out rather than reaching for a shared
// helper: this file is the only place in the package that needs it.
func categoryPlural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
