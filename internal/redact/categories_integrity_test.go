package redact

import "testing"

// TestCategories_NoDuplicateNames guards against a real class of copy-
// paste mistake: DefaultCategorizedDetectors() is a long, hand-written
// literal slice (~40 entries and growing), and appending a new
// {Detector{}, "category", "subcategory", "description"} entry by
// copying a neighboring line is exactly the kind of edit that could
// silently leave the Category/Subcategory unchanged from the line it
// was copied from. A duplicate name means two different detectors would
// share one identity: one would spuriously match the other via
// FilterDetectors' enable/disable lookup (disabling one silently
// disables both), and rules.EnsureAllCategories would collapse both
// slots in a saved rules.json into one entry.
func TestCategories_NoDuplicateNames(t *testing.T) {
	seen := make(map[string][]string) // name -> descriptions seen under it, for a useful failure message
	for _, c := range DefaultCategorizedDetectors() {
		seen[c.Name()] = append(seen[c.Name()], c.Description)
	}
	for name, descriptions := range seen {
		if len(descriptions) > 1 {
			t.Errorf("category %q is registered %d times in DefaultCategorizedDetectors: %v", name, len(descriptions), descriptions)
		}
	}
}

// TestCategories_EveryDetectorHasNonEmptyFields catches an entry
// literal missing a field (category, subcategory, or description left
// as the zero value ""), a real risk in a long hand-written slice
// literal where a misplaced comma or missing field wouldn't be a
// compile error (Go allows partial struct literals) but would produce a
// category name like "" or ".subcategory" that's silently wrong.
func TestCategories_EveryDetectorHasNonEmptyFields(t *testing.T) {
	for _, c := range DefaultCategorizedDetectors() {
		if c.Category == "" {
			t.Errorf("a detector has an empty Category (subcategory=%q, description=%q)", c.Subcategory, c.Description)
		}
		if c.Subcategory == "" {
			t.Errorf("a detector has an empty Subcategory (category=%q, description=%q)", c.Category, c.Description)
		}
		if c.Description == "" {
			t.Errorf("detector %q has an empty Description", c.Name())
		}
		if c.Detector == nil {
			t.Errorf("category %q has a nil Detector", c.Name())
		}
	}
}

// TestCategories_AllCategoryInfoMatchesDetectors pins the relationship
// AllCategoryInfo's own doc comment claims: every DefaultCategorizedDetectors
// entry appears in AllCategoryInfo exactly once, plus exactly the two
// allowlist.* pseudo-categories, plus the newer allowlist.web_infrastructure
// one (three total), no more, no less, and nothing invented or dropped
// in the translation between the two.
func TestCategories_AllCategoryInfoMatchesDetectors(t *testing.T) {
	detectorNames := make(map[string]bool)
	for _, c := range DefaultCategorizedDetectors() {
		detectorNames[c.Name()] = true
	}

	infoNames := make(map[string]bool)
	for _, c := range AllCategoryInfo() {
		if infoNames[c.Name()] {
			t.Errorf("AllCategoryInfo contains duplicate entry %q", c.Name())
		}
		infoNames[c.Name()] = true
	}

	for name := range detectorNames {
		if !infoNames[name] {
			t.Errorf("detector category %q is missing from AllCategoryInfo", name)
		}
	}

	wantAllowlistNames := []string{
		CategoryAllowlist + "." + SubcategoryWellKnownPlatforms,
		CategoryAllowlist + "." + SubcategorySecurityTestingServices,
		CategoryAllowlist + "." + SubcategoryWebInfrastructure,
		CategoryAllowlist + "." + SubcategoryThirdPartySaaS,
	}
	for _, name := range wantAllowlistNames {
		if !infoNames[name] {
			t.Errorf("expected allowlist pseudo-category %q in AllCategoryInfo, missing", name)
		}
	}

	extra := len(infoNames) - len(detectorNames)
	if extra != len(wantAllowlistNames) {
		t.Errorf("AllCategoryInfo has %d entries beyond the real detectors, expected exactly %d (the allowlist pseudo-categories); something extra or missing", extra, len(wantAllowlistNames))
	}
}

// TestCategories_NamingConventions checks the low-level hygiene a large
// hand-written category list can drift on over time: lowercase,
// underscore-separated, no stray whitespace, no accidental dots (which
// would break the "category.subcategory" Name() parsing everywhere else
// in this codebase assumes exactly one dot).
func TestCategories_NamingConventions(t *testing.T) {
	valid := func(s string) bool {
		if s == "" {
			return false
		}
		for _, r := range s {
			allowed := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-'
			if !allowed {
				return false
			}
		}
		return true
	}
	for _, c := range DefaultCategorizedDetectors() {
		if !valid(c.Category) {
			t.Errorf("category %q has non-conforming characters (want lowercase/digits/underscore/hyphen only)", c.Category)
		}
		if !valid(c.Subcategory) {
			t.Errorf("subcategory %q (under category %q) has non-conforming characters", c.Subcategory, c.Category)
		}
	}
}
