package catalog

import (
	"strings"
	"testing"
)

// TestParseDeclarationVisibility covers the shared JSON array decoding used by
// both importers (spec section 49).
func TestParseDeclarationVisibility(t *testing.T) {
	selectors, err := parseDeclarationVisibility(`["tag:prod","group:eng","tag:prod"]`, 1<<10)
	if err != nil || len(selectors) != 3 || selectors[0] != "tag:prod" {
		t.Fatalf("selectors = %v, err = %v", selectors, err)
	}
	if selectors, err := parseDeclarationVisibility(" ", 1<<10); err != nil || selectors != nil {
		t.Errorf("empty value = %v, err = %v", selectors, err)
	}
	if selectors, err := parseDeclarationVisibility("null", 1<<10); err != nil || selectors != nil {
		t.Errorf("null = %v, err = %v", selectors, err)
	}

	for _, raw := range []string{`{"password":"hunter2"}`, `[1,2]`, `"tag:prod"`, `[`} {
		_, err := parseDeclarationVisibility(raw, 1<<10)
		if err == nil {
			t.Errorf("%q was accepted", raw)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("error leaks the value: %v", err)
		}
	}
	if _, err := parseDeclarationVisibility(`["tag:prod"]`, 4); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized value error = %v", err)
	}
}

// TestParseDeclarationBool covers the strict boolean decoding: only the exact
// spellings are accepted so a typo skips the service with a warning.
func TestParseDeclarationBool(t *testing.T) {
	for raw, want := range map[string]bool{"": false, "true": true, "false": false} {
		got, err := parseDeclarationBool(raw)
		if err != nil || got != want {
			t.Errorf("parseDeclarationBool(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, raw := range []string{"True", "TRUE", "true ", " yes", "1"} {
		if _, err := parseDeclarationBool(raw); err == nil {
			t.Errorf("parseDeclarationBool(%q) was accepted", raw)
		}
	}
}
