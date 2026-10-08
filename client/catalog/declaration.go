package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Declaration parsing shared by the catalog importers (spec section 49).
// Both importers expose the declaration axes services.json already accepts
// (sections 46, 47, 48): visibility selectors, ACL-derived visibility and
// cross-organization sharing. The importer only carries the values; the
// control plane still validates selectors against the loaded policy document
// when the node publishes, so a declaration accepted here can still be
// rejected there without the importer guessing.

// parseDeclarationVisibility decodes a JSON array of strings. An empty value
// declares nothing. The raw value is bounded before decoding so a catalog
// cannot make the importer allocate without limit. Errors never echo the
// value: catalog values may be treated as sensitive (AGENTS section 8).
func parseDeclarationVisibility(raw string, maxBytes int) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	if len(raw) > maxBytes {
		return nil, fmt.Errorf("is larger than %d bytes", maxBytes)
	}
	var selectors []string
	if err := json.Unmarshal([]byte(raw), &selectors); err != nil {
		return nil, errors.New("is not a JSON array of strings")
	}
	return selectors, nil
}

// parseDeclarationBool decodes a boolean declaration value. Only "", "true"
// and "false" are accepted: a typo must skip the service with a warning
// instead of silently turning a declaration the operator wrote into false.
func parseDeclarationBool(raw string) (bool, error) {
	switch raw {
	case "":
		return false, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New(`must be "true" or "false"`)
	}
}
