package version

import (
	"regexp"
	"testing"
)

// TestGetVersion verifies that GetVersion returns a non-empty version string.
func TestGetVersion(t *testing.T) {
	t.Parallel()

	ver := GetVersion()
	if ver == "" {
		t.Error("GetVersion() returned empty string")
	}

	// Version should contain at least a version number
	semverRegex := regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)
	if !semverRegex.MatchString(ver) {
		t.Errorf("GetVersion() = %q; expected a valid SemVer string (e.g., 1.0.0 or v1.0.0-alpha)", ver)
	}
}
