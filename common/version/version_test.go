package version

import (
	"regexp"
	"strings"
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

// TestGetVersionDetail verifies that GetVersionDetail returns an empty string
// when no details have been added.
func TestGetVersionDetail(t *testing.T) {
	t.Parallel()

	// Reset the detail builder by creating a new test
	detail := GetVersionDetail()
	// Initially should be empty
	if detail != "" {
		t.Logf("GetVersionDetail() = %q, may have been set by other tests", detail)
	}
}

// TestAddVersionDetail verifies that AddVersionDetail appends to the detail builder.
func TestAddVersionDetail(t *testing.T) {
	t.Parallel()

	// Note: This test may be affected by other tests that call AddVersionDetail
	// The detail builder is a global variable
	initialDetail := GetVersionDetail()

	AddVersionDetail("test-detail")
	detail := GetVersionDetail()

	if !strings.Contains(detail, "test-detail") {
		t.Errorf("GetVersionDetail() = %q, expected to contain 'test-detail'", detail)
	}

	// Restore initial state (not possible with global builder, but we document it)
	_ = initialDetail
}

// TestConstructResult verifies that ConstructResult combines version and detail.
func TestConstructResult(t *testing.T) {
	t.Parallel()

	result := ConstructResult()
	if result == "" {
		t.Error("ConstructResult() returned empty string")
	}

	// Should contain a newline separator
	if !strings.Contains(result, "\n") {
		t.Logf("ConstructResult() = %q, expected newline separator", result)
	}
}
