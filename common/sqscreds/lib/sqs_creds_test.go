package sqscreds

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// TestBase64 verifies that Base64 correctly serializes AwsCreds as a
// base64-encoded JSON string.
func TestBase64(t *testing.T) {
	t.Parallel()

	creds := AwsCreds{
		AwsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
		AwsSecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	encoded, err := creds.Base64()
	if err != nil {
		t.Fatalf("Base64() returned error: %v", err)
	}

	// Decode and verify the content
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64.StdEncoding.DecodeString returned error: %v", err)
	}

	var parsed AwsCreds
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if parsed.AwsAccessKeyId != creds.AwsAccessKeyId {
		t.Errorf("AwsAccessKeyId = %q, want %q", parsed.AwsAccessKeyId, creds.AwsAccessKeyId)
	}
	if parsed.AwsSecretKey != creds.AwsSecretKey {
		t.Errorf("AwsSecretKey = %q, want %q", parsed.AwsSecretKey, creds.AwsSecretKey)
	}
}

// TestBase64Empty verifies that Base64 correctly handles empty credentials.
func TestBase64Empty(t *testing.T) {
	t.Parallel()

	creds := AwsCreds{}
	encoded, err := creds.Base64()
	if err != nil {
		t.Fatalf("Base64() returned error: %v", err)
	}

	if encoded == "" {
		t.Error("Base64() returned empty string for non-empty input")
	}
}

// TestAwsCredsFromBase64 verifies that AwsCredsFromBase64 correctly deserializes
// a base64-encoded JSON string into AwsCreds.
func TestAwsCredsFromBase64(t *testing.T) {
	t.Parallel()

	original := AwsCreds{
		AwsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
		AwsSecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	encoded, err := original.Base64()
	if err != nil {
		t.Fatalf("Base64() returned error: %v", err)
	}

	decoded, err := AwsCredsFromBase64(encoded)
	if err != nil {
		t.Fatalf("AwsCredsFromBase64() returned error: %v", err)
	}

	if decoded.AwsAccessKeyId != original.AwsAccessKeyId {
		t.Errorf("AwsAccessKeyId = %q, want %q", decoded.AwsAccessKeyId, original.AwsAccessKeyId)
	}
	if decoded.AwsSecretKey != original.AwsSecretKey {
		t.Errorf("AwsSecretKey = %q, want %q", decoded.AwsSecretKey, original.AwsSecretKey)
	}
}

// TestAwsCredsFromBase64Invalid verifies that AwsCredsFromBase64 returns an
// error for invalid base64 input.
func TestAwsCredsFromBase64Invalid(t *testing.T) {
	t.Parallel()

	if _, err := AwsCredsFromBase64("not-valid-base64!@#"); err == nil {
		t.Error("AwsCredsFromBase64 succeeded on invalid base64, want error")
	}
}

// TestAwsCredsFromBase64InvalidJSON verifies that AwsCredsFromBase64 returns an
// error when the base64-decoded data is not valid JSON.
func TestAwsCredsFromBase64InvalidJSON(t *testing.T) {
	t.Parallel()

	invalidJSON := base64.StdEncoding.EncodeToString([]byte("not json"))
	if _, err := AwsCredsFromBase64(invalidJSON); err == nil {
		t.Error("AwsCredsFromBase64 succeeded on invalid JSON, want error")
	}
}

// TestRoundTrip verifies that Base64 and AwsCredsFromBase64 are inverse operations.
func TestRoundTrip(t *testing.T) {
	t.Parallel()

	original := AwsCreds{
		AwsAccessKeyId: "id-with-special-chars-!@#$%^&*()",
		AwsSecretKey:   "key/with/slashes/and+plus=signs",
	}

	encoded, err := original.Base64()
	if err != nil {
		t.Fatalf("Base64() returned error: %v", err)
	}

	decoded, err := AwsCredsFromBase64(encoded)
	if err != nil {
		t.Fatalf("AwsCredsFromBase64() returned error: %v", err)
	}

	if decoded.AwsAccessKeyId != original.AwsAccessKeyId {
		t.Errorf("AwsAccessKeyId = %q, want %q", decoded.AwsAccessKeyId, original.AwsAccessKeyId)
	}
	if decoded.AwsSecretKey != original.AwsSecretKey {
		t.Errorf("AwsSecretKey = %q, want %q", decoded.AwsSecretKey, original.AwsSecretKey)
	}
}