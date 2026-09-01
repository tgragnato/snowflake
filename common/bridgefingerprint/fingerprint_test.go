package bridgefingerprint

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestFingerprintFromBytes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		length  int
		wantErr bool
	}{
		{"empty", 0, true},
		{"too short", 19, true},
		{"sha1 length", 20, false},
		{"between the two valid lengths", 21, true},
		{"between the two valid lengths", 31, true},
		{"sha256 length", 32, false},
		{"too long", 33, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			raw := bytes.Repeat([]byte{0xab}, test.length)
			fingerprint, err := FingerprintFromBytes(raw)

			if test.wantErr {
				if !errors.Is(err, ErrBridgeFingerprintInvalid) {
					t.Fatalf("length %d: expected ErrBridgeFingerprintInvalid, got %v", test.length, err)
				}
				if fingerprint != Fingerprint("") {
					t.Errorf("length %d: expected an empty fingerprint on error, got %q", test.length, fingerprint)
				}
				return
			}

			if err != nil {
				t.Fatalf("length %d: unexpected error: %v", test.length, err)
			}
			if !bytes.Equal(fingerprint.ToBytes(), raw) {
				t.Errorf("length %d: ToBytes did not round-trip: got %x, want %x", test.length, fingerprint.ToBytes(), raw)
			}
		})
	}
}

func TestFingerprintFromHexString(t *testing.T) {
	t.Parallel()

	// A real 20-byte bridge fingerprint, as it appears in a torrc Bridge line.
	const sha1Hex = "8838024498816A039FCBBAB14E6F40A0843051FA"
	sha256Hex := strings.Repeat("ab", 32)

	t.Run("sha1 length", func(t *testing.T) {
		t.Parallel()

		fingerprint, err := FingerprintFromHexString(sha1Hex)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want, err := hex.DecodeString(sha1Hex)
		if err != nil {
			t.Fatalf("test fixture is not valid hex: %v", err)
		}
		if !bytes.Equal(fingerprint.ToBytes(), want) {
			t.Errorf("got %x, want %x", fingerprint.ToBytes(), want)
		}
	})

	t.Run("sha256 length", func(t *testing.T) {
		t.Parallel()

		if _, err := FingerprintFromHexString(sha256Hex); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("lowercase hex is accepted", func(t *testing.T) {
		t.Parallel()

		lower, err := FingerprintFromHexString(strings.ToLower(sha1Hex))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		upper, err := FingerprintFromHexString(sha1Hex)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lower != upper {
			t.Errorf("case of the hex string changed the fingerprint: %x vs %x", lower.ToBytes(), upper.ToBytes())
		}
	})

	t.Run("not hex", func(t *testing.T) {
		t.Parallel()

		// Rejected by hex decoding, so this is not ErrBridgeFingerprintInvalid.
		if _, err := FingerprintFromHexString("zzzz"); err == nil {
			t.Fatal("expected an error for a non-hex string")
		}
	})

	t.Run("odd length hex", func(t *testing.T) {
		t.Parallel()

		if _, err := FingerprintFromHexString(sha1Hex[:len(sha1Hex)-1]); err == nil {
			t.Fatal("expected an error for an odd-length hex string")
		}
	})

	t.Run("valid hex of the wrong length", func(t *testing.T) {
		t.Parallel()

		if _, err := FingerprintFromHexString(strings.Repeat("ab", 16)); !errors.Is(err, ErrBridgeFingerprintInvalid) {
			t.Fatalf("expected ErrBridgeFingerprintInvalid, got %v", err)
		}
	})

	t.Run("empty string", func(t *testing.T) {
		t.Parallel()

		if _, err := FingerprintFromHexString(""); !errors.Is(err, ErrBridgeFingerprintInvalid) {
			t.Fatalf("expected ErrBridgeFingerprintInvalid, got %v", err)
		}
	})
}

func TestToBytesPreservesNonUTF8(t *testing.T) {
	t.Parallel()

	// Fingerprints are arbitrary binary held in a string, so bytes that are
	// not valid UTF-8 must survive the round trip unchanged.
	raw := []byte{0xff, 0xfe, 0x00, 0x80}
	raw = append(raw, bytes.Repeat([]byte{0x01}, 16)...)

	fingerprint, err := FingerprintFromBytes(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(fingerprint.ToBytes(), raw) {
		t.Errorf("got %x, want %x", fingerprint.ToBytes(), raw)
	}
}
