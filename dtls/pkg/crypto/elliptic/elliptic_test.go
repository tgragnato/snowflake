// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package elliptic

import (
	"crypto/rand"
	"errors"
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct {
		in  Curve
		out string
	}{
		{X25519, "X25519"},
		{P384, "P-384"},
		{0, "0x0"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.out, func(t *testing.T) {
			if tt.in.String() != tt.out {
				t.Fatalf("Expected: %s, got: %s", tt.out, tt.in.String())
			}
		})
	}
}

func TestGenerateKeypair_InvalidCurve(t *testing.T) {
	var invalid Curve = 0 // not a supported curve
	_, err := GenerateKeypair(invalid)
	if !errors.Is(err, errInvalidNamedCurve) {
		t.Fatalf("expected error %v, got %v", errInvalidNamedCurve, err)
	}
}

// create a fake reader that is guaranteed to fail to trigger a failure in generate keypair.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) {
	return 0, errors.ErrUnsupported // any error is fine here.
}

func TestGenerateKeypair_RandFailure(t *testing.T) {
	// replace crypto/rand.Reader to force ecdh.GenerateKey to fail.
	orig := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = orig }()

	_, err := GenerateKeypair(P384)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestToECDH_InvalidCurve(t *testing.T) {
	var invalid Curve = 0xFFFF
	_, err := invalid.toECDH()
	if !errors.Is(err, errInvalidNamedCurve) {
		t.Fatalf("expected error %v, got %v", errInvalidNamedCurve, err)
	}
}
