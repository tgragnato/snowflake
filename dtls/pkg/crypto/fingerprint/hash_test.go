// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package fingerprint

import (
	"crypto"
	"errors"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestHashFromString(t *testing.T) {
	t.Run("InvalidHashAlgorithm", func(t *testing.T) {
		_, err := HashFromString("invalid-hash-algorithm")
		if !errors.Is(err, dtlserrors.ErrFingerprintInvalidHashAlgorithm) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrFingerprintInvalidHashAlgorithm, err)
		}
	})
	t.Run("ValidHashAlgorithm", func(t *testing.T) {
		h, err := HashFromString("sha-512")
		if err != nil {
			t.Error(err)
		}
		if h != crypto.SHA512 {
			t.Errorf("expected %v, got %v", h, crypto.SHA512)
		}
	})
	t.Run("ValidCaseInsensitiveHashAlgorithm", func(t *testing.T) {
		h, err := HashFromString("SHA-512")
		if err != nil {
			t.Error(err)
		}
		if h != crypto.SHA512 {
			t.Errorf("expected %v, got %v", h, crypto.SHA512)
		}
	})
}

func TestStringFromHash_Roundtrip(t *testing.T) {
	for _, h := range nameToHash() {
		s, err := StringFromHash(h)
		if err != nil {
			t.Error(err)
		}

		h2, err := HashFromString(s)
		if err != nil {
			t.Error(err)
		}
		if h != h2 {
			t.Errorf("expected %v, got %v", h, h2)
		}
	}
}
