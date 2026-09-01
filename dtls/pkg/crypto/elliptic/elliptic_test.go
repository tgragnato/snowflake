// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package elliptic

import (
	"errors"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestString(t *testing.T) {
	tests := []struct {
		in  Curve
		out string
	}{
		{X25519, "X25519"},
		{P384, "P-384"},
		{X25519MLKEM768, "X25519MLKEM768"},
		{0, "0x0"},
	}

	for _, tt := range tests {
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
	if !errors.Is(err, dtlserrors.ErrInvalidNamedCurve) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrInvalidNamedCurve, err)
	}
}

func TestGenerateKeypair_X25519MLKEM768ClientShare(t *testing.T) {
	if !Curves()[X25519MLKEM768] {
		t.Error("expected true")
	}

	keypair, err := GenerateKeypair(X25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	if X25519MLKEM768 != keypair.Curve {
		t.Errorf("expected %v, got %v", X25519MLKEM768, keypair.Curve)
	}
	if len(keypair.PublicKey) != X25519MLKEM768ClientPublicKeySize {
		t.Errorf("wrong length: got %d, want %d", len(keypair.PublicKey), X25519MLKEM768ClientPublicKeySize)
	}
	if len(keypair.PrivateKey) != X25519MLKEM768ClientPrivateKeySize {
		t.Errorf("wrong length: got %d, want %d", len(keypair.PrivateKey), X25519MLKEM768ClientPrivateKeySize)
	}
}

func TestGenerateKeypairForPeer_X25519MLKEM768ServerShare(t *testing.T) {
	clientKeypair, err := GenerateKeypair(X25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}

	serverKeypair, err := GenerateKeypairForPeer(X25519MLKEM768, clientKeypair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if X25519MLKEM768 != serverKeypair.Curve {
		t.Errorf("expected %v, got %v", X25519MLKEM768, serverKeypair.Curve)
	}
	if len(serverKeypair.PublicKey) != X25519MLKEM768ServerPublicKeySize {
		t.Errorf("wrong length: got %d, want %d", len(serverKeypair.PublicKey), X25519MLKEM768ServerPublicKeySize)
	}
	if len(serverKeypair.PrivateKey) != X25519MLKEM768ServerPrivateKeySize {
		t.Errorf("wrong length: got %d, want %d", len(serverKeypair.PrivateKey), X25519MLKEM768ServerPrivateKeySize)
	}
}

func TestGenerateKeypairForPeer_X25519MLKEM768RejectsBadPeerShareLength(t *testing.T) {
	_, err := GenerateKeypairForPeer(X25519MLKEM768, []byte{0x01})
	if !errors.Is(err, dtlserrors.ErrLengthMismatch) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrLengthMismatch, err)
	}
}

// create a fake reader that is guaranteed to fail to trigger a failure in generate keypair.
// The randomness failure path of generateECDHKeypair is not covered: since
// Go 1.24 crypto/ecdh draws from the FIPS-140 internal DRBG and ignores the
// io.Reader it is handed, so replacing crypto/rand.Reader no longer makes
// GenerateKey fail. The same holds for mlkem.GenerateKey768, which takes no
// reader at all. The only reachable error is an unsupported curve, covered by
// TestToECDH_InvalidCurve.

func TestToECDH_InvalidCurve(t *testing.T) {
	var invalid Curve = 0xFFFF
	_, err := invalid.toECDH()
	if !errors.Is(err, dtlserrors.ErrInvalidNamedCurve) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrInvalidNamedCurve, err)
	}
}
