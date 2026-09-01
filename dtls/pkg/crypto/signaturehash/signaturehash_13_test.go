// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package signaturehash

import (
	"reflect"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
)

func TestAlgorithms13(t *testing.T) {
	algos := Algorithms13()

	// Verify we got expected number of algorithms.
	// ECDSA (3) + Ed25519 (1) + RSA-PSS RSAE (3) = 7. RSA PKCS#1 is not
	// offered: this fork does not implement it. RSA_PSS_PSS is parsed for
	// wire compatibility but never negotiated, so it is not offered either.
	if len(algos) != 7 {
		t.Errorf("Algorithms13 should return 7 signature schemes wrong length: got %d, want %d", len(algos), 7)
	}
	if !reflect.DeepEqual(Algorithm{hash.SHA256, signature.ECDSA}, algos[0]) {
		t.Errorf("expected %v, got %v", Algorithm{hash.SHA256, signature.ECDSA}, algos[0])
	}
	if !reflect.DeepEqual(Algorithm{hash.SHA384, signature.ECDSA}, algos[1]) {
		t.Errorf("expected %v, got %v", Algorithm{hash.SHA384, signature.ECDSA}, algos[1])
	}
	if !reflect.DeepEqual(Algorithm{hash.SHA512, signature.ECDSA}, algos[2]) {
		t.Errorf("expected %v, got %v", Algorithm{hash.SHA512, signature.ECDSA}, algos[2])
	}

	// Verify Ed25519
	if !reflect.DeepEqual(Algorithm{hash.Ed25519, signature.Ed25519}, algos[3]) {
		t.Errorf("expected %v, got %v", Algorithm{hash.Ed25519, signature.Ed25519}, algos[3])
	}

	// Verify RSA-PSS schemes (TLS 1.3 preference for RSA)
	if !reflect.DeepEqual(Algorithm{hash.SHA256, signature.RSA_PSS_RSAE_SHA256}, algos[4]) {
		t.Errorf("expected %v, got %v", Algorithm{hash.SHA256, signature.RSA_PSS_RSAE_SHA256}, algos[4])
	}
	if !reflect.DeepEqual(Algorithm{hash.SHA384, signature.RSA_PSS_RSAE_SHA384}, algos[5]) {
		t.Errorf("expected %v, got %v", Algorithm{hash.SHA384, signature.RSA_PSS_RSAE_SHA384}, algos[5])
	}
	if !reflect.DeepEqual(Algorithm{hash.SHA512, signature.RSA_PSS_RSAE_SHA512}, algos[6]) {
		t.Errorf("expected %v, got %v", Algorithm{hash.SHA512, signature.RSA_PSS_RSAE_SHA512}, algos[6])
	}
}

func TestAlgorithms13_IncludesRSAPSS(t *testing.T) {
	algos := Algorithms13()

	// Verify DTLS 1.3 algorithms include RSA-PSS schemes
	hasRSAPSS := false
	for _, algo := range algos {
		if algo.Signature.IsPSS() {
			hasRSAPSS = true

			break
		}
	}
	if !hasRSAPSS {
		t.Error("Algorithms13 should include RSA-PSS schemes")
	}
}

// There is no test that RSA-PSS is preferred over RSA PKCS#1 v1.5: PKCS#1 is
// not among the offered schemes at all, so the ordering has nothing to compare
// against. TestAlgorithms13 covers the schemes that are offered, and their
// order.
