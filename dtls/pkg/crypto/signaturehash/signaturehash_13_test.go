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

	// Verify we got expected number of algorithms
	// ECDSA (3) + Ed25519 (1) + RSA-PSS (3) + RSA PKCS#1 (3) = 10
	if len(algos) != 10 {
		t.Errorf("Algorithms13 should return 10 signature schemes wrong length: got %d, want %d", len(algos), 10)
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

func TestAlgorithms13_RSAPSSBeforePKCS1(t *testing.T) {
	algos := Algorithms13()

	// Find positions of first RSA-PSS and first RSA PKCS#1 schemes
	firstRSAPSS := -1
	firstRSA := -1

	for i, algo := range algos {
		if firstRSAPSS == -1 && algo.Signature.IsPSS() {
			firstRSAPSS = i
		}
	}

	// In TLS 1.3, RSA-PSS should be preferred over RSA PKCS#1 v1.5
	if -1 == firstRSAPSS {
		t.Errorf("should not equal %v", -1)
	}
	if -1 == firstRSA {
		t.Errorf("should not equal %v", -1)
	}
	if !(firstRSAPSS < firstRSA) {
		t.Errorf("RSA-PSS schemes should come before RSA PKCS#1 in Algorithms13() for TLS 1.3 preference expected %v < %v", firstRSAPSS, firstRSA)
	}
}
