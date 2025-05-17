// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"hash"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// CipherSuiteID is an ID for our supported CipherSuites.
type CipherSuiteID = ciphersuite.ID

// Supported Cipher Suites.
const (
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 CipherSuiteID = ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	TLS_PSK_WITH_AES_128_GCM_SHA256         CipherSuiteID = ciphersuite.TLS_PSK_WITH_AES_128_GCM_SHA256
)

// CipherSuiteAuthenticationType controls what authentication method is using during the handshake for a CipherSuite.
type CipherSuiteAuthenticationType = ciphersuite.AuthenticationType

// AuthenticationType Enums.
const (
	CipherSuiteAuthenticationTypeCertificate  CipherSuiteAuthenticationType = ciphersuite.AuthenticationTypeCertificate
	CipherSuiteAuthenticationTypePreSharedKey CipherSuiteAuthenticationType = ciphersuite.AuthenticationTypePreSharedKey
	CipherSuiteAuthenticationTypeAnonymous    CipherSuiteAuthenticationType = ciphersuite.AuthenticationTypeAnonymous
)

// CipherSuiteKeyExchangeAlgorithm controls what exchange algorithm is using during the handshake for a CipherSuite.
type CipherSuiteKeyExchangeAlgorithm = ciphersuite.KeyExchangeAlgorithm

// CipherSuiteKeyExchangeAlgorithm Bitmask.
const (
	CipherSuiteKeyExchangeAlgorithmNone  CipherSuiteKeyExchangeAlgorithm = ciphersuite.KeyExchangeAlgorithmNone
	CipherSuiteKeyExchangeAlgorithmPsk   CipherSuiteKeyExchangeAlgorithm = ciphersuite.KeyExchangeAlgorithmPsk
	CipherSuiteKeyExchangeAlgorithmEcdhe CipherSuiteKeyExchangeAlgorithm = ciphersuite.KeyExchangeAlgorithmEcdhe
)

var _ = allCipherSuites() // Necessary until this function isn't only used by Go 1.14

// CipherSuite is an interface that all DTLS CipherSuites must satisfy.
type CipherSuite interface {
	// String of CipherSuite, only used for logging
	String() string

	// ID of CipherSuite.
	ID() CipherSuiteID

	// What type of Certificate does this CipherSuite use
	CertificateType() clientcertificate.Type

	// What Hash function is used during verification
	HashFunc() func() hash.Hash

	// AuthenticationType controls what authentication method is using during the handshake
	AuthenticationType() CipherSuiteAuthenticationType

	// KeyExchangeAlgorithm controls what exchange algorithm is using during the handshake
	KeyExchangeAlgorithm() CipherSuiteKeyExchangeAlgorithm

	// ECC (Elliptic Curve Cryptography) determines whether ECC extesions will be send during handshake.
	// https://datatracker.ietf.org/doc/html/rfc4492#page-10
	ECC() bool

	// Called when keying material has been generated, should initialize the internal cipher
	Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error
	IsInitialized() bool
	Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error)
	Decrypt(h recordlayer.Header, in []byte) ([]byte, error)
}

// CipherSuiteName provides the same functionality as tls.CipherSuiteName
// that appeared first in Go 1.14.
//
// Our implementation differs slightly in that it takes in a CiperSuiteID,
// like the rest of our library, instead of a uint16 like crypto/tls.
func CipherSuiteName(id CipherSuiteID) string {
	suite := cipherSuiteForID(id, nil)
	if suite != nil {
		return suite.String()
	}

	return fmt.Sprintf("0x%04X", uint16(id))
}

// Taken from https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
// A cipherSuite is a specific combination of key agreement, cipher and MAC
// function.
func cipherSuiteForID(id CipherSuiteID, customCiphers func() []CipherSuite) CipherSuite {
	switch id {
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return &ciphersuite.TLSPskWithAes128GcmSha256{}
	case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return &ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{}
	}

	if customCiphers != nil {
		for _, c := range customCiphers() {
			if c.ID() == id {
				return c
			}
		}
	}

	return nil
}

// CipherSuites we support in order of preference.
func defaultCipherSuites() []CipherSuite {
	return []CipherSuite{
		&ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{},
	}
}

func allCipherSuites() []CipherSuite {
	return []CipherSuite{
		&ciphersuite.TLSPskWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{},
	}
}

func cipherSuiteIDs(cipherSuites []CipherSuite) []uint16 {
	rtrn := []uint16{}
	for _, c := range cipherSuites {
		rtrn = append(rtrn, uint16(c.ID()))
	}

	return rtrn
}

func parseCipherSuites(
	userSelectedSuites []CipherSuiteID,
	customCipherSuites func() []CipherSuite,
	includeCertificateSuites, includePSKSuites bool,
) ([]CipherSuite, error) {
	cipherSuitesForIDs := func(ids []CipherSuiteID) ([]CipherSuite, error) {
		cipherSuites := []CipherSuite{}
		for _, id := range ids {
			c := cipherSuiteForID(id, nil)
			if c == nil {
				return nil, &invalidCipherSuiteError{id}
			}
			cipherSuites = append(cipherSuites, c)
		}

		return cipherSuites, nil
	}

	var (
		cipherSuites []CipherSuite
		err          error
		i            int
	)
	if userSelectedSuites != nil {
		cipherSuites, err = cipherSuitesForIDs(userSelectedSuites)
		if err != nil {
			return nil, err
		}
	} else {
		cipherSuites = defaultCipherSuites()
	}

	// Put CustomCipherSuites before ID selected suites
	if customCipherSuites != nil {
		cipherSuites = append(customCipherSuites(), cipherSuites...)
	}

	var foundCertificateSuite, foundPSKSuite, foundAnonymousSuite bool
	for _, c := range cipherSuites {
		switch {
		case includeCertificateSuites && c.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate:
			foundCertificateSuite = true
		case includePSKSuites && c.AuthenticationType() == CipherSuiteAuthenticationTypePreSharedKey:
			foundPSKSuite = true
		case c.AuthenticationType() == CipherSuiteAuthenticationTypeAnonymous:
			foundAnonymousSuite = true
		default:
			continue
		}
		cipherSuites[i] = c
		i++
	}

	switch {
	case includeCertificateSuites && !foundCertificateSuite && !foundAnonymousSuite:
		return nil, errNoAvailableCertificateCipherSuite
	case includePSKSuites && !foundPSKSuite:
		return nil, errNoAvailablePSKCipherSuite
	case i == 0:
		return nil, errNoAvailableCipherSuites
	}

	return cipherSuites[:i], nil
}

func filterCipherSuitesForCertificate(cert *tls.Certificate, cipherSuites []CipherSuite) []CipherSuite {
	if cert == nil || cert.PrivateKey == nil {
		return cipherSuites
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return cipherSuites
	}

	var certType clientcertificate.Type
	switch signer.Public().(type) {
	case ed25519.PublicKey, *ecdsa.PublicKey:
		certType = clientcertificate.ECDSASign
	}

	filtered := []CipherSuite{}
	for _, c := range cipherSuites {
		if c.AuthenticationType() != CipherSuiteAuthenticationTypeCertificate || certType == c.CertificateType() {
			filtered = append(filtered, c)
		}
	}

	return filtered
}
