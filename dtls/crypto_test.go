// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	stdelliptic "crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlscrypto "github.com/pion/dtls/v3/internal/handshakecrypto"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

// RSA-PSS certificate with id-RSASSA-PSS OID (1.2.840.113549.1.1.10)
// Generated with:
//
//	openssl genpkey -algorithm RSA-PSS -out rsa_pss_key.pem -pkeyopt rsa_keygen_bits:2048
//	openssl req -new -x509 -key rsa_pss_key.pem -out rsa_pss_cert.pem -days 365 -subj "/CN=RSA-PSS-Test"
//
// Note: Go's x509.CreateCertificate does not support creating RSA-PSS certificates,
// and x509.ParsePKCS8PrivateKey cannot parse RSA-PSS private keys (fails with
// "PKCS#8 wrapping contained private key with unknown algorithm: 1.2.840.113549.1.1.10").
// Therefore we use this cert for OID validation testing only.
const rsaPSSCertificate = `
-----BEGIN CERTIFICATE-----
MIIDdTCCAimgAwIBAgIUOvVXWgzlj9KVp4TQe+ZATB3PkvswQQYJKoZIhvcNAQEK
MDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEF
AKIDAgEgMBcxFTATBgNVBAMMDFJTQS1QU1MtVGVzdDAeFw0yNjAxMjQwNDE1MzFa
Fw0yNzAxMjQwNDE1MzFaMBcxFTATBgNVBAMMDFJTQS1QU1MtVGVzdDCCASAwCwYJ
KoZIhvcNAQEKA4IBDwAwggEKAoIBAQCpwVkHm2eU336pNtW7VYuu7nWUkSZxr9Oz
DAQrZbLsdcSeWj/sSe37/EPmtQrH8f8mK7OR7mY1DrodHyAqyGeeHIwTaAMdrrMX
X0RiPbid7w6MU3QZ1q5Hp8IAf8sLrQofchFRLDw6XkMcI4hbWtVJ9GwZiOO2gpDk
uS7SBLEiEzKHme+UzPMFUa2xCypYd/bpO0F+h9vtPDFTCRfK6EFf7mb/QAl1UwfO
Xq5+hMMiKWyhK2OIKhYc98k7eV7nlC4rz5tMY2v1tUJA6/fAZEmAREVE740hxmkN
qN5Enm5tF/ipROPbmQnyCkwtZxKTLi0tz8RTq7lZXRoQr9fo/6ufAgMBAAGjUzBR
MB0GA1UdDgQWBBRpdc2ssJhWnWTm4DPJLW3aDy71WTAfBgNVHSMEGDAWgBRpdc2s
sJhWnWTm4DPJLW3aDy71WTAPBgNVHRMBAf8EBTADAQH/MEEGCSqGSIb3DQEBCjA0
oA8wDQYJYIZIAWUDBAIBBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAIBBQCi
AwIBIAOCAQEATkolVgnlASfTEvMElGmrLTRVPBovk7ZCpER+/H316xswuUDWKn9t
BUhSCYinj5yywgwgx4sErnB5YkB+SR2kkE8WMAU0SNTh2kLUr4TrdqM1o0S5hGQT
awGCPIWZjip3V0TeAqC4sWTgdy2EBYPEJ0AZGm50/yJlWiOzsdDbzceKjremCxLF
Qgkrd/H9mRfIsybvQZ0SbhCWTbNiGpv+O3q4rJ8l3FiaNc9xt+9/FbzeRIipmVb3
ACeCkdjZt/3rjb/tZRHcURgXYi2109wQOaIE5tAQYFCvaKp3HNdWGU1K5+AO0SIY
k2mwB2RsEXa29/Xzj1eMyG33CDgo55AtDw==
-----END CERTIFICATE-----
`

const rawPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxIA2BrrnR2sIlATsp7aRBD/3krwZ7vt9dNeoDQAee0s6SuYP
6MBx/HPnAkwNvPS90R05a7pwRkoT6Ur4PfPhCVlUe8lV+0Eto3ZSEeHz3HdsqlM3
bso67L7Dqrc7MdVstlKcgJi8yeAoGOIL9/igOv0XBFCeznm9nznx6mnsR5cugw+1
ypXelaHmBCLV7r5SeVSh57+KhvZGbQ2fFpUaTPegRpJZXBNS8lSeWvtOv9d6N5UB
ROTAJodMZT5AfX0jB0QB9IT/0I96H6BSENH08NXOeXApMuLKvnAf361rS7cRAfRL
rWZqERMP4u6Cnk0Cnckc3WcW27kGGIbtwbqUIQIDAQABAoIBAGF7OVIdZp8Hejn0
N3L8HvT8xtUEe9kS6ioM0lGgvX5s035Uo4/T6LhUx0VcdXRH9eLHnLTUyN4V4cra
ZkxVsE3zAvZl60G6E+oDyLMWZOP6Wu4kWlub9597A5atT7BpMIVCdmFVZFLB4SJ3
AXkC3nplFAYP+Lh1rJxRIrIn2g+pEeBboWbYA++oDNuMQffDZaokTkJ8Bn1JZYh0
xEXKY8Bi2Egd5NMeZa1UFO6y8tUbZfwgVs6Enq5uOgtfayq79vZwyjj1kd29MBUD
8g8byV053ZKxbUOiOuUts97eb+fN3DIDRTcT2c+lXt/4C54M1FclJAbtYRK/qwsl
pYWKQAECgYEA4ZUbqQnTo1ICvj81ifGrz+H4LKQqe92Hbf/W51D/Umk2kP702W22
HP4CvrJRtALThJIG9m2TwUjl/WAuZIBrhSAbIvc3Fcoa2HjdRp+sO5U1ueDq7d/S
Z+PxRI8cbLbRpEdIaoR46qr/2uWZ943PHMv9h4VHPYn1w8b94hwD6vkCgYEA3v87
mFLzyM9ercnEv9zHMRlMZFQhlcUGQZvfb8BuJYl/WogyT6vRrUuM0QXULNEPlrin
mBQTqc1nCYbgkFFsD2VVt1qIyiAJsB9MD1LNV6YuvE7T2KOSadmsA4fa9PUqbr71
hf3lTTq+LeR09LebO7WgSGYY+5YKVOEGpYMR1GkCgYEAxPVQmk3HKHEhjgRYdaG5
lp9A9ZE8uruYVJWtiHgzBTxx9TV2iST+fd/We7PsHFTfY3+wbpcMDBXfIVRKDVwH
BMwchXH9+Ztlxx34bYJaegd0SmA0Hw9ugWEHNgoSEmWpM1s9wir5/ELjc7dGsFtz
uzvsl9fpdLSxDYgAAdzeGtkCgYBAzKIgrVox7DBzB8KojhtD5ToRnXD0+H/M6OKQ
srZPKhlb0V/tTtxrIx0UUEFLlKSXA6mPw6XDHfDnD86JoV9pSeUSlrhRI+Ysy6tq
eIE7CwthpPZiaYXORHZ7wCqcK/HcpJjsCs9rFbrV0yE5S3FMdIbTAvgXg44VBB7O
UbwIoQKBgDuY8gSrA5/A747wjjmsdRWK4DMTMEV4eCW1BEP7Tg7Cxd5n3xPJiYhr
nhLGN+mMnVIcv2zEMS0/eNZr1j/0BtEdx+3IC6Eq+ONY0anZ4Irt57/5QeKgKn/L
JPhfPySIPG4UmwE4gW8t79vfOKxnUu2fDD1ZXUYopan6EckACNH/
-----END RSA PRIVATE KEY-----
`

// TestGenerateKeySignature checks that a generated signature verifies, for each
// key type the fork still signs with. It cannot assert a fixed expected
// signature: RSA-PSS is randomised, and RSA signing is refused by config
// validation anyway, so a golden vector is only possible for algorithms this
// fork no longer uses.
func TestGenerateKeySignature(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(stdelliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	clientRandom := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	serverRandom := []byte{
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	}
	publicKey := []byte{
		0x20, 0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10,
		0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15,
	}
	for _, test := range []struct {
		name    string
		key     crypto.Signer
		hashAlg hash.Algorithm
		sigAlg  signature.Algorithm
	}{
		{"ECDSA P-256", ecdsaKey, hash.SHA256, signature.ECDSA},
		{"Ed25519", ed25519Key, hash.Ed25519, signature.Ed25519},
	} {
		t.Run(test.name, func(t *testing.T) {
			template := &x509.Certificate{SerialNumber: big.NewInt(1)}
			rawCert, err := x509.CreateCertificate(
				rand.Reader, template, template, test.key.Public(), test.key,
			)
			if err != nil {
				t.Fatal(err)
			}

			sig, err := dtlscrypto.GenerateKeySignature(
				clientRandom, serverRandom, publicKey, elliptic.X25519,
				test.key, test.hashAlg, test.sigAlg,
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(sig) == 0 {
				t.Fatal("expected a non-empty signature")
			}

			message := dtlscrypto.ValueKeyMessage(clientRandom, serverRandom, publicKey, elliptic.X25519)
			if err := dtlscrypto.VerifyKeySignature(
				message, sig, test.hashAlg, test.sigAlg, [][]byte{rawCert},
			); err != nil {
				t.Fatalf("the generated signature did not verify: %v", err)
			}

			// The signature must be bound to the message it was made over.
			tampered := append([]byte(nil), message...)
			tampered[0] ^= 0xff
			if err := dtlscrypto.VerifyKeySignature(
				tampered, sig, test.hashAlg, test.sigAlg, [][]byte{rawCert},
			); err == nil {
				t.Error("a tampered message verified")
			}
		})
	}
}

func TestRSAPSSSignatureGeneration(t *testing.T) {
	clientRandom := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	serverRandom := []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	publicKey := []byte{0x10, 0x11, 0x12, 0x13}

	// Parse the private key
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Error("error: ", err)
	}

	// Generate PSS signature
	sig, err := dtlscrypto.GenerateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
		key, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
	if err != nil {
		t.Error("error: ", err)
	}
	if sig == nil {
		t.Error("expected not nil")
	}

	// Verify that PSS signature is different from PKCS#1 v1.5 (PSS is randomized)
	sig2, err := dtlscrypto.GenerateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
		key, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
	if err != nil {
		t.Error("error: ", err)
	}
	// PSS signatures should be different each time due to random salt
	if bytes.Equal(sig, sig2) {
		t.Errorf("expected not equal %v, got %v", sig, sig2)
	}
}

func TestRSAPSSSignatureVerification(t *testing.T) {
	clientRandom := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	serverRandom := []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	publicKey := []byte{0x10, 0x11, 0x12, 0x13}

	// Parse the private key
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Error("error: ", err)
	}

	// Generate certificate with the public key
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &key.PublicKey,
	}
	rawCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Error("error: ", err)
	}

	// Generate PSS signature
	sig, err := dtlscrypto.GenerateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
		key, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
	if err != nil {
		t.Error("error: ", err)
	}

	// Verify PSS signature
	expectedMsg := dtlscrypto.ValueKeyMessage(clientRandom, serverRandom, publicKey, elliptic.X25519)
	err = dtlscrypto.VerifyKeySignature(expectedMsg, sig, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, [][]byte{rawCert})
	if err != nil {
		t.Error("error: ", err)
	}

	// An RSA certificate paired with a non-PSS signature algorithm must be
	// refused rather than falling back to PKCS#1 v1.5, which this fork does
	// not verify at all.
	err = dtlscrypto.VerifyKeySignature(expectedMsg, sig, hash.SHA256, signature.ECDSA, [][]byte{rawCert})
	if !errors.Is(err, dtlserrors.ErrKeySignatureVerifyUnimplemented) {
		t.Errorf("expected %v, got %v", dtlserrors.ErrKeySignatureVerifyUnimplemented, err)
	}
}

func TestRSAPSSRSAEVariants(t *testing.T) {
	clientRandom := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	serverRandom := []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	publicKey := []byte{0x10, 0x11, 0x12, 0x13}

	// Parse the private key
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Error("error: ", err)
	}

	// Generate certificate with rsaEncryption OID (standard RSA cert)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &key.PublicKey,
	}
	rawCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Error("error: ", err)
	}

	expectedMsg := dtlscrypto.ValueKeyMessage(clientRandom, serverRandom, publicKey, elliptic.X25519)

	// Test RSA-PSS RSAE variants (work with standard RSA certs)
	// Note: We don't test RSA_PSS_PSS variants here because they require id-RSASSA-PSS OID certs,
	// which Go's x509.CreateCertificate doesn't support creating (and can't parse properly either).
	// OID validation is tested separately in TestCertificateOIDValidation.
	testCases := []struct {
		name     string
		hashAlgo hash.Algorithm
		sigAlgo  signature.Algorithm
	}{
		{"RSA_PSS_RSAE_SHA256", hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
		{"RSA_PSS_RSAE_SHA384", hash.SHA384, signature.RSA_PSS_RSAE_SHA384},
		{"RSA_PSS_RSAE_SHA512", hash.SHA512, signature.RSA_PSS_RSAE_SHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate signature
			sig, err := dtlscrypto.GenerateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
				key, tc.hashAlgo, tc.sigAlgo)
			if err != nil {
				t.Error("error: ", err)
			}
			if sig == nil {
				t.Error("expected not nil")
			}
			if !(len(sig) > 0) {
				t.Error("Signature should not be empty")
			}

			// Verify signature
			err = dtlscrypto.VerifyKeySignature(expectedMsg, sig, tc.hashAlgo, tc.sigAlgo, [][]byte{rawCert})
			if err != nil {
				t.Error("Signature verification should succeed")
			}

			// Verify IsPSS() returns true
			if !tc.sigAlgo.IsPSS() {
				t.Fatal("condition is false")
			}

			// Verify GetPSSHash() returns correct hash
			if tc.hashAlgo != tc.sigAlgo.GetPSSHash() {
				t.Fatalf("expected %v, got %v", tc.hashAlgo, tc.sigAlgo.GetPSSHash())
			}
		})
	}
}

func TestCertificateOIDValidation(t *testing.T) {
	clientRandom := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	serverRandom := []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	publicKey := []byte{0x10, 0x11, 0x12, 0x13}

	// Load standard RSA key and cert (has rsaEncryption OID)
	block, _ := pem.Decode([]byte(rawPrivateKey))
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Error("error: ", err)
	}

	rsaEncryptionCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &rsaKey.PublicKey,
	}
	rsaEncryptionCertBytes, err := x509.CreateCertificate(
		rand.Reader, rsaEncryptionCert, rsaEncryptionCert, &rsaKey.PublicKey, rsaKey,
	)
	if err != nil {
		t.Error("error: ", err)
	}

	// Load RSA-PSS cert (has id-RSASSA-PSS OID)
	// We use a locally generated RSA-PSS cert since Go's x509.CreateCertificate doesn't support creating them.
	// We use the regular RSA key for signing because Go can't parse RSA-PSS private keys either.
	// For OID validation testing, only the cert's OID matters, not which key was used to sign.
	pssCertBlock, _ := pem.Decode([]byte(rsaPSSCertificate))
	pssCertBytes := pssCertBlock.Bytes

	expectedMsg := dtlscrypto.ValueKeyMessage(clientRandom, serverRandom, publicKey, elliptic.X25519)

	t.Run("RSAE_with_rsaEncryption_OID_succeeds", func(t *testing.T) {
		// Generate signature with RSAE algorithm using rsaEncryption cert
		sig, err := dtlscrypto.GenerateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
			rsaKey, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
		if err != nil {
			t.Error("error: ", err)
		}

		// Should succeed: RSAE + rsaEncryption OID is valid per RFC 8446
		err = dtlscrypto.VerifyKeySignature(
			expectedMsg, sig, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, [][]byte{rsaEncryptionCertBytes},
		)
		if err != nil {
			t.Error("error: ", err)
		}
	})

	t.Run("PSS_with_idRSASSAPSS_OID_succeeds", func(t *testing.T) {
		t.Skip("Go's x509 library cannot extract public key from RSA-PSS certificates (OID 1.2.840.113549.1.1.10)")
		// This test would verify that PSS + id-RSASSA-PSS OID is valid per RFC 8446,
		// but Go's crypto/x509 doesn't fully support parsing RSA-PSS certs.
		// The important validation (that mismatches are rejected) is tested in other cases.
	})

	t.Run("PSS_with_rsaEncryption_OID_fails", func(t *testing.T) {
		// Generate signature with PSS algorithm
		sig, err := dtlscrypto.GenerateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
			rsaKey, hash.SHA256, signature.RSA_PSS_PSS_SHA256)
		if err != nil {
			t.Error("error: ", err)
		}

		// Should fail: PSS algorithm requires id-RSASSA-PSS OID, not rsaEncryption
		err = dtlscrypto.VerifyKeySignature(
			expectedMsg, sig, hash.SHA256, signature.RSA_PSS_PSS_SHA256, [][]byte{rsaEncryptionCertBytes},
		)
		if err == nil {
			t.Error("expected error")
		}
		if !errors.Is(err, dtlserrors.ErrInvalidCertificateOID) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidCertificateOID, err)
		}
	})

	t.Run("RSAE_with_idRSASSAPSS_OID_fails", func(t *testing.T) {
		// Generate signature with RSAE algorithm
		sig, err := dtlscrypto.GenerateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
			rsaKey, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
		if err != nil {
			t.Error("error: ", err)
		}

		// Should fail: RSAE algorithm requires rsaEncryption OID, not id-RSASSA-PSS
		err = dtlscrypto.VerifyKeySignature(
			expectedMsg, sig, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, [][]byte{pssCertBytes},
		)
		if err == nil {
			t.Error("expected error")
		}
		if !errors.Is(err, dtlserrors.ErrInvalidCertificateOID) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidCertificateOID, err)
		}
	})
}

func TestValidateCertificateSignatureAlgorithms(t *testing.T) {
	// Helper to create a test certificate with specific signature algorithm
	createTestCert := func(sigAlg x509.SignatureAlgorithm, isCA bool) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:       big.NewInt(1),
			SignatureAlgorithm: sigAlg,
			IsCA:               isCA,
		}
	}

	t.Run("Empty allowed list passes", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.ECDSAWithSHA256, false),
		}
		err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, nil)
		if err != nil {
			t.Error("error: ", err)
		}
	})

	t.Run("Single cert with allowed algorithm passes", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.ECDSAWithSHA256, false),
			createTestCert(x509.ECDSAWithSHA256, true), // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA},
		}
		err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, allowed)
		if err != nil {
			t.Error("error: ", err)
		}
	})

	t.Run("Single cert with disallowed algorithm fails", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.ECDSAWithSHA256, false),
			createTestCert(x509.ECDSAWithSHA256, true), // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA384, Signature: signature.ECDSA}, // Different algorithm
		}
		err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, allowed)
		if !errors.Is(err, dtlserrors.ErrInvalidCertificateSignatureAlgorithm) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidCertificateSignatureAlgorithm, err)
		}
	})

	t.Run("Root certificate is not validated", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.ECDSAWithSHA256, false), // Leaf - validated
			createTestCert(x509.ECDSAWithSHA384, true),  // Root - NOT validated
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA}, // Only allows SHA256
		}
		// Should pass because root (SHA384) is not validated
		err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, allowed)
		if err != nil {
			t.Error("error: ", err)
		}
	})

	t.Run("Multi-cert chain with all allowed algorithms passes", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.ECDSAWithSHA256, false), // Leaf
			createTestCert(x509.ECDSAWithSHA384, false), // Intermediate
			createTestCert(x509.ECDSAWithSHA512, true),  // Root (not validated)
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA},
			{Hash: hash.SHA384, Signature: signature.ECDSA},
			// SHA512 not needed since root is not validated
		}
		err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, allowed)
		if err != nil {
			t.Error("error: ", err)
		}
	})

	t.Run("Multi-cert chain with one disallowed intermediate fails", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.ECDSAWithSHA256, false), // Leaf - allowed
			createTestCert(x509.ECDSAWithSHA384, false), // Intermediate - NOT allowed
			createTestCert(x509.ECDSAWithSHA512, true),  // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA}, // Only allows SHA256
		}
		err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, allowed)
		if !errors.Is(err, dtlserrors.ErrInvalidCertificateSignatureAlgorithm) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidCertificateSignatureAlgorithm, err)
		}
	})

	t.Run("ECDSA certificates", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.ECDSAWithSHA256, false),
			createTestCert(x509.ECDSAWithSHA384, false),
			createTestCert(x509.ECDSAWithSHA512, true), // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA},
			{Hash: hash.SHA384, Signature: signature.ECDSA},
		}
		err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, allowed)
		if err != nil {
			t.Error("error: ", err)
		}
	})

	t.Run("RSA-PSS certificates", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.SHA256WithRSAPSS, false),
			createTestCert(x509.SHA384WithRSAPSS, true), // Root
		}
		// FromCertificate maps every x509 RSA-PSS algorithm to the
		// RSA_PSS_PSS_* scheme, so the allowed entry has to name that
		// variant rather than RSA_PSS_RSAE_* to match.
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.RSA_PSS_PSS_SHA256},
		}
		err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, allowed)
		if err != nil {
			t.Error("error: ", err)
		}
	})

	t.Run("Ed25519 certificates", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.PureEd25519, false),
			createTestCert(x509.PureEd25519, true), // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.None, Signature: signature.Ed25519},
		}
		err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, allowed)
		if err != nil {
			t.Error("error: ", err)
		}
	})

	t.Run("Unsupported certificate algorithm", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.MD5WithRSA, false), // MD5 not supported
			createTestCert(x509.ECDSAWithSHA256, true),
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA},
		}
		err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, allowed)
		if err == nil {
			t.Error("expected error")
		}
		// Should error from FromCertificate, not from algorithm mismatch
	})

	t.Run("Single cert chain does not validate", func(t *testing.T) {
		// Single cert is treated as self-signed root, which is not validated
		certs := []*x509.Certificate{
			createTestCert(x509.ECDSAWithSHA256, true), // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA384, Signature: signature.ECDSA}, // Different algorithm
		}
		// Should pass because single root cert is not validated
		err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, allowed)
		if err != nil {
			t.Error("error: ", err)
		}
	})
}
