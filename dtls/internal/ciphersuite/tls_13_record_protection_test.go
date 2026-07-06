// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"golang.org/x/crypto/chacha20"
)

type recordProtection13TestCase struct {
	name                       string
	suite                      tls13RecordProtectionSuite
	keyLen                     int
	tagLen                     int
	expectedSequenceNumberMask func(t *testing.T, sequenceNumberKey, encryptedRecord []byte) []byte
}

type tls13RecordProtectionSuite interface {
	CipherSuiteTLS13
	newRecordProtection(localTrafficSecret, remoteTrafficSecret []byte) (*recordProtection13, error)
}

func recordProtection13TestCases() []recordProtection13TestCase {
	return []recordProtection13TestCase{
		{
			name:                       "TLS_CHACHA20_POLY1305_SHA256",
			suite:                      NewTLSChacha20Poly1305Sha256(),
			keyLen:                     tls13ChaCha20Poly1305KeyLen,
			tagLen:                     tls13ChaCha20Poly1305TagLen,
			expectedSequenceNumberMask: expectedChaCha20SequenceNumberMask13,
		},
	}
}

func expectedAESSequenceNumberMask13(t *testing.T, sequenceNumberKey, encryptedRecord []byte) []byte {
	t.Helper()

	block, err := aes.NewCipher(sequenceNumberKey)
	if err != nil {
		t.Fatal(err)
	}

	expectedMask := make([]byte, aes.BlockSize)
	block.Encrypt(expectedMask, encryptedRecord[:aes.BlockSize])

	return expectedMask
}

func expectedChaCha20SequenceNumberMask13(t *testing.T, sequenceNumberKey, encryptedRecord []byte) []byte {
	t.Helper()

	chacha, err := chacha20.NewUnauthenticatedCipher(sequenceNumberKey, encryptedRecord[4:16])
	if err != nil {
		t.Fatal(err)
	}
	chacha.SetCounter(binary.LittleEndian.Uint32(encryptedRecord[:4]))

	expectedMask := make([]byte, tls13ChaCha20BlockLen)
	chacha.XORKeyStream(expectedMask, expectedMask)

	return expectedMask
}

func trafficSecret13(suite tls13RecordProtectionSuite, fill byte) []byte {
	hashFunc := suite.HashFunc()

	return bytes.Repeat([]byte{fill}, hashFunc().Size())
}

func newRecordProtection13TestSuite(t *testing.T, name string) tls13RecordProtectionSuite {
	t.Helper()

	for _, testCase := range recordProtection13TestCases() {
		if testCase.name == name {
			return testCase.suite
		}
	}

	t.Fatalf("name: %s", name)

	return nil
}

func requireRecordProtection13(t *testing.T, suite tls13RecordProtectionSuite) *recordProtection13 {
	t.Helper()

	switch s := suite.(type) {
	case *TLSChacha20Poly1305Sha256:
		protection, ok := s.getRecordProtection13()
		if !ok {
			t.Fatal("expected true")
		}

		return protection
	default:
		t.Fatalf("suite: %T", suite)

		return nil
	}
}

func TestDeriveRecordTrafficKeys13Suites(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			hashFunc := testCase.suite.HashFunc()
			trafficSecret := trafficSecret13(testCase.suite, 0x3c)

			keys, err := deriveRecordTrafficKeys13(hashFunc, trafficSecret, testCase.keyLen)
			if err != nil {
				t.Fatal(err)
			}

			if len(keys.key) != testCase.keyLen {
				t.Fatalf("wrong length: got %d, want %d", len(keys.key), testCase.keyLen)
			}
			if len(keys.iv) != tls13AEADWriteIVLen {
				t.Fatalf("wrong length: got %d, want %d", len(keys.iv), tls13AEADWriteIVLen)
			}
			if len(keys.sequenceNumberKey) != testCase.keyLen {
				t.Fatalf("wrong length: got %d, want %d", len(keys.sequenceNumberKey), testCase.keyLen)
			}

			expectedKey, err := keyschedule.HkdfExpandLabel(
				hashFunc,
				trafficSecret,
				trafficKeyLabel13,
				nil,
				testCase.keyLen,
			)
			if err != nil {
				t.Fatal(err)
			}

			expectedIV, err := keyschedule.HkdfExpandLabel(
				hashFunc,
				trafficSecret,
				trafficIVLabel13,
				nil,
				tls13AEADWriteIVLen,
			)
			if err != nil {
				t.Fatal(err)
			}

			expectedSequenceNumberKey, err := keyschedule.HkdfExpandLabel(
				hashFunc,
				trafficSecret,
				trafficSequenceNumberKeyLabel13,
				nil,
				testCase.keyLen,
			)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(expectedKey, keys.key) {
				t.Errorf("expected %v, got %v", expectedKey, keys.key)
			}
			if !reflect.DeepEqual(expectedIV, keys.iv) {
				t.Errorf("expected %v, got %v", expectedIV, keys.iv)
			}
			if !reflect.DeepEqual(expectedSequenceNumberKey, keys.sequenceNumberKey) {
				t.Errorf("expected %v, got %v", expectedSequenceNumberKey, keys.sequenceNumberKey)
			}
			if reflect.DeepEqual(keys.key, keys.sequenceNumberKey) {
				t.Errorf("should not equal %v", keys.key)
			}
		})
	}
}

func TestTLS13CipherSuiteNewRecordProtectionSuites(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			localTrafficSecret := trafficSecret13(testCase.suite, 0x5a)
			remoteTrafficSecret := trafficSecret13(testCase.suite, 0x6b)

			protection, err := testCase.suite.newRecordProtection(localTrafficSecret, remoteTrafficSecret)
			if err != nil {
				t.Fatal(err)
			}
			if protection.local.aead == nil {
				t.Fatal("expected non-nil")
			}
			if protection.remote.aead == nil {
				t.Fatal("expected non-nil")
			}

			if tls13AEADWriteIVLen != protection.local.aead.NonceSize() {
				t.Errorf("expected %v, got %v", tls13AEADWriteIVLen, protection.local.aead.NonceSize())
			}
			if testCase.tagLen != protection.local.aead.Overhead() {
				t.Errorf("expected %v, got %v", testCase.tagLen, protection.local.aead.Overhead())
			}
			if len(protection.local.iv) != tls13AEADWriteIVLen {
				t.Fatalf("wrong length: got %d, want %d", len(protection.local.iv), tls13AEADWriteIVLen)
			}
			if len(protection.remote.iv) != tls13AEADWriteIVLen {
				t.Fatalf("wrong length: got %d, want %d", len(protection.remote.iv), tls13AEADWriteIVLen)
			}
			if len(protection.local.sequenceNumberKey) != testCase.keyLen {
				t.Fatalf("wrong length: got %d, want %d", len(protection.local.sequenceNumberKey), testCase.keyLen)
			}
			if len(protection.remote.sequenceNumberKey) != testCase.keyLen {
				t.Fatalf("wrong length: got %d, want %d", len(protection.remote.sequenceNumberKey), testCase.keyLen)
			}
			if reflect.DeepEqual(protection.local.iv, protection.remote.iv) {
				t.Errorf("should not equal %v", protection.local.iv)
			}
			if reflect.DeepEqual(protection.local.sequenceNumberKey, protection.remote.sequenceNumberKey) {
				t.Errorf("should not equal %v", protection.local.sequenceNumberKey)
			}

			plaintext := []byte("dtls13 record protection")
			additionalData := []byte("synthetic aad")
			nonce := append([]byte(nil), protection.local.iv...)

			ciphertext := protection.local.aead.Seal(nil, nonce, plaintext, additionalData)
			if len(ciphertext) != len(plaintext)+protection.local.aead.Overhead() {
				t.Fatalf("wrong length: got %d, want %d", len(ciphertext), len(plaintext)+protection.local.aead.Overhead())
			}

			decrypted, err := protection.local.aead.Open(nil, nonce, ciphertext, additionalData)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(plaintext, decrypted) {
				t.Errorf("expected %v, got %v", plaintext, decrypted)
			}
		})
	}
}

func TestTLS13CipherSuiteInitFromTrafficSecrets13(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			clientSuite := testCase.suite
			serverSuite := newRecordProtection13TestSuite(t, testCase.name)

			clientSecret := trafficSecret13(testCase.suite, 0xa6)
			serverSecret := trafficSecret13(testCase.suite, 0xb6)

			if clientSuite.IsInitialized() {
				t.Fatal("expected false")
			}
			if serverSuite.IsInitialized() {
				t.Fatal("expected false")
			}

			if clientSuite.InitFromTrafficSecrets13(clientSecret, serverSecret, true) != nil {
				t.Fatal(clientSuite.InitFromTrafficSecrets13(clientSecret, serverSecret, true))
			}
			if serverSuite.InitFromTrafficSecrets13(clientSecret, serverSecret, false) != nil {
				t.Fatal(serverSuite.InitFromTrafficSecrets13(clientSecret, serverSecret, false))
			}

			if !clientSuite.IsInitialized() {
				t.Fatal("expected true")
			}
			if !serverSuite.IsInitialized() {
				t.Fatal("expected true")
			}

			clientProtection := requireRecordProtection13(t, clientSuite)
			serverProtection := requireRecordProtection13(t, serverSuite)
			header := recordlayer.UnifiedHeader{
				SequenceNumber: 0x1234,
				EpochLow:       2,
			}
			sequenceNumber := uint64(0x0102030405060708)
			plaintext := []byte("traffic-secret initialized payload")

			record, err := clientProtection.seal(header, sequenceNumber, protocol.ContentTypeApplicationData, plaintext)
			if err != nil {
				t.Fatal(err)
			}

			innerPlaintext, err := serverProtection.open(record.Header, sequenceNumber, record.EncryptedRecord)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(plaintext, innerPlaintext.Content) {
				t.Errorf("expected %v, got %v", plaintext, innerPlaintext.Content)
			}
			if protocol.ContentTypeApplicationData != innerPlaintext.RealType {
				t.Errorf("expected %v, got %v", protocol.ContentTypeApplicationData, innerPlaintext.RealType)
			}
		})
	}
}

func TestRecordProtection13SealOpenSyntheticTrafficSecret(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			localTrafficSecret := trafficSecret13(testCase.suite, 0xa6)
			remoteTrafficSecret := trafficSecret13(testCase.suite, 0xb6)
			protection, err := testCase.suite.newRecordProtection(localTrafficSecret, remoteTrafficSecret)
			if err != nil {
				t.Fatal(err)
			}
			peerProtection, err := testCase.suite.newRecordProtection(remoteTrafficSecret, localTrafficSecret)
			if err != nil {
				t.Fatal(err)
			}

			header := recordlayer.UnifiedHeader{
				SequenceNumber: 0x1234,
				EpochLow:       2,
			}
			sequenceNumber := uint64(0x0102030405060708)
			plaintext := []byte("protected dtls13 payload")

			record, err := protection.seal(header, sequenceNumber, protocol.ContentTypeApplicationData, plaintext)
			if err != nil {
				t.Fatal(err)
			}

			if uint16(len(record.EncryptedRecord)) != record.Header.Length {
				t.Fatalf("expected %v, got %v", uint16(len(record.EncryptedRecord)), record.Header.Length)
			}
			if !record.Header.LengthBit {
				t.Fatal("expected true")
			}
			if !record.Header.SeqBit {
				t.Fatal("expected true")
			}
			if len(record.EncryptedRecord) != len(plaintext)+1+testCase.tagLen {
				t.Fatalf("wrong length: got %d, want %d", len(record.EncryptedRecord), len(plaintext)+1+testCase.tagLen)
			}

			innerPlaintext, err := peerProtection.open(record.Header, sequenceNumber, record.EncryptedRecord)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(plaintext, innerPlaintext.Content) {
				t.Errorf("expected %v, got %v", plaintext, innerPlaintext.Content)
			}
			if protocol.ContentTypeApplicationData != innerPlaintext.RealType {
				t.Errorf("expected %v, got %v", protocol.ContentTypeApplicationData, innerPlaintext.RealType)
			}
			if uint(0) != innerPlaintext.Zeros {
				t.Errorf("expected %v, got %v", uint(0), innerPlaintext.Zeros)
			}
		})
	}
}

func TestRecordProtection13SealRejectsOversizedPlaintext(t *testing.T) {
	suite := NewTLSChacha20Poly1305Sha256()
	protection, err := suite.newRecordProtection(trafficSecret13(suite, 0xaa), trafficSecret13(suite, 0xab))
	if err != nil {
		t.Fatal(err)
	}

	header := recordlayer.UnifiedHeader{SequenceNumber: 0x1234, EpochLow: 2}
	_, err = protection.seal(
		header,
		0x0102030405060708,
		protocol.ContentTypeApplicationData,
		bytes.Repeat([]byte{0x01}, maxDTLSPlaintextRecordLen13),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = protection.seal(
		header,
		0x0102030405060708,
		protocol.ContentTypeApplicationData,
		bytes.Repeat([]byte{0x01}, maxDTLSPlaintextRecordLen13+1),
	)
	if !errors.Is(err, dtlserrors.ErrInvalidPacketLength) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrInvalidPacketLength, err)
	}
}

func TestRecordProtection13OpenRejectsWrongAdditionalData(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			localTrafficSecret := trafficSecret13(testCase.suite, 0xb7)
			remoteTrafficSecret := trafficSecret13(testCase.suite, 0xc7)
			protection, err := testCase.suite.newRecordProtection(localTrafficSecret, remoteTrafficSecret)
			if err != nil {
				t.Fatal(err)
			}
			peerProtection, err := testCase.suite.newRecordProtection(remoteTrafficSecret, localTrafficSecret)
			if err != nil {
				t.Fatal(err)
			}

			record, err := protection.seal(
				recordlayer.UnifiedHeader{SequenceNumber: 0x4567, EpochLow: 1},
				0x0102030405060708,
				protocol.ContentTypeHandshake,
				[]byte{0x01, 0x02, 0x03},
			)
			if err != nil {
				t.Fatal(err)
			}

			record.Header.SequenceNumber ^= 0x0001
			_, err = peerProtection.open(record.Header, 0x0102030405060708, record.EncryptedRecord)
			if !errors.Is(err, dtlserrors.ErrDecryptPacket) {
				t.Errorf("expected error %v, got %v", dtlserrors.ErrDecryptPacket, err)
			}
		})
	}
}

func TestRecordProtection13OpenRejectsWrongSequenceNumber(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			localTrafficSecret := trafficSecret13(testCase.suite, 0xbe)
			remoteTrafficSecret := trafficSecret13(testCase.suite, 0xce)
			protection, err := testCase.suite.newRecordProtection(localTrafficSecret, remoteTrafficSecret)
			if err != nil {
				t.Fatal(err)
			}
			peerProtection, err := testCase.suite.newRecordProtection(remoteTrafficSecret, localTrafficSecret)
			if err != nil {
				t.Fatal(err)
			}

			record, err := protection.seal(
				recordlayer.UnifiedHeader{SequenceNumber: 0x4567, EpochLow: 1},
				0x0102030405060708,
				protocol.ContentTypeHandshake,
				[]byte{0x01, 0x02, 0x03},
			)
			if err != nil {
				t.Fatal(err)
			}

			_, err = peerProtection.open(record.Header, 0x0102030405060709, record.EncryptedRecord)
			if !errors.Is(err, dtlserrors.ErrDecryptPacket) {
				t.Errorf("expected error %v, got %v", dtlserrors.ErrDecryptPacket, err)
			}
		})
	}
}

func TestRecordProtection13SequenceNumberMaskSyntheticTrafficSecret(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			protection, err := testCase.suite.newRecordProtection(
				trafficSecret13(testCase.suite, 0xc8),
				trafficSecret13(testCase.suite, 0xc9),
			)
			if err != nil {
				t.Fatal(err)
			}

			record, err := protection.seal(
				recordlayer.UnifiedHeader{SequenceNumber: 0x0102, EpochLow: 3},
				0x1112131415161718,
				protocol.ContentTypeApplicationData,
				[]byte("mask sample source"),
			)
			if err != nil {
				t.Fatal(err)
			}

			mask, err := protection.sequenceNumberMask(record.EncryptedRecord)
			if err != nil {
				t.Fatal(err)
			}
			expectedMask := testCase.expectedSequenceNumberMask(t, protection.local.sequenceNumberKey, record.EncryptedRecord)

			if !reflect.DeepEqual(expectedMask, mask) {
				t.Errorf("expected %v, got %v", expectedMask, mask)
			}

			rawHeader, err := record.Header.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			maskedHeader := append([]byte(nil), rawHeader...)
			maskedHeader[1] ^= mask[0]
			maskedHeader[2] ^= mask[1]
			if reflect.DeepEqual(rawHeader, maskedHeader) {
				t.Errorf("should not equal %v", rawHeader)
			}

			maskedHeader[1] ^= mask[0]
			maskedHeader[2] ^= mask[1]
			if !reflect.DeepEqual(rawHeader, maskedHeader) {
				t.Errorf("expected %v, got %v", rawHeader, maskedHeader)
			}
		})
	}
}

func TestRecordProtection13SequenceNumberMaskRejectsShortCiphertext(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			protection, err := testCase.suite.newRecordProtection(
				trafficSecret13(testCase.suite, 0xd9),
				trafficSecret13(testCase.suite, 0xda),
			)
			if err != nil {
				t.Fatal(err)
			}

			_, err = protection.sequenceNumberMask(bytes.Repeat([]byte{0x01}, tls13SequenceNumberMaskSampleLen-1))
			if !errors.Is(err, dtlserrors.ErrBufferTooSmall) {
				t.Errorf("expected error %v, got %v", dtlserrors.ErrBufferTooSmall, err)
			}
		})
	}
}

func TestRecordSequenceNumberMaskChaCha20RFC8439BlockVector(t *testing.T) {
	sequenceNumberKey, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	encryptedRecord, err := hex.DecodeString("01000000000000090000004a00000000")
	if err != nil {
		t.Fatal(err)
	}

	mask, err := recordSequenceNumberMaskChaCha20Poly1305TLS13(sequenceNumberKey, encryptedRecord)
	if err != nil {
		t.Fatal(err)
	}

	expected, err := hex.DecodeString(
		"10f1e7e4d13b5915500fdd1fa32071c4" +
			"c7d1f4c733c068030422aa9ac3d46c4e" +
			"d2826446079faa0914c2d705d98b02a2" +
			"b5129cd1de164eb9cbd083e8a2503c4e",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, mask) {
		t.Errorf("expected %v, got %v", expected, mask)
	}
}

func TestRecordNonce13(t *testing.T) {
	iv := []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab}
	nonce, err := recordNonce13(iv, 0x0102030405060708)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual([]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa5, 0xa7, 0xa5, 0xa3, 0xad, 0xaf, 0xad, 0xa3}, nonce) {
		t.Errorf("expected %v, got %v", []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa5, 0xa7, 0xa5, 0xa3, 0xad, 0xaf, 0xad, 0xa3}, nonce)
	}
	if !reflect.DeepEqual([]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab}, iv) {
		t.Errorf("expected %v, got %v", []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab}, iv)
	}
}

func TestNewAESGCMRecordProtection13RejectsInvalidAESKeyLength(t *testing.T) {
	suite := NewTLSChacha20Poly1305Sha256()
	_, err := newAESGCMRecordProtection13(
		suite.HashFunc(),
		trafficSecret13(suite, 0x5a),
		trafficSecret13(suite, 0x6a),
		31,
	)
	if err == nil {
		t.Error("expected error")
	}
}

func TestDeriveRecordTrafficKeys13RejectsInvalidKeyLength(t *testing.T) {
	suite := NewTLSChacha20Poly1305Sha256()
	_, err := deriveRecordTrafficKeys13(suite.HashFunc(), trafficSecret13(suite, 0x3c), 0)
	if !errors.Is(err, dtlserrors.ErrLengthMismatch) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrLengthMismatch, err)
	}
}
