// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package fingerprint

import (
	"crypto"
	"crypto/x509"
	"errors"
	"testing"
)

func TestFingerprint(t *testing.T) {
	rawCertificate := []byte{
		0x30, 0x82, 0x01, 0x98, 0x30, 0x82, 0x01, 0x3d, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x11, 0x00, 0xa9, 0x91,
		0x76, 0x0a, 0xcd, 0x97, 0x4c, 0x36, 0xba, 0xc9, 0xc2, 0x66, 0x91, 0x47, 0x6c, 0xac, 0x30, 0x0a, 0x06, 0x08,
		0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x2b, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x13, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x1e, 0x17, 0x0d, 0x31, 0x39, 0x31, 0x31, 0x31, 0x30, 0x30, 0x39, 0x30, 0x34, 0x32, 0x33, 0x5a, 0x17, 0x0d,
		0x31, 0x39, 0x31, 0x32, 0x31, 0x30, 0x30, 0x39, 0x30, 0x34, 0x32, 0x33, 0x5a, 0x30, 0x2b, 0x31, 0x29, 0x30,
		0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
		0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x9c, 0x12, 0x8e, 0xb5, 0x21,
		0x23, 0x9f, 0x35, 0x5d, 0x39, 0x64, 0xc3, 0x75, 0x81, 0xa4, 0xc8, 0xc8, 0x08, 0x8a, 0xa8, 0x42, 0x30, 0x30,
		0x65, 0xb8, 0xb1, 0x3e, 0x4a, 0x51, 0x86, 0xeb, 0xad, 0x03, 0x02, 0x35, 0x83, 0xc4, 0x19, 0x3a, 0x5b, 0x79,
		0x83, 0xec, 0x59, 0x0e, 0x4f, 0x99, 0xb1, 0xd2, 0xf0, 0x50, 0xfa, 0xb8, 0x5f, 0xfc, 0x88, 0xf3, 0x15, 0xed,
		0xb8, 0x14, 0xf0, 0xba, 0xcd, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
		0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
		0x03, 0x01, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
		0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46,
		0x02, 0x21, 0x00, 0xcd, 0x44, 0xb1, 0xf2, 0x09, 0xe5, 0xf1, 0xf4, 0xc9, 0x26, 0x95, 0x9a, 0x2d, 0x6d, 0xf3,
		0x0c, 0xb8, 0xeb, 0x27, 0x2d, 0x81, 0x19, 0xe9, 0x51, 0xf7, 0xad, 0x64, 0x7d, 0x42, 0x32, 0x9e, 0xf8, 0x02,
		0x21, 0x00, 0xee, 0xad, 0x96, 0x41, 0xf1, 0x12, 0xd0, 0x6b, 0xcd, 0x09, 0xf0, 0x3c, 0x67, 0xb3, 0xdd, 0xed,
		0x0a, 0xf1, 0xd8, 0x41, 0x4f, 0x61, 0xfd, 0x53, 0x1d, 0xf5, 0x27, 0xbe, 0x6d, 0x0b, 0xe2, 0x0d,
	}

	cert, err := x509.ParseCertificate(rawCertificate)
	if err != nil {
		t.Fatal(err)
	}

	const expectedSHA256 = "60:ef:f5:79:ad:8d:3e:d7:e8:4d:5a:5a:d6:1e:71:2d:47:52:a5:cb:df:34:37:87:10:a5:4e:d7:2a:2c:37:34"
	actualSHA256, err := Fingerprint(cert, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	} else if actualSHA256 != expectedSHA256 {
		t.Fatalf("Fingerprint SHA256 mismatch expected(%s) actual(%s)", expectedSHA256, actualSHA256)
	}
}

func TestFingerprint_UnavailableHash(t *testing.T) {
	_, err := Fingerprint(&x509.Certificate{}, crypto.Hash(0xFFFFFFFF))
	if !errors.Is(err, errHashUnavailable) {
		t.Fatalf("Expected error '%v' for invalid hash ID, got '%v'", errHashUnavailable, err)
	}
}
