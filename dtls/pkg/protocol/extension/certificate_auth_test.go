// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"crypto/x509"
	"math"
	"reflect"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

func TestCertificateAuth(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Error(err)
	}

	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Error(err)
	}

	subject := certificate.RawSubject
	lenSub := len(subject)

	extension := CertificateAuthorities{Authorities: [][]byte{subject}}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x00, 0x2f, // extension type
		0x00, byte(lenSub + 4), // G115: test fixture length is bounded by generated certificate subject size.
		0x00, byte(lenSub + 2), // G115: test fixture length is bounded by generated certificate subject size.
		0x00, byte(lenSub), // G115: test fixture length is bounded by generated certificate subject size.

	}
	expect = append(expect, subject...)

	if !reflect.DeepEqual(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newExtension := CertificateAuthorities{}

	if newExtension.Unmarshal(expect) != nil {
		t.Error(newExtension.Unmarshal(expect))
	}
	if !reflect.DeepEqual(extension.Authorities, newExtension.Authorities) {
		t.Errorf("expected %v, got %v", extension.Authorities, newExtension.Authorities)
	}
}

func TestCertificateAuth_Multiple(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Error(err)
	}

	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Error(err)
	}

	subject := certificate.RawSubject
	lenSub := len(subject)

	extension := CertificateAuthorities{Authorities: [][]byte{subject, subject}}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x00, 0x2f, // extension type
		// G115: test fixture length is bounded by generated certificate subject size.
		0x00, byte(lenSub*2 + 6),
		// G115: test fixture length is bounded by generated certificate subject size.
		0x00, byte(lenSub*2 + 4),
		// G115: test fixture length is bounded by generated certificate subject size.
		0x00, byte(lenSub),
	}
	expect = append(expect, subject...)
	// G115: test fixture length is bounded by generated certificate subject size.
	expect = append(expect, []byte{0x00, byte(lenSub)}...)
	expect = append(expect, subject...)

	if !reflect.DeepEqual(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newExtension := CertificateAuthorities{}

	if newExtension.Unmarshal(expect) != nil {
		t.Error(newExtension.Unmarshal(expect))
	}
	if !reflect.DeepEqual(extension.Authorities, newExtension.Authorities) {
		t.Errorf("expected %v, got %v", extension.Authorities, newExtension.Authorities)
	}
}

func TestCertificateAuth_Empty(t *testing.T) {
	extension := CertificateAuthorities{Authorities: [][]byte{}}

	_, err := extension.Marshal()
	if err == nil {
		t.Error("expected error")
	}

	raw := []byte{
		0x00, 0x2f, // extension type
		0x00, 0x02, // extension length
		0x00, 0x00, // empty subjects
	}

	newExtension := CertificateAuthorities{}

	if newExtension.Unmarshal(raw) == nil {
		t.Error("expected error")
	}
}

func FuzzCertificateAuthUnmarshal(f *testing.F) {
	cert, _ := selfsign.GenerateSelfSigned()
	certificate, _ := x509.ParseCertificate(cert.Certificate[0])
	subject := certificate.RawSubject
	lenSub := len(subject)

	raw := []byte{
		0x00, 0x2f, // extension type
		0x00, byte(lenSub*2 + 6), // G115: fuzz seed uses bounded generated certificate subject size.
		0x00, byte(lenSub*2 + 4), // G115: fuzz seed uses bounded generated certificate subject size.
		0x00, byte(lenSub), // G115: fuzz seed uses bounded generated certificate subject size.
	}
	raw = append(raw, subject...)
	// G115: fuzz seed uses bounded generated certificate subject size.
	raw = append(raw, []byte{0x00, byte(lenSub)}...)
	raw = append(raw, subject...)

	testcases := [][]byte{
		{
			0x00, 0x2f, // extension type
			0x00, 0x02, // extension length
			0x00, 0x00, // empty subjects
		},
		raw,
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		certAuth := CertificateAuthorities{}
		err := certAuth.Unmarshal(data)
		if err != nil {
			return
		}
		length := len(certAuth.Authorities)
		if length == 0 {
			t.Errorf("expected non-zero")
		}
		if !(length <= math.MaxUint16) {
			t.Errorf("expected %v <= %v", length, math.MaxUint16)
		}
		testExtDataLength(t, &certAuth, data, true)
	})
}
