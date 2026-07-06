// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

func TestHandshakeMessageCertificateRequest13(t *testing.T) {
	cases := map[string]struct {
		rawCertificateRequest    []byte
		parsedCertificateRequest *MessageCertificateRequest13
		expErr                   error
	}{
		"valid - no context, single signature algorithm": {
			rawCertificateRequest: []byte{
				0x00,       // context length = 0
				0x00, 0x08, // extensions length = 8
				0x00, 0x0D, // extension type = signature_algorithms (13)
				0x00, 0x04, // extension length = 4
				0x00, 0x02, // signature_algorithms length = 2
				0x04, 0x03, // ECDSA-SHA256
			},
			parsedCertificateRequest: &MessageCertificateRequest13{
				CertificateRequestContext: []byte{},
				Extensions: []extension.Extension{
					&extension.SupportedSignatureAlgorithms{
						SignatureHashAlgorithms: []signaturehash.Algorithm{
							{Hash: hash.SHA256, Signature: signature.ECDSA},
						},
					},
				},
			},
		},
		"valid - with context, multiple signature algorithms": {
			rawCertificateRequest: []byte{
				0x04,                   // context length = 4
				0x01, 0x02, 0x03, 0x04, // context data
				0x00, 0x0C, // extensions length = 12
				0x00, 0x0D, // extension type = signature_algorithms (13)
				0x00, 0x08, // extension length = 8
				0x00, 0x06, // signature_algorithms length = 6
				0x04, 0x03, // ECDSA-SHA256
				0x04, 0x01, // RSA-PKCS1-SHA256
				0x05, 0x03, // ECDSA-SHA384
			},
			parsedCertificateRequest: &MessageCertificateRequest13{
				CertificateRequestContext: []byte{0x01, 0x02, 0x03, 0x04},
				Extensions: []extension.Extension{
					&extension.SupportedSignatureAlgorithms{
						SignatureHashAlgorithms: []signaturehash.Algorithm{
							{Hash: hash.SHA256, Signature: signature.ECDSA},
							{Hash: hash.SHA256, Signature: signature.RSA_PSS_RSAE_SHA512},
							{Hash: hash.SHA384, Signature: signature.ECDSA},
						},
					},
				},
			},
		},
		"invalid - missing signature_algorithms": {
			rawCertificateRequest: []byte{
				0x00,       // context length = 0
				0x00, 0x00, // extensions length = 0
			},
			expErr: dtlserrors.ErrMissingSignatureAlgorithmsExtension,
		},
		"invalid - buffer too small": {
			rawCertificateRequest: []byte{0x00},
			expErr:                dtlserrors.ErrBufferTooSmall,
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			c := &MessageCertificateRequest13{}
			err := c.Unmarshal(testCase.rawCertificateRequest)

			if testCase.expErr != nil {
				if !errors.Is(err, testCase.expErr) {
					t.Errorf("expected error %v, got %v", testCase.expErr, err)
				}
			} else {
				if err != nil {
					t.Error(err)
				}
				if !reflect.DeepEqual(testCase.parsedCertificateRequest.CertificateRequestContext, c.CertificateRequestContext) {
					t.Errorf("expected %v, got %v", testCase.parsedCertificateRequest.CertificateRequestContext, c.CertificateRequestContext)
				}
				if !reflect.DeepEqual(testCase.parsedCertificateRequest.Extensions, c.Extensions) {
					t.Errorf("expected %v, got %v", testCase.parsedCertificateRequest.Extensions, c.Extensions)
				}

				raw, err := c.Marshal()
				if err != nil {
					t.Error(err)
				}
				if !reflect.DeepEqual(testCase.rawCertificateRequest, raw) {
					t.Errorf("expected %v, got %v", testCase.rawCertificateRequest, raw)
				}
			}
		})
	}
}

func TestMessageCertificateRequest13_Type(t *testing.T) {
	m := &MessageCertificateRequest13{}
	if TypeCertificateRequest != m.Type() {
		t.Errorf("expected %v, got %v", TypeCertificateRequest, m.Type())
	}
}

func TestMessageCertificateRequest13_MinimalValid(t *testing.T) {
	// Build (valid) message with empty context
	msg := &MessageCertificateRequest13{
		CertificateRequestContext: []byte{},
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
					{Hash: hash.SHA256, Signature: signature.RSA_PSS_RSAE_SHA512},
				},
			},
		},
	}
	marshalUnmarshalMessageCertificateRequest13AndVerifyMatch(t, msg)
}

func TestMessageCertificateRequest13_WithContext(t *testing.T) {
	// Build (valid) message with non-empty context
	msg := &MessageCertificateRequest13{
		CertificateRequestContext: []byte{0x01, 0x02, 0x03, 0x04},
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
				},
			},
		},
	}
	marshalUnmarshalMessageCertificateRequest13AndVerifyMatch(t, msg)
}

func TestMessageCertificateRequest13_MaxContextLength(t *testing.T) {
	// Build (valid) message with context of exactly the max size
	context := make([]byte, certReq13ContextMaxLength)
	for i := range context {
		context[i] = byte(i)
	}
	msg := &MessageCertificateRequest13{
		CertificateRequestContext: context,
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
				},
			},
		},
	}
	marshalUnmarshalMessageCertificateRequest13AndVerifyMatch(t, msg)
}

func TestMessageCertificateRequest13_MultipleExtensions(t *testing.T) {
	// Build (valid) message with multiple extensions
	// (signature_algorithms, which must be present, and server_name)
	msg := &MessageCertificateRequest13{
		CertificateRequestContext: []byte{0x01, 0x02, 0x03, 0x04},
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
					{Hash: hash.SHA384, Signature: signature.ECDSA},
					{Hash: hash.SHA512, Signature: signature.RSA_PSS_RSAE_SHA512},
				},
			},
			&extension.ServerName{ServerName: "example.com"},
		},
	}
	marshalUnmarshalMessageCertificateRequest13AndVerifyMatch(t, msg)
}

func TestMessageCertificateRequest13_ContextTooLong(t *testing.T) {
	// Build (invalid) message with context exceeding the max size
	tooLongContext := make([]byte, certReq13ContextMaxLength+1)
	msg := &MessageCertificateRequest13{
		CertificateRequestContext: tooLongContext,
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
				},
			},
		},
	}

	_, err := msg.Marshal()
	if !errors.Is(err, dtlserrors.ErrCertificateRequestContextTooLong) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrCertificateRequestContextTooLong, err)
	}
}

func TestMessageCertificateRequest13_MissingSignatureAlgorithms(t *testing.T) {
	// Build (invalid) message with no signature_algorithms extension
	msg := &MessageCertificateRequest13{}

	_, err := msg.Marshal()
	if !errors.Is(err, dtlserrors.ErrMissingSignatureAlgorithmsExtension) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrMissingSignatureAlgorithmsExtension, err)
	}
}

func TestMessageCertificateRequest13_UnmarshalMissingSignatureAlgorithms(t *testing.T) {
	// Define (invalid) serialized message (has no signature_algorithms extension)
	data := []byte{
		0x00,       // context length = 0
		0x00, 0x00, // extensions length = 0
	}

	err := (&MessageCertificateRequest13{}).Unmarshal(data)
	if !errors.Is(err, dtlserrors.ErrMissingSignatureAlgorithmsExtension) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrMissingSignatureAlgorithmsExtension, err)
	}
}

func TestMessageCertificateRequest13_UnmarshalBufferTooSmall(t *testing.T) {
	// Define (invalid) serialized messages (data too small)
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"1 byte", []byte{0x00}},
		{"2 bytes", []byte{0x00, 0x00}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := (&MessageCertificateRequest13{}).Unmarshal(test.data)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestMessageCertificateRequest13_UnmarshalInvalidContext(t *testing.T) {
	// Define (invalid) serialized message (data smaller than advertised context length)
	data := []byte{
		0x05,                   // context length = 5
		0x01, 0x02, 0x03, 0x04, // only 2 bytes
	}

	err := (&MessageCertificateRequest13{}).Unmarshal(data)
	if !errors.Is(err, dtlserrors.ErrInvalidCertificateRequestContext) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrInvalidCertificateRequestContext, err)
	}
}

func TestMessageCertificateRequest13_UnmarshalInvalidExtensions(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		// Define (invalid) serialized message (data smaller than advertised context length)
		{
			name: "only 1 byte of extensions after context",
			data: []byte{
				0x01, // context length = 1
				0xFF, // context data
				0x00, // only 1 byte of extensions (< 2 bytes required)
			},
		},
		// Define (invalid) serialized message (extensions length bytes truncated)
		{
			name: "no extensions after empty context",
			data: []byte{
				0x02,       // context length = 2
				0x01, 0x02, // context data
				0x00, // only 1 byte of extensions (< 2 bytes required)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := (&MessageCertificateRequest13{}).Unmarshal(test.data)
			if !errors.Is(err, dtlserrors.ErrInvalidExtensionsLength) {
				t.Errorf("expected error %v, got %v", dtlserrors.ErrInvalidExtensionsLength, err)
			}
		})
	}
}

func FuzzMessageCertificateRequest13(f *testing.F) {
	// Seed with valid minimal message (signature_algorithms extension)
	f.Add([]byte{
		0x00,       // context length = 0
		0x00, 0x06, // extensions length = 6
		0x00, 0x0D, // extension type = signature_algorithms (13)
		0x00, 0x02, // extension length = 2
		0x04, 0x03, // ECDSA-SHA256
	})

	// Seed with valid message with context
	f.Add([]byte{
		0x04,                   // context length = 4
		0x01, 0x02, 0x03, 0x04, // context data
		0x00, 0x06, // extensions length = 6
		0x00, 0x0D, // extension type = signature_algorithms (13)
		0x00, 0x02, // extension length = 2
		0x04, 0x03, // ECDSA-SHA256
	})

	// Seed with valid message with multiple signature algorithms
	f.Add([]byte{
		0x00,       // context length = 0
		0x00, 0x0A, // extensions length = 10
		0x00, 0x0D, // extension type = signature_algorithms (13)
		0x00, 0x06, // extension length = 6
		0x04, 0x03, // ECDSA-SHA256
		0x08, 0x04, // RSA-PSS-RSAE-SHA256
		0x08, 0x05, // RSA-PSS-RSAE-SHA384
	})

	// Seed with invalid data for edge case testing
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = (&MessageCertificateRequest13{}).Unmarshal(data)
	})
}

// marshalUnmarshalMessageCertificateRequest13AndVerifyMatch marshals and
// unmarshals a MessageCertificateRequest13, then verifies that the message
// before and after have matching properties.
func marshalUnmarshalMessageCertificateRequest13AndVerifyMatch(
	t *testing.T,
	in *MessageCertificateRequest13,
) {
	t.Helper()

	out := &MessageCertificateRequest13{}

	// Marshal, then unmarshal
	marshaled, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	err = out.Unmarshal(marshaled)
	if err != nil {
		t.Fatal(err)
	}

	// Verify before/after marshal/unmarshal match
	if !reflect.DeepEqual(in.CertificateRequestContext, out.CertificateRequestContext) {
		t.Errorf("expected %v, got %v", in.CertificateRequestContext, out.CertificateRequestContext)
	}
	if !reflect.DeepEqual(in.Extensions, out.Extensions) {
		t.Errorf("expected %v, got %v", in.Extensions, out.Extensions)
	}

	// Verify has signature algorithms extension present
	hasSignatureAlgorithms := false
	for _, ext := range out.Extensions {
		if ext.TypeValue() == extension.SupportedSignatureAlgorithmsTypeValue {
			hasSignatureAlgorithms = true

			break
		}
	}
	if !hasSignatureAlgorithms {
		t.Error("expected true")
	}
}
