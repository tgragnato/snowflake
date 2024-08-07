// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"errors"
	"reflect"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

func TestHandshakeMessageCertificateRequest(t *testing.T) {
	cases := map[string]struct {
		rawCertificateRequest    []byte
		parsedCertificateRequest *MessageCertificateRequest
		expErr                   error
	}{
		"valid - with CertificateAuthoritiesNames": {
			rawCertificateRequest: []byte{
				0x1, 0x40, 0x0, 0x4, 0x4, 0x3, 0x5, 0x3, 0x0, 0x6,
				0x0, 0x4, 0x74, 0x65, 0x73, 0x74,
			},
			parsedCertificateRequest: &MessageCertificateRequest{
				CertificateTypes: []clientcertificate.Type{
					clientcertificate.ECDSASign,
				},
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
					{Hash: hash.SHA384, Signature: signature.ECDSA},
				},
				CertificateAuthoritiesNames: [][]byte{[]byte("test")},
			},
		},
		"valid - without CertificateAuthoritiesNames": {
			rawCertificateRequest: []byte{
				0x1, 0x40, 0x0, 0x4, 0x4, 0x3, 0x5, 0x3, 0x0, 0x0,
			},
			parsedCertificateRequest: &MessageCertificateRequest{
				CertificateTypes: []clientcertificate.Type{
					clientcertificate.ECDSASign,
				},
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
					{Hash: hash.SHA384, Signature: signature.ECDSA},
				},
			},
		},
		"invalid - casLength CertificateAuthoritiesNames": {
			rawCertificateRequest: []byte{
				0x02, 0x01, 0x40, 0x00, 0x0C, 0x04, 0x03, 0x04, 0x01, 0x05,
				0x03, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x01,
			},
			expErr: errBufferTooSmall,
		},
	}

	for name, testCase := range cases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			c := &MessageCertificateRequest{}
			if err := c.Unmarshal(testCase.rawCertificateRequest); err != nil {
				if testCase.expErr != nil {
					if errors.Is(err, testCase.expErr) {
						return
					}
				}
				t.Error(err)
			} else if !reflect.DeepEqual(c, testCase.parsedCertificateRequest) {
				t.Errorf("parsedCertificateRequest unmarshal: got %#v, want %#v", c, testCase.parsedCertificateRequest)
			}
			raw, err := c.Marshal()
			if err != nil {
				t.Error(err)
			} else if !reflect.DeepEqual(raw, testCase.rawCertificateRequest) {
				t.Errorf("parsedCertificateRequest marshal: got %#v, want %#v", raw, testCase.rawCertificateRequest)
			}
		})
	}
}
