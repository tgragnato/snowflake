// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"reflect"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

func TestExtensionSupportedSignatureAlgorithms(t *testing.T) {
	rawExtensionSupportedSignatureAlgorithms := []byte{
		0x00, 0x0d,
		0x00, 0x08,
		0x00, 0x06,
		0x04, 0x03,
		0x05, 0x03,
		0x06, 0x03,
	}
	parsedExtensionSupportedSignatureAlgorithms := &SupportedSignatureAlgorithms{
		SignatureHashAlgorithms: []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA},
			{Hash: hash.SHA384, Signature: signature.ECDSA},
			{Hash: hash.SHA512, Signature: signature.ECDSA},
		},
	}

	raw, err := parsedExtensionSupportedSignatureAlgorithms.Marshal()
	if err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(raw, rawExtensionSupportedSignatureAlgorithms) {
		t.Fatalf(
			"extensionSupportedSignatureAlgorithms marshal: got %#v, want %#v",
			raw, rawExtensionSupportedSignatureAlgorithms,
		)
	}

	roundtrip := &SupportedSignatureAlgorithms{}
	if err := roundtrip.Unmarshal(raw); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(roundtrip, parsedExtensionSupportedSignatureAlgorithms) {
		t.Errorf(
			"extensionSupportedSignatureAlgorithms unmarshal: got %#v, want %#v",
			roundtrip, parsedExtensionSupportedSignatureAlgorithms,
		)
	}
}
