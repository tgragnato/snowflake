// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"reflect"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
)

func TestSupportedVersions_ClientHello_RoundTrip(t *testing.T) {
	ext := &SupportedVersions{
		Versions: []protocol.Version{
			protocol.Version1_3,
			protocol.Version1_2,
			// even though DTLS v1.0 isn't supported, it should still be marshaled/unmarshaled correctly.
			protocol.Version1_0,
		},
	}

	// length=7, listLen=6, 3 version pairs
	rawExpected := []byte{
		0x00, 0x2b, // extension type
		0x00, 0x07, // extension_data length
		0x06,       // versions length (bytes)
		0xfe, 0xfc, // DTLS v1.3
		0xfe, 0xfd, // DTLS v1.2
		0xfe, 0xff, // DTLS v1.0
	}

	raw, err := ext.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !reflect.DeepEqual(rawExpected, raw) {
		t.Errorf("Marshal output mismatch.\nExpected: %v\nGot:      %v", rawExpected, raw)
	}

	var rt SupportedVersions
	if err := rt.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if !reflect.DeepEqual(ext.Versions, rt.Versions) {
		t.Errorf("Versions mismatch after roundtrip.\nExpected: %v\nGot:      %v", ext.Versions, rt.Versions)
	}
}

func TestSupportedVersions_ServerHello_RoundTrip(t *testing.T) {
	// Server/HRR form: exactly one entry in Versions.
	ext := &SupportedVersions{
		Versions: []protocol.Version{protocol.Version1_3},
	}

	// length=2, selected_version = 0xfe,0xfc
	rawExpected := []byte{
		0x00, 0x2b, // extension type
		0x00, 0x02, // extension_data length
		0xfe, 0xfc, // selected_version
	}

	raw, err := ext.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !reflect.DeepEqual(rawExpected, raw) {
		t.Errorf("Marshal output mismatch.\nExpected: %v\nGot:      %v", rawExpected, raw)
	}

	var rt SupportedVersions
	if err := rt.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	expectedVersions := []protocol.Version{protocol.Version1_3}
	if !reflect.DeepEqual(expectedVersions, rt.Versions) {
		t.Errorf("Versions mismatch after roundtrip.\nExpected: %v\nGot:      %v", expectedVersions, rt.Versions)
	}
}

func TestSupportedVersions_ClientHello_Marshal_Invalid(t *testing.T) {
	ext := &SupportedVersions{
		Versions: []protocol.Version{
			protocol.Version1_3,
			protocol.Version1_2,
			// even though DTLS v1.0 isn't supported, it should still be marshaled/unmarshaled correctly.
			protocol.Version1_0,
			{Major: 0xfe, Minor: 0x00}, // invalid version
		},
	}

	// in this case we want it to error to protect against malformed messages/DOS attacks.
	_, err := ext.Marshal()
	if err != errInvalidDTLSVersion {
		t.Errorf("expected error %v, got %v", errInvalidDTLSVersion, err)
	}
}

func TestSupportedVersions_ClientHello_Unmarshal_Invalid(t *testing.T) {
	// note that the invalid version is excluded here.
	ext := &SupportedVersions{
		Versions: []protocol.Version{
			protocol.Version1_3,
			protocol.Version1_2,
			// even though DTLS v1.0 isn't supported, it should still be marshaled/unmarshaled correctly.
			protocol.Version1_0,
		},
	}

	raw := []byte{
		0x00, 0x2b, // extension type
		0x00, 0x09, // extension_data length
		0x08,       // versions length (bytes)
		0xfe, 0xfc, // DTLS v1.3
		0xfe, 0xfd, // DTLS v1.2
		0xfe, 0xff, // DTLS v1.0
		0xfe, 0x00, // invalid version
	}

	// in this case we don't want it to error because valid versions can still be parsed.
	var rt SupportedVersions
	if err := rt.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if !reflect.DeepEqual(ext.Versions, rt.Versions) {
		t.Errorf("Versions mismatch.\nExpected: %v\nGot:      %v", ext.Versions, rt.Versions)
	}
}

func TestSupportedVersions_Marshal_LengthBounds(t *testing.T) {
	// list with length > 254 bytes, each version is 2 bytes.
	// so 128 versions -> 256 bytes (it should error).
	tooMany := make([]protocol.Version, 128)
	for i := range tooMany {
		tooMany[i] = protocol.Version1_2
	}

	ext := &SupportedVersions{Versions: tooMany}
	_, err := ext.Marshal()
	if err != errInvalidSupportedVersionsFormat {
		t.Errorf("expected error %v, got %v", errInvalidSupportedVersionsFormat, err)
	}
}

func TestSupportedVersions_Unmarshal_Errors(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		err  error
	}{
		{
			name: "invalid extension type",
			raw: []byte{
				0x00, 0x0d, // invalid extension type
			},
			err: errInvalidExtensionType,
		},
		{
			name: "empty extension_data",
			raw: []byte{
				0x00, 0x2b, // extension type
				0x00, 0x00, // length = 0
			},
			err: errInvalidSupportedVersionsFormat,
		},
		{
			name: "client list odd length",
			// length=4, listLen=3 (odd), 3 bytes follow
			raw: []byte{
				0x00, 0x2b, // extension type
				0x00, 0x04, // length = 4
				0x03,             // listLen = 3
				0xfe, 0xfd, 0xfe, // extra byte, parsing as list must fail
			},
			err: errInvalidSupportedVersionsFormat,
		},
		{
			name: "client list length mismatch",
			// extension_data length=3, but listLen=4 -> mismatch
			raw: []byte{
				0x00, 0x2b, // extension type
				0x00, 0x03, // length = 3
				0x04,       // listLen = 4
				0xfe, 0xfd, // but only 2 bytes present
			},
			err: errInvalidSupportedVersionsFormat,
		},
		{
			name: "server selected wrong size",
			// extension_data length=3 for server form (must be exactly 2 for server form)
			raw: []byte{
				0x00, 0x2b, // extension type
				0x00, 0x03, // length = 3
				0xfe, 0xfc, 0x00,
			},
			err: errInvalidSupportedVersionsFormat,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var sv SupportedVersions
			err := sv.Unmarshal(tc.raw)
			if err != tc.err {
				t.Errorf("expected error %v, got %v", tc.err, err)
			}
		})
	}
}

func TestExtensionsUnmarshal_SupportedVersions_ClientHello(t *testing.T) {
	supportedVersionsExt := []byte{
		0x00, 0x2b, // extension type
		0x00, 0x05, // extension_data length = 5
		0x04,       // list length = 4
		0xfe, 0xfc, // DTLS v1.3
		0xfe, 0xfd, // DTLS v1.2
	}
	var sv SupportedVersions

	ex := sv.Unmarshal(supportedVersionsExt)
	if ex != nil {
		t.Fatalf("Unmarshal failed: %v", ex)
	}
	expected := []protocol.Version{
		protocol.Version1_3,
		protocol.Version1_2,
	}
	if !reflect.DeepEqual(expected, sv.Versions) {
		t.Errorf("Versions mismatch.\nExpected: %v\nGot:      %v", expected, sv.Versions)
	}
}

func TestExtensionsUnmarshal_SupportedVersions_ServerHello(t *testing.T) {
	// only selected_version DTLS v1.3
	supportedVersionsExt := []byte{
		0x00, 0x2b, // extension type
		0x00, 0x02, // extension_data length = 2
		0xfe, 0xfc, // selected_version = DTLS v1.3
	}

	var sv SupportedVersions

	ex := sv.Unmarshal(supportedVersionsExt)
	if ex != nil {
		t.Fatalf("Unmarshal failed: %v", ex)
	}
	expected := []protocol.Version{protocol.Version1_3}
	if !reflect.DeepEqual(expected, sv.Versions) {
		t.Errorf("Versions mismatch.\nExpected: %v\nGot:      %v", expected, sv.Versions)
	}
}
