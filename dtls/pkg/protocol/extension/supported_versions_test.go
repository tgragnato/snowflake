// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
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
	if rt.Unmarshal(raw) != nil {
		t.Error(rt.Unmarshal(raw))
	}
	if !reflect.DeepEqual(ext.Versions, rt.Versions) {
		t.Errorf("expected %v, got %v", ext.Versions, rt.Versions)
	}
	if rt.IsSelectedVersion() {
		t.Error("expected false")
	}
}

func TestSupportedVersions_ServerHello_RoundTrip(t *testing.T) {
	// Server/HRR form: exactly one entry in Versions.
	ext := &SupportedVersions{
		Versions:        []protocol.Version{protocol.Version1_3},
		SelectedVersion: true,
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
	if rt.Unmarshal(raw) != nil {
		t.Error(rt.Unmarshal(raw))
	}
	if !reflect.DeepEqual([]protocol.Version{protocol.Version1_3}, rt.Versions) {
		t.Errorf("expected %v, got %v", []protocol.Version{protocol.Version1_3}, rt.Versions)
	}
	if !rt.IsSelectedVersion() {
		t.Error("expected true")
	}
}

func TestSupportedVersions_ClientHello_SingleVersionRoundTrip(t *testing.T) {
	ext := &SupportedVersions{
		Versions: []protocol.Version{protocol.Version1_3},
	}

	// length=3, listLen=2, DTLS v1.3
	rawExpected := []byte{
		0x00, 0x2b, // extension type
		0x00, 0x03, // extension_data length
		0x02,       // versions length (bytes)
		0xfe, 0xfc, // DTLS v1.3
	}

	raw, err := ext.Marshal()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(rawExpected, raw) {
		t.Errorf("expected %v, got %v", rawExpected, raw)
	}

	var rt SupportedVersions
	if rt.Unmarshal(raw) != nil {
		t.Error(rt.Unmarshal(raw))
	}
	if !reflect.DeepEqual([]protocol.Version{protocol.Version1_3}, rt.Versions) {
		t.Errorf("expected %v, got %v", []protocol.Version{protocol.Version1_3}, rt.Versions)
	}
	if rt.IsSelectedVersion() {
		t.Error("expected false")
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
	if !errors.Is(err, dtlserrors.ErrInvalidDTLSVersion) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrInvalidDTLSVersion, err)
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
	if !errors.Is(err, dtlserrors.ErrInvalidSupportedVersionsFormat) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrInvalidSupportedVersionsFormat, err)
	}
}

func TestSupportedVersions_Marshal_SelectedVersionRequiresSingleVersion(t *testing.T) {
	ext := &SupportedVersions{
		Versions: []protocol.Version{
			protocol.Version1_3,
			protocol.Version1_2,
		},
		SelectedVersion: true,
	}

	_, err := ext.Marshal()
	if !errors.Is(err, dtlserrors.ErrInvalidSupportedVersionsFormat) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrInvalidSupportedVersionsFormat, err)
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
			err: dtlserrors.ErrInvalidExtensionType,
		},
		{
			name: "empty extension_data",
			raw: []byte{
				0x00, 0x2b, // extension type
				0x00, 0x00, // length = 0
			},
			err: dtlserrors.ErrInvalidSupportedVersionsFormat,
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
			err: dtlserrors.ErrInvalidSupportedVersionsFormat,
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
			err: dtlserrors.ErrInvalidSupportedVersionsFormat,
		},
		{
			name: "server selected wrong size",
			// extension_data length=3 for server form (must be exactly 2 for server form)
			raw: []byte{
				0x00, 0x2b, // extension type
				0x00, 0x03, // length = 3
				0xfe, 0xfc, 0x00,
			},
			err: dtlserrors.ErrInvalidSupportedVersionsFormat,
		},
	}

	for _, tc := range cases {
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
		t.Errorf("expected %v, got %v", expected, sv.Versions)
	}
	if sv.IsSelectedVersion() {
		t.Error("expected false")
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
		t.Error(ex)
	}
	// Server/HRR form yields a single entry in Versions.
	if !reflect.DeepEqual([]protocol.Version{protocol.Version1_3}, sv.Versions) {
		t.Errorf("expected %v, got %v", []protocol.Version{protocol.Version1_3}, sv.Versions)
	}
	if !sv.IsSelectedVersion() {
		t.Error("expected true")
	}
}

func TestExtensionsUnmarshal_SupportedVersions_OneItemVector(t *testing.T) {
	supportedVersionsExt := []byte{
		0x00, 0x2b, // extension type
		0x00, 0x03, // extension_data length = 3
		0x02,       // list length = 2
		0xfe, 0xfc, // DTLS v1.3
	}

	var sv SupportedVersions

	ex := sv.Unmarshal(supportedVersionsExt)
	if ex != nil {
		t.Error(ex)
	}
	if !reflect.DeepEqual([]protocol.Version{protocol.Version1_3}, sv.Versions) {
		t.Errorf("expected %v, got %v", []protocol.Version{protocol.Version1_3}, sv.Versions)
	}
	if sv.IsSelectedVersion() {
		t.Error("expected false")
	}
}

func FuzzSupportedVersionsUnmarshal(f *testing.F) {
	tcs := [][]byte{
		{
			0x00, 0x2b, // extension type
			0x00, 0x02, // extension_data length = 2
			0xfe, 0xfc, // selected_version = DTLS v1.3
		},
		{
			0x00, 0x2b, // extension type
			0x00, 0x07, // extension_data length
			0x06,       // versions length (bytes)
			0xfe, 0xfc, // DTLS v1.3
			0xfe, 0xfd, // DTLS v1.2
			0xfe, 0xff, // DTLS v1.0
		},
		{
			0x00, 0x2b, // extension type
			0x00, 0x02, // extension_data length
			0xfe, 0xfc, // selected_version
		},
	}

	for _, tc := range tcs {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		vers := SupportedVersions{}
		err := vers.Unmarshal(data)
		if err != nil {
			return
		}
		// Invalid versions are filtered out
		testExtDataLength(t, &vers, data, false)
	})
}
