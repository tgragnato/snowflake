// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"
)

func TestRenegotiationInfo(t *testing.T) {
	extension := RenegotiationInfo{RenegotiatedConnection: 0}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	newExtension := RenegotiationInfo{}
	if newExtension.Unmarshal(raw) != nil {
		t.Error(newExtension.Unmarshal(raw))
	}
	if extension.RenegotiatedConnection != newExtension.RenegotiatedConnection {
		t.Errorf("expected %v, got %v", extension.RenegotiatedConnection, newExtension.RenegotiatedConnection)
	}
}

func FuzzRenegotiationInfoUnmarshal(f *testing.F) {
	validCase := []byte{
		0xff, 0x01, // Extension type
		0x00, 0x01, // Extension length
		0x00, // RenegotiatedConnection
	}

	withTrailing := []byte{
		0xff, 0x01, // Extension type
		0x00, 0x01, // Extension length (says 1 byte follows)
		0x00,       // RenegotiatedConnection
		0xde, 0xad, // Trailing data
	}

	// Too short
	tooShort := []byte{0xff, 0x01, 0x00}

	testCases := [][]byte{
		validCase,
		withTrailing,
		tooShort,
	}
	for _, tc := range testCases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		ri := RenegotiationInfo{}
		err := ri.Unmarshal(data)
		if err != nil {
			return
		}
		testExtDataLength(t, &ri, data, true)
	})
}
