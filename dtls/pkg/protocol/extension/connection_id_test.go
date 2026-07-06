// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"reflect"
	"testing"

)

func TestExtensionConnectionID(t *testing.T) {
	rawExtensionConnectionID := []byte{1, 6, 8, 3, 88, 12, 2, 47}
	parsedExtensionConnectionID := &ConnectionID{
		CID: rawExtensionConnectionID,
	}

	raw, err := parsedExtensionConnectionID.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	roundtrip := &ConnectionID{}
	if err := roundtrip.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(roundtrip, parsedExtensionConnectionID) {
		t.Errorf("parsedExtensionConnectionID unmarshal: got %#v, want %#v", roundtrip, parsedExtensionConnectionID)
	}
}

func FuzzCIDUnmarshal(f *testing.F) {
	bigCID := make([]byte, 0xff)
	bigCID[0] = 0x00
	bigCID[1] = 0x36
	bigCID[2] = 0xff
	bigCID[3] = 0xff
	bigCID[4] = 0xff
	bigCID[5] = 0xfd

	testCases := [][]byte{
		{
			0x00, 0x36, // Extension type
			0x00, 0x03, // Extension length
			0x00, 0x01, // CID length
			0x42, // CID
		},
		bigCID,
	}
	for _, tc := range testCases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		cid := ConnectionID{}
		err := cid.Unmarshal(data)
		if err != nil {
			return
		}
		length := len(cid.CID)
		if !(length < 0xff) {
								t.Errorf("expected %v < %v", length, 0xff)
							}
		testExtDataLength(t, &cid, data, true)
	})
}
