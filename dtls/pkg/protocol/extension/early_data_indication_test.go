// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"reflect"
	"testing"
)

func TestEarlyDataIndication_NewSessionTicket(t *testing.T) {
	earlyData := uint32(128)
	extension := EarlyDataIndication{MaxEarlyData: &earlyData}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x00, 0x2a, // extension type
		0x00, 0x04, // extension length
		0x00, 0x00, // MaxEarlyData
		0x00, 0x80, // MaxEarlyData
	}
	if !reflect.DeepEqual(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newExtension := EarlyDataIndication{}

	if newExtension.Unmarshal(expect) != nil {
		t.Error(newExtension.Unmarshal(expect))
	}
	if extension.MaxEarlyData != newExtension.MaxEarlyData {
		t.Errorf("expected %v, got %v", extension.MaxEarlyData, newExtension.MaxEarlyData)
	}
}

func TestEarlyDataIndication_CHEE(t *testing.T) {
	extension := EarlyDataIndication{}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x00, 0x2a, // extension type
		0x00, 0x00, // extension length
	}
	if !reflect.DeepEqual(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newExtension := EarlyDataIndication{}

	if newExtension.Unmarshal(expect) != nil {
		t.Error(newExtension.Unmarshal(expect))
	}
	if newExtension.MaxEarlyData != nil {
		t.Errorf("expected nil, got %v", newExtension.MaxEarlyData)
	}
}

func FuzzEarlyDataIndicationUnmarshal(f *testing.F) {
	testCases := [][]byte{
		// NewSessionTicket
		{
			0x00, 0x2a, // extension type
			0x00, 0x04, // extension length
			0x00, 0x00, // MaxEarlyData
			0x00, 0x80, // MaxEarlyData
		},
		// ClientHello, EncryptedExtensions
		{
			0x00, 0x2a, // extension type
			0x00, 0x00, // extension length
		},
	}
	for _, tc := range testCases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var e EarlyDataIndication
		err := e.Unmarshal(data)
		if err != nil {
			return
		}
		testExtDataLength(t, &e, data, true)
	})
}
