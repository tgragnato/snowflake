// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestPskKeyExchangeModes(t *testing.T) {
	raw := []byte{
		0x00, 0x2d, // extension type
		0x00, 0x02, // extension length
		0x01, // modes length
		0x00, // mode
	}

	extension := PskKeyExchangeModes{}

	expect := PskKeyExchangeModes{KeModes: []PskKeyExchangeMode{PskKe}}

	if extension.Unmarshal(raw) != nil {
		t.Error(extension.Unmarshal(raw))
	}
	if 1 != len(extension.KeModes) {
		t.Errorf("expected %v, got %v", 1, len(extension.KeModes))
	}
	if expect.KeModes[0] != extension.KeModes[0] {
		t.Errorf("expected %v, got %v", expect.KeModes[0], extension.KeModes[0])
	}

	test, err := expect.Marshal()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(raw, test) {
		t.Errorf("expected %v, got %v", raw, test)
	}
}

func TestPskKeyExchangeModes_Empty(t *testing.T) {
	raw := []byte{
		0x00, 0x2d, // extension type
		0x00, 0x01, // extension length
		0x00, // modes length
	}

	extension := PskKeyExchangeModes{}

	err := extension.Unmarshal(raw)
	if !errors.Is(err, dtlserrors.ErrPskKeyExchangeModesFormat) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrPskKeyExchangeModesFormat, err)
	}
}

func FuzzPskKeyExchangeModesUnmarshal(f *testing.F) {
	modes := make([]byte, 0x105)
	modes[0] = 0x00
	modes[1] = 0x2d
	modes[2] = 0x01
	modes[3] = 0x00
	modes[4] = 0xff

	testcases := [][]byte{
		{
			0x00, 0x2d, // extension type
			0x00, 0x02, // extension length
			0x01, // modes length
			0x00, // mode
		},
		{
			0x00, 0x2d, // extension type
			0x00, 0x01, // extension length
			0x00, // modes length
		},
		{
			0x00, 0x2d, // extension type
			0x00, 0x01, // extension length
			0xff, // modes length
		},
		modes,
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pskModes := PskKeyExchangeModes{}
		err := pskModes.Unmarshal(data)
		if err != nil {
			return
		}
		testExtDataLength(t, &pskModes, data, true)
		length := len(pskModes.KeModes)
		if length == 0 {
			t.Errorf("expected non-zero")
		}
		if !(length <= 255) {
			t.Errorf("expected %v <= %v", length, 255)
		}
	})
}
