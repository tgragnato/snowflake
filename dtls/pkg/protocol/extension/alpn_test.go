// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestALPN(t *testing.T) {
	extension := ALPN{
		ProtocolNameList: []string{"http/1.1", "spdy/1", "spdy/2", "spdy/3"},
	}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	newExtension := ALPN{}
	if newExtension.Unmarshal(raw) != nil {
		t.Error(newExtension.Unmarshal(raw))
	}
	if !reflect.DeepEqual(extension.ProtocolNameList, newExtension.ProtocolNameList) {
		t.Errorf("expected %v, got %v", extension.ProtocolNameList, newExtension.ProtocolNameList)
	}
}

func TestALPNProtocolSelection(t *testing.T) {
	selectedProtocol, err := ALPNProtocolSelection([]string{"http/1.1", "spd/1"}, []string{"spd/1"})
	if err != nil {
		t.Error(err)
	}
	if "spd/1" != selectedProtocol {
		t.Errorf("expected %v, got %v", "spd/1", selectedProtocol)
	}

	_, err = ALPNProtocolSelection([]string{"http/1.1"}, []string{"spd/1"})
	if !errors.Is(err, dtlserrors.ErrALPNNoAppProto) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrALPNNoAppProto, err)
	}

	selectedProtocol, err = ALPNProtocolSelection([]string{"http/1.1", "spd/1"}, []string{})
	if err != nil {
		t.Error(err)
	}
	if len(selectedProtocol) != 0 {
		t.Error("expected empty")
	}
}

func FuzzALPNUnmarshal(f *testing.F) {
	testCases := [][]byte{
		{
			0x00, 0x10, // Extension type
			0x00, 0x04, // Extension length
			0x00, 0x02, // ALPN length
			0x00, // ALPN length
			0x00, // ALPN
		},
		{
			0x00, 0x10, // Extension type
			0x00, 0x04, // Extension length
			0x00, 0x02, // ALPN list length
			0x01, // ALPN length
			0x41, // ALPN
		},
		{
			0x00, 0x10, // Extension type
			0x00, 0x06, // Extension length
			0x00, 0x0a, // ALPN list length
			0x01, // ALPN length
			0x41, // ALPN
			0x01, // ALPN length
			0x42, // ALPN
			0x42, // ALPN
			0x42, // ALPN
			0x42, // ALPN
			0x42, // ALPN
		},
	}
	for _, tc := range testCases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		alpn := ALPN{}
		err := alpn.Unmarshal(data)
		if err != nil {
			return
		}
		length := len(alpn.ProtocolNameList)
		if length == 0 {
			t.Errorf("expected non-zero")
		}

		for _, s := range alpn.ProtocolNameList {
			if len(s) == 0 {
				t.Errorf("expected non-zero")
			}
		}
		testExtDataLength(t, &alpn, data, true)
	})
}
