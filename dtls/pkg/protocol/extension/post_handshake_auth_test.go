// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestPostHandshakeAuth(t *testing.T) {
	extension := PostHandshakeAuth{Enabled: true}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x00, 0x31, // extension type
		0x00, 0x00, // extension length
	}
	if !reflect.DeepEqual(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newExtension := PostHandshakeAuth{}

	if newExtension.Unmarshal(expect) != nil {
		t.Error(newExtension.Unmarshal(expect))
	}
	if extension.Enabled != newExtension.Enabled {
		t.Errorf("expected %v, got %v", extension.Enabled, newExtension.Enabled)
	}
}

func TestPostHandshakeAuth_NonEmpty(t *testing.T) {
	raw := []byte{
		0x00, 0x31, // extension type
		0x00, 0x42, // extension length
	}
	newExtension := PostHandshakeAuth{}
	err := newExtension.Unmarshal(raw)

	if !errors.Is(err, dtlserrors.ErrLengthMismatch) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrLengthMismatch, err)
	}
}

func FuzzPostHandshakeAuthUnmarshal(f *testing.F) {
	testcases := [][]byte{
		{
			0x00, 0x31, // extension type
			0x00, 0x00, // extension length
		},
		{
			0x00, 0x31, // extension type
			0x00, 0x02, // extension length
			0x42, 0x42,
		},
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p := PostHandshakeAuth{}
		err := p.Unmarshal(data)
		if err != nil {
			return
		}
		testExtDataLength(t, &p, data, true)
	})
}
