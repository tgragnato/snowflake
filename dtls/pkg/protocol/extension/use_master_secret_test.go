// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestUseMasterSecret(t *testing.T) {
	extension := UseExtendedMasterSecret{Supported: true}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x00, 0x17, // extension type
		0x00, 0x00, // extension length
	}
	if !reflect.DeepEqual(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newExtension := UseExtendedMasterSecret{}

	if newExtension.Unmarshal(expect) != nil {
		t.Error(newExtension.Unmarshal(expect))
	}
	if extension.Supported != newExtension.Supported {
		t.Errorf("expected %v, got %v", extension.Supported, newExtension.Supported)
	}
}

func TestUseMasterSecret_NonEmpty(t *testing.T) {
	raw := []byte{
		0x00, 0x17, // extension type
		0x00, 0x42, // extension length
	}
	newExtension := UseExtendedMasterSecret{}
	err := newExtension.Unmarshal(raw)

	if !errors.Is(err, dtlserrors.ErrLengthMismatch) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrLengthMismatch, err)
	}
}

func FuzzUseMasterSecretUnmarshal(f *testing.F) {
	testcases := [][]byte{
		{
			0x00, 0x17, // extension type
			0x00, 0x00, // extension length
		},
		{
			0x00, 0x17, // extension type
			0x00, 0x02, // extension length
			0x42, 0x42,
		},
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m := UseExtendedMasterSecret{}
		err := m.Unmarshal(data)
		if err != nil {
			return
		}
		testExtDataLength(t, &m, data, true)
	})
}
