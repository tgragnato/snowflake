// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"
)

func TestServerName(t *testing.T) {
	extension := ServerName{ServerName: "test.domain"}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	newExtension := ServerName{}
	if newExtension.Unmarshal(raw) != nil {
		t.Error(newExtension.Unmarshal(raw))
	}
	if extension.ServerName != newExtension.ServerName {
		t.Errorf("expected %v, got %v", extension.ServerName, newExtension.ServerName)
	}
}

func FuzzServerNameUnmarshal(f *testing.F) {
	tc := []byte{
		0x0, 0x0, 0x0, 0x10, 0x0, 0xe, 0x0, 0x0, 0xb, 0x74, 0x65, 0x73, 0x74,
		0x2e, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e,
	}
	f.Add(tc)

	f.Fuzz(func(t *testing.T, data []byte) {
		sn := ServerName{}
		err := sn.Unmarshal(data)
		if err != nil {
			return
		}
		testExtDataLength(t, &sn, data, false)
	})
}
