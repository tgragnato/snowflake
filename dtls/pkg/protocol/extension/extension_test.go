// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestExtensions(t *testing.T) {
	t.Run("Zero", func(t *testing.T) {
		extensions, err := Unmarshal([]byte{})
		if err != nil || len(extensions) != 0 {
			t.Fatal("Failed to decode zero extensions")
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		extensions, err := Unmarshal([]byte{0x00})
		if !errors.Is(err, dtlserrors.ErrBufferTooSmall) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrBufferTooSmall, err)
		}
		if len(extensions) != 0 {
			t.Error("expected empty")
		}
	})
}

// testExtDataLength is used to check the declared length in an extension and
// trailing bytes. It should only be called after a succesfull unmarshal.
func testExtDataLength(t *testing.T, ext Extension, data []byte, trailing bool) {
	t.Helper()
	// [2 type][2 length][...value...]
	if len(data) < 4 {
		{
			t.Error("Unmarshal succeeded with fewer than 4 bytes")
		}
	}
	declaredLength := int(binary.BigEndian.Uint16(data[2:4]))
	extensionEnd := 4 + declaredLength

	// The extension data window must not overflow the data buffer.
	if extensionEnd > len(data) {
		t.Errorf("Unmarshal succeeded but declared length %d overflows actual data length %d. Data: %x",
			declaredLength, len(data), data)

		return
	}

	if trailing {
		// If the round-trip produces different bytes, Unmarshal consumed
		// something it shouldn't have or there are trailing bytes in the extension.
		enc, err := ext.Marshal()
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(data[:extensionEnd], enc) {
			t.Errorf("expected %v, got %v", data[:extensionEnd], enc)
		}
	}
}
