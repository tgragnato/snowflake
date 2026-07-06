// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
)

func TestExtensionSupportedPointFormats(t *testing.T) {
	rawExtensionSupportedPointFormats := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	parsedExtensionSupportedPointFormats := &SupportedPointFormats{
		PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
	}

	raw, err := parsedExtensionSupportedPointFormats.Marshal()
	if err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(raw, rawExtensionSupportedPointFormats) {
		t.Fatalf("extensionSupportedPointFormats marshal: got %#v, want %#v", raw, rawExtensionSupportedPointFormats)
	}

	roundtrip := &SupportedPointFormats{}
	if err := roundtrip.Unmarshal(raw); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(roundtrip, parsedExtensionSupportedPointFormats) {
		t.Errorf(
			"extensionSupportedPointFormats unmarshal: got %#v, want %#v",
			roundtrip, parsedExtensionSupportedPointFormats,
		)
	}
}

func TestExtensionSupportedPointFormats_TooLong(t *testing.T) {
	pointFormats := make([]elliptic.CurvePointFormat, 256)
	_, err := (&SupportedPointFormats{PointFormats: pointFormats}).Marshal()
	if !errors.Is(err, dtlserrors.ErrPointFormatsTooLarge) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrPointFormatsTooLarge, err)
	}
}

func FuzzExtensionSupportedPointFormatsUnmarshal(f *testing.F) {
	tc := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	f.Add(tc)

	f.Fuzz(func(t *testing.T, data []byte) {
		points := SupportedPointFormats{}
		err := points.Unmarshal(data)
		if err != nil {
			return
		}
		// Invalid point formats are filtered out
		testExtDataLength(t, &points, data, false)
	})
}
