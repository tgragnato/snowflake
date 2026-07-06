// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestOIDFilters(t *testing.T) {
	oid := []byte{0x55, 0x04, 0x03}
	values := []byte{0xde, 0xad, 0xbe, 0xef}
	filter := OIDFilter{OID: oid, Values: values}
	extension := OIDFilters{Filters: []OIDFilter{filter}}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x00, 0x30, // extension type (48)
		0x00, 0x0c, // extension data length
		0x00, 0x0a, // filter list length
		0x03,             // OID length
		0x55, 0x04, 0x03, // OID bytes (id-at-commonName)
		0x00, 0x04, // values length
		0xde, 0xad, 0xbe, 0xef, // values bytes
	}
	if !reflect.DeepEqual(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newExtension := OIDFilters{}
	if newExtension.Unmarshal(expect) != nil {
		t.Error(newExtension.Unmarshal(expect))
	}
	if len(newExtension.Filters) != 1 {
		t.Errorf("expected len %d, got %d", 1, len(newExtension.Filters))
	}
	if !reflect.DeepEqual(oid, newExtension.Filters[0].OID) {
		t.Errorf("expected %v, got %v", oid, newExtension.Filters[0].OID)
	}
	if !reflect.DeepEqual(values, newExtension.Filters[0].Values) {
		t.Errorf("expected %v, got %v", values, newExtension.Filters[0].Values)
	}
}

func TestOIDFilters_MultipleFilters(t *testing.T) {
	oid1 := []byte{0x55, 0x04}
	values1 := []byte{0xaa, 0xbb}
	oid2 := []byte{0x55, 0x05}
	values2 := []byte{0x01, 0x02, 0x03, 0x04}
	extension := OIDFilters{Filters: []OIDFilter{
		{OID: oid1, Values: values1},
		{OID: oid2, Values: values2},
	}}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x00, 0x30, // extension type
		0x00, 0x12, // extension data length
		0x00, 0x10, // filter list length
		0x02,       // OID length
		0x55, 0x04, // OID bytes
		0x00, 0x02, // values length
		0xaa, 0xbb, // values bytes
		0x02,       // OID length
		0x55, 0x05, // OID bytes
		0x00, 0x04, // values length
		0x01, 0x02, 0x03, 0x04, // values bytes
	}
	if !reflect.DeepEqual(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newExtension := OIDFilters{}
	if newExtension.Unmarshal(expect) != nil {
		t.Error(newExtension.Unmarshal(expect))
	}
	if len(newExtension.Filters) != 2 {
		t.Errorf("expected len %d, got %d", 2, len(newExtension.Filters))
	}
	if !reflect.DeepEqual(oid1, newExtension.Filters[0].OID) {
		t.Errorf("expected %v, got %v", oid1, newExtension.Filters[0].OID)
	}
	if !reflect.DeepEqual(values1, newExtension.Filters[0].Values) {
		t.Errorf("expected %v, got %v", values1, newExtension.Filters[0].Values)
	}
	if !reflect.DeepEqual(oid2, newExtension.Filters[1].OID) {
		t.Errorf("expected %v, got %v", oid2, newExtension.Filters[1].OID)
	}
	if !reflect.DeepEqual(values2, newExtension.Filters[1].Values) {
		t.Errorf("expected %v, got %v", values2, newExtension.Filters[1].Values)
	}
}

func TestOIDFilters_DuplicateFilters(t *testing.T) {
	oid := []byte{0x55, 0x04}
	values1 := []byte{0xaa, 0xbb}
	values2 := []byte{0xcc, 0xdd}
	extension := OIDFilters{Filters: []OIDFilter{
		{OID: oid, Values: values1},
		{OID: oid, Values: values2},
	}}

	_, err := extension.Marshal()
	if !errors.Is(err, dtlserrors.ErrDuplicateOID) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrDuplicateOID, err)
	}

	raw := []byte{
		0x00, 0x30, // extension type
		0x00, 0x10, // extension data length
		0x00, 0x0e, // filter list length
		0x02,       // OID length
		0x55, 0x04, // OID bytes
		0x00, 0x02, // values length
		0xaa, 0xbb, // values bytes
		0x02,       // OID length
		0x55, 0x04, // OID bytes
		0x00, 0x02, // values length
		0xcc, 0xdd, // values bytes
	}

	newExtension := OIDFilters{}
	if !errors.Is(newExtension.Unmarshal(raw), dtlserrors.ErrDuplicateOID) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrDuplicateOID, newExtension.Unmarshal(raw))
	}
}

func TestOIDFilters_EmptyValues(t *testing.T) {
	oid := []byte{0x55, 0x04, 0x03}
	extension := OIDFilters{Filters: []OIDFilter{
		{OID: oid, Values: []byte{}},
	}}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x00, 0x30, // extension type
		0x00, 0x08, // extension data length
		0x00, 0x06, // filter list length
		0x03,             // OID length
		0x55, 0x04, 0x03, // OID bytes
		0x00, 0x00, // values length (empty)
	}
	if !reflect.DeepEqual(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newExtension := OIDFilters{}
	if newExtension.Unmarshal(expect) != nil {
		t.Error(newExtension.Unmarshal(expect))
	}
	if len(newExtension.Filters) != 1 {
		t.Errorf("expected len %d, got %d", 1, len(newExtension.Filters))
	}
	if !reflect.DeepEqual(oid, newExtension.Filters[0].OID) {
		t.Errorf("expected %v, got %v", oid, newExtension.Filters[0].OID)
	}
	if len(newExtension.Filters[0].Values) != 0 {
		t.Error("expected empty")
	}
}

func TestOIDFilters_EmptyFilterList(t *testing.T) {
	extension := OIDFilters{Filters: []OIDFilter{}}

	raw, err := extension.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x00, 0x30, // extension type
		0x00, 0x02, // extension data length
		0x00, 0x00, // filter list length (empty)
	}
	if !reflect.DeepEqual(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newExtension := OIDFilters{}
	if newExtension.Unmarshal(expect) != nil {
		t.Error(newExtension.Unmarshal(expect))
	}
	if len(newExtension.Filters) != 0 {
		t.Error("expected empty")
	}
}

func TestOIDFilters_EmptyOID(t *testing.T) {
	raw := []byte{
		0x00, 0x30, // extension type
		0x00, 0x04, // extension data length
		0x00, 0x02, // filter list length
		0x00, // OID length = 0 (invalid)
		0x00, // start of values length
	}
	newExtension := OIDFilters{}
	if !errors.Is(newExtension.Unmarshal(raw), dtlserrors.ErrOIDFiltersFormat) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrOIDFiltersFormat, newExtension.Unmarshal(raw))
	}
}

func TestOIDFilters_MarshalEmptyOID(t *testing.T) {
	extension := OIDFilters{Filters: []OIDFilter{
		{OID: []byte{}, Values: []byte{0x01}},
	}}
	_, err := extension.Marshal()
	if !errors.Is(err, dtlserrors.ErrEmptyOIDFilter) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrEmptyOIDFilter, err)
	}
}

func FuzzOIDFiltersUnmarshal(f *testing.F) {
	f.Add([]byte{
		0x00, 0x30,
		0x00, 0x0c,
		0x00, 0x0a,
		0x03, 0x55, 0x04, 0x03,
		0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,
	})
	f.Add([]byte{
		0x00, 0x30,
		0x00, 0x02,
		0x00, 0x00,
	})
	f.Add([]byte{
		0x00, 0x30,
		0x00, 0x04,
		0x00, 0x02,
		0x00, 0x00,
	})
	f.Add([]byte{0x00, 0x30})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		ext := OIDFilters{}
		err := ext.Unmarshal(data)
		if err != nil {
			return
		}
		seen := map[string]struct{}{}
		for _, filter := range ext.Filters {
			if len(filter.OID) == 0 {
				t.Errorf("expected non-empty")
			}
			_, dup := seen[string(filter.OID)]
			if dup {
				t.Error("expected false")
			}
			seen[string(filter.OID)] = struct{}{}
		}
		testExtDataLength(t, &ext, data, true)
	})
}
