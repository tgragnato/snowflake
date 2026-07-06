// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"golang.org/x/crypto/cryptobyte"
)

func TestPreSharedKey_ServerHello(t *testing.T) {
	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x02, // extension length
		0x01, 0x42, // selected_identity
	}

	extension := PreSharedKey{}

	expect := PreSharedKey{SelectedIdentity: 0x142}

	if extension.Unmarshal(raw) != nil {
		t.Error(extension.Unmarshal(raw))
	}
	if expect.SelectedIdentity != extension.SelectedIdentity {
		t.Errorf("expected %v, got %v", expect.SelectedIdentity, extension.SelectedIdentity)
	}

	test, err := expect.Marshal()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(raw, test) {
		t.Errorf("expected %v, got %v", raw, test)
	}
}

func TestPreSharedKey_ClientHello(t *testing.T) {
	binder := make([]byte, 32)
	for i := range binder {
		binder[i] = byte(i)
	}

	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x2d, // extension length
		0x00, 0x08, // identities length
		0x00, 0x02, // identity length
		0x42, 0x42, // identity
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x21, // binders length
		0x20, // binder entry legnth
	}

	raw = append(raw, binder...)

	extension := PreSharedKey{}

	expectIdentity := PskIdentity{Identity: []byte{0x42, 0x42}, ObfuscatedTicketAge: uint32(0xffffffff)}
	expect := PreSharedKey{Identities: []PskIdentity{expectIdentity}, Binders: []PskBinderEntry{binder}}

	if extension.Unmarshal(raw) != nil {
		t.Error(extension.Unmarshal(raw))
	}
	if uint16(0) != extension.SelectedIdentity {
		t.Errorf("expected %v, got %v", uint16(0), extension.SelectedIdentity)
	}
	if 1 != len(extension.Identities) {
		t.Errorf("expected %v, got %v", 1, len(extension.Identities))
	}
	if !reflect.DeepEqual(expect.Identities[0], extension.Identities[0]) {
		t.Errorf("expected %v, got %v", expect.Identities[0], extension.Identities[0])
	}
	if 1 != len(extension.Binders) {
		t.Errorf("expected %v, got %v", 1, len(extension.Binders))
	}
	if !reflect.DeepEqual(expect.Binders[0], extension.Binders[0]) {
		t.Errorf("expected %v, got %v", expect.Binders[0], extension.Binders[0])
	}

	test, err := expect.Marshal()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(raw, test) {
		t.Errorf("expected %v, got %v", raw, test)
	}
}

func TestPreSharedKey_ClientHello_EmptyIdentities(t *testing.T) {
	binder := make([]byte, 32)
	for i := range binder {
		binder[i] = byte(i)
	}

	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x2b, // extension length
		0x00, 0x06, // identities length
		0x00, 0x00, // identity length
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x21, // binders length
		0x20, // binder entry legnth
	}

	raw = append(raw, binder...)

	extension := PreSharedKey{}

	err := extension.Unmarshal(raw)
	if !errors.Is(err, dtlserrors.ErrPreSharedKeyFormat) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrPreSharedKeyFormat, err)
	}
}

func TestPreSharedKey_ClientHello_MultipleIdentities(t *testing.T) {
	binder := make([]byte, 32)
	for i := range binder {
		binder[i] = byte(i)
	}

	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x56, // extension length
		0x00, 0x10, // identities length
		0x00, 0x02, // identity length
		0x41, 0x41, // identity
		0xaa, 0xaa, // ticket_age
		0xaa, 0xaa, // ticket_age
		0x00, 0x02, // identity length
		0x42, 0x42, // identity
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x42, // binders length
		0x20, // binder entry legnth
	}

	raw = append(raw, binder...)
	raw = append(raw, []byte{0x20}...)
	raw = append(raw, binder...)

	extension := PreSharedKey{}

	expectIdentity1 := PskIdentity{
		Identity:            []byte{0x41, 0x41},
		ObfuscatedTicketAge: uint32(0xaaaaaaaa),
	}
	expectIdentity2 := PskIdentity{
		Identity:            []byte{0x42, 0x42},
		ObfuscatedTicketAge: uint32(0xffffffff),
	}

	expect := PreSharedKey{
		Identities: []PskIdentity{
			expectIdentity1,
			expectIdentity2,
		},
		Binders: []PskBinderEntry{
			binder,
			binder,
		},
	}

	if extension.Unmarshal(raw) != nil {
		t.Error(extension.Unmarshal(raw))
	}
	if uint16(0) != extension.SelectedIdentity {
		t.Errorf("expected %v, got %v", uint16(0), extension.SelectedIdentity)
	}
	if 2 != len(extension.Identities) {
		t.Errorf("expected %v, got %v", 2, len(extension.Identities))
	}
	if !reflect.DeepEqual(expect.Identities[0], extension.Identities[0]) {
		t.Errorf("expected %v, got %v", expect.Identities[0], extension.Identities[0])
	}
	if !reflect.DeepEqual(expect.Identities[1], extension.Identities[1]) {
		t.Errorf("expected %v, got %v", expect.Identities[1], extension.Identities[1])
	}
	if 2 != len(extension.Binders) {
		t.Errorf("expected %v, got %v", 2, len(extension.Binders))
	}
	if !reflect.DeepEqual(expect.Binders[0], extension.Binders[0]) {
		t.Errorf("expected %v, got %v", expect.Binders[0], extension.Binders[0])
	}
	if !reflect.DeepEqual(expect.Binders[1], extension.Binders[1]) {
		t.Errorf("expected %v, got %v", expect.Binders[1], extension.Binders[1])
	}

	test, err := expect.Marshal()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(raw, test) {
		t.Errorf("expected %v, got %v", raw, test)
	}
}

func TestPreSharedKey_ClientHello_MultipleIdentities_SingleBinder(t *testing.T) {
	binder := make([]byte, 32)
	for i := range binder {
		binder[i] = byte(i)
	}

	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x0a, // extension length
		0x00, 0x10, // identities length
		0x00, 0x02, // identity length
		0x41, 0x41, // identity
		0xaa, 0xaa, // ticket_age
		0xaa, 0xaa, // ticket_age
		0x00, 0x02, // identity length
		0x42, 0x42, // identity
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x42, // binders length
		0x20, // binder entry legnth
	}

	raw = append(raw, binder...)

	extension := PreSharedKey{}

	err := extension.Unmarshal(raw)
	if !errors.Is(err, dtlserrors.ErrPreSharedKeyFormat) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrPreSharedKeyFormat, err)
	}
}

func TestPreSharedKey_ClientHello_LowBinders(t *testing.T) {
	binder := make([]byte, 16)
	for i := range binder {
		binder[i] = byte(i)
	}
	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x0a, // extension length
		0x00, 0x06, // identities length
		0x00, 0x02, // identity length
		0x42, 0x42, // identity
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x11, // binders length
		0x10, // binder entry legnth
	}
	raw = append(raw, binder...)

	extension := PreSharedKey{}

	err := extension.Unmarshal(raw)
	if !errors.Is(err, dtlserrors.ErrPreSharedKeyFormat) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrPreSharedKeyFormat, err)
	}
}

func FuzzPreSharedKeyUnmarshal(f *testing.F) {
	binder := make([]byte, 32)
	for i := range binder {
		binder[i] = byte(i)
	}

	rawCH := []byte{
		0x00, 0x29, // extension type
		0x00, 0x2d, // extension length
		0x00, 0x08, // identities length
		0x00, 0x02, // identity length
		0x42, 0x42, // identity
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x21, // binders length
		0x20, // binder entry legnth
	}

	rawCH = append(rawCH, binder...)

	testcases := [][]byte{
		{
			0x00, 0x29, // extension type
			0x00, 0x02, // extension length
			0x01, 0x42, // selected_identity
		},
		rawCH,
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		psk := PreSharedKey{}
		err := psk.Unmarshal(data)
		if err != nil {
			return
		}
		testExtDataLength(t, &psk, data, true)

		// ServerHello
		if len(data) == 6 && len(psk.Identities) != 0 && len(psk.Binders) != 0 {
			{
				t.Error("PreSharedKey was unmarshalled without error both as ServerHello and ClientHello")
			}
		}

		// ClientHello
		b := cryptobyte.String(data[2:3])
		var length uint16
		b.ReadUint16(&length)
		if length > 2 {
			if len(psk.Identities) == 0 {
				t.Errorf("expected non-zero")
			}
			if len(psk.Binders) == 0 {
				t.Errorf("expected non-zero")
			}
			if !reflect.DeepEqual(psk.Binders, psk.Binders) {
				t.Errorf("expected %v, got %v", len(psk.Binders), len(psk.Binders))
			}
		}
	})
}
