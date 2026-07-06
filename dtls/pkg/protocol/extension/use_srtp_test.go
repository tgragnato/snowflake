// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestExtensionUseSRTP(t *testing.T) {
	t.Run("No MasterKeyIdentifier", func(t *testing.T) {
		rawUseSRTP := []byte{0x00, 0x0e, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00}
		parsedUseSRTP := &UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			MasterKeyIdentifier: []byte{},
		}

		marshaled, err := parsedUseSRTP.Marshal()
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(rawUseSRTP, marshaled) {
			t.Errorf("expected %v, got %v", rawUseSRTP, marshaled)
		}

		unmarshaled := &UseSRTP{}
		if unmarshaled.Unmarshal(rawUseSRTP) != nil {
			t.Error(unmarshaled.Unmarshal(rawUseSRTP))
		}
		if !reflect.DeepEqual(parsedUseSRTP, unmarshaled) {
			t.Errorf("expected %v, got %v", parsedUseSRTP, unmarshaled)
		}
	})

	t.Run("With MasterKeyIdentifier", func(t *testing.T) {
		rawUseSRTP := []byte{0x00, 0x0e, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x05, 0xA, 0xB, 0xC, 0xD, 0xE}
		parsedUseSRTP := &UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			MasterKeyIdentifier: []byte{0xA, 0xB, 0xC, 0xD, 0xE},
		}

		marshaled, err := parsedUseSRTP.Marshal()
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(rawUseSRTP, marshaled) {
			t.Errorf("expected %v, got %v", rawUseSRTP, marshaled)
		}

		unmarshaled := &UseSRTP{}
		if unmarshaled.Unmarshal(rawUseSRTP) != nil {
			t.Error(unmarshaled.Unmarshal(rawUseSRTP))
		}
		if !reflect.DeepEqual(parsedUseSRTP, unmarshaled) {
			t.Errorf("expected %v, got %v", parsedUseSRTP, unmarshaled)
		}
	})

	t.Run("Invalid Lengths", func(t *testing.T) {
		unmarshaled := &UseSRTP{}

		err := unmarshaled.Unmarshal([]byte{0x00, 0x0e, 0x00, 0x05, 0x00, 0x04, 0x00, 0x01, 0x00})
		if !errors.Is(err, dtlserrors.ErrLengthMismatch) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrLengthMismatch, err)
		}

		err = unmarshaled.Unmarshal([]byte{0x00, 0x0e, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x01})
		if !errors.Is(err, dtlserrors.ErrLengthMismatch) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrLengthMismatch, err)
		}

		_, err = (&UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			MasterKeyIdentifier: make([]byte, 500),
		}).Marshal()
		if !errors.Is(err, dtlserrors.ErrMasterKeyIdentifierTooLarge) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrMasterKeyIdentifierTooLarge, err)
		}

		_, err = (&UseSRTP{
			ProtectionProfiles: make([]SRTPProtectionProfile, 32767),
		}).Marshal()
		if !errors.Is(err, dtlserrors.ErrUseSRTPDataTooLarge) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrUseSRTPDataTooLarge, err)
		}
	})
}

func FuzzExtensionUseSRTPUnmarshal(f *testing.F) {
	testcases := [][]byte{
		{
			0x00, 0x0e, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00,
		},
		{
			0x00, 0x0e, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x05, 0xA, 0xB, 0xC, 0xD, 0xE,
		},
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		u := UseSRTP{}
		err := u.Unmarshal(data)
		if err != nil {
			return
		}
		// Invalid profiles are filtered out
		testExtDataLength(t, &u, data, false)
	})
}
