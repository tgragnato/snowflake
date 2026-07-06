// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

import (
	"errors"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestChangeCipherSpecRoundTrip(t *testing.T) {
	c := ChangeCipherSpec{}
	raw, err := c.Marshal()
	if err != nil {
		t.Error(err)
	}

	var cNew ChangeCipherSpec
	if cNew.Unmarshal(raw) != nil {
		t.Error(cNew.Unmarshal(raw))
	}
	if c != cNew {
		t.Errorf("expected %v, got %v", c, cNew)
	}
}

func TestChangeCipherSpecInvalid(t *testing.T) {
	c := ChangeCipherSpec{}
	if !errors.Is(c.Unmarshal([]byte{0x00}), dtlserrors.ErrInvalidCipherSpec) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrInvalidCipherSpec, c.Unmarshal([]byte{0x00}))
	}
}
