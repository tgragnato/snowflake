// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"
	"testing"
)

func TestHandshakeMessageServerHelloDone(t *testing.T) {
	rawServerHelloDone := []byte{}
	parsedServerHelloDone := &MessageServerHelloDone{}

	c := &MessageServerHelloDone{}
	if c.Unmarshal(rawServerHelloDone) != nil {
		t.Error(c.Unmarshal(rawServerHelloDone))
	}
	if parsedServerHelloDone != c {
		t.Errorf("expected %v, got %v", parsedServerHelloDone, c)
	}

	raw, err := c.Marshal()
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(rawServerHelloDone, raw) {
		t.Errorf("expected %v, got %v", rawServerHelloDone, raw)
	}
}
