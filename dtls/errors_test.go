// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

var errExample = errors.New("an example error")

func TestErrorUnwrap(t *testing.T) {
	err := fmt.Errorf("handshake failed: %w", errExample)

	if !errors.Is(err, errExample) {
		t.Errorf("expected ErrorIs to be true for wrapped error")
	}
	if !errors.Is(errors.Unwrap(err), errExample) {
		t.Errorf("expected ErrorIs to be true for unwrapped error")
	}
}

func TestErrorNetError(t *testing.T) {
	err := temporaryNetworkError{err: errExample}

	var ne net.Error
	if !errors.As(err, &ne) {
		t.Errorf("expected ErrorAs to succeed")
	}
	if !errors.Is(err, errExample) {
		t.Errorf("expected ErrorIs to be true")
	}
	if ne.Timeout() {
		t.Errorf("expected Timeout() to be false")
	}
	if !ne.Temporary() {
		t.Errorf("expected Temporary() to be true")
	}
	if ne.Error() != "an example error" {
		t.Errorf("expected error message 'an example error', got '%s'", ne.Error())
	}
}
