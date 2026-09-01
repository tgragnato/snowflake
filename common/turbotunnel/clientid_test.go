package turbotunnel

import (
	"encoding/hex"
	"net"
	"testing"
)

// A ClientID is the return address of a session, so two of them must not
// collide: a repeat would splice two clients' traffic together.
func TestNewClientIDIsUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[ClientID]struct{})
	for range 1000 {
		id := NewClientID()
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("NewClientID returned the duplicate %v", id)
		}
		seen[id] = struct{}{}
	}
}

func TestNewClientIDIsNotZero(t *testing.T) {
	t.Parallel()

	var zero ClientID
	for range 100 {
		if NewClientID() == zero {
			t.Fatal("NewClientID returned the zero value")
		}
	}
}

func TestClientIDImplementsNetAddr(t *testing.T) {
	t.Parallel()

	var addr net.Addr = NewClientID()

	if got := addr.Network(); got != "clientid" {
		t.Errorf("Network: got %q, want \"clientid\"", got)
	}
}

func TestClientIDString(t *testing.T) {
	t.Parallel()

	id := ClientID{0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd}

	const want = "000123456789abcd"
	if got := id.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// The string form is the hex encoding of all 8 bytes, which is what the
	// logs use to refer to a session.
	decoded, err := hex.DecodeString(id.String())
	if err != nil {
		t.Fatalf("String did not produce valid hex: %v", err)
	}
	if len(decoded) != len(id) {
		t.Errorf("decoded %d bytes, want %d", len(decoded), len(id))
	}
	for i := range id {
		if decoded[i] != id[i] {
			t.Errorf("byte %d: got %#x, want %#x", i, decoded[i], id[i])
		}
	}
}

func TestClientIDStringZero(t *testing.T) {
	t.Parallel()

	var zero ClientID
	if got, want := zero.String(), "0000000000000000"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
