package nat

import (
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// mappedAddr is the address the fake servers report back in
// XOR-MAPPED-ADDRESS. Any two different values stand in for a NAT that
// allocates a different mapping per destination.
var (
	mappedAddrA = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 1234}
	mappedAddrB = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 5678}
)

// fakeSTUNServer is a UDP listener that answers STUN binding requests with
// whatever the handler decides, standing in for an RFC 5780 capable server.
type fakeSTUNServer struct {
	conn *net.UDPConn
}

// newFakeSTUNServer starts a server that replies to each binding request with
// the message returned by handler. A nil return means the request is dropped,
// which is how a real server behaves when the client's NAT filters the reply.
func newFakeSTUNServer(t *testing.T, handler func(req *stun.Message) *stun.Message) *fakeSTUNServer {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	s := &fakeSTUNServer{conn: conn}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return // the listener was closed
			}

			req := new(stun.Message)
			req.Raw = append([]byte(nil), buf[:n]...)
			if err := req.Decode(); err != nil {
				continue
			}

			resp := handler(req)
			if resp == nil {
				continue
			}
			if _, err := conn.WriteTo(resp.Raw, from); err != nil {
				return
			}
		}
	}()

	return s
}

func (s *fakeSTUNServer) addr() string {
	return s.conn.LocalAddr().String()
}

func (s *fakeSTUNServer) udpAddr() *net.UDPAddr {
	return s.conn.LocalAddr().(*net.UDPAddr)
}

// isChangeRequest reports whether the request asks the server to reply from a
// different address and port, which is Test II of the filtering probe.
func isChangeRequest(req *stun.Message) bool {
	_, err := req.Get(stun.AttrChangeRequest)
	return err == nil
}

// bindingSuccess builds a success response carrying the given mapped address,
// and an OTHER-ADDRESS attribute when otherAddr is not nil. The transaction ID
// is set first because XOR-MAPPED-ADDRESS is encoded against it.
func bindingSuccess(req *stun.Message, mapped *net.UDPAddr, otherAddr *net.UDPAddr) *stun.Message {
	setters := []stun.Setter{
		stun.NewTransactionIDSetter(req.TransactionID),
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: mapped.IP, Port: mapped.Port},
	}
	if otherAddr != nil {
		setters = append(setters, &stun.OtherAddress{IP: otherAddr.IP, Port: otherAddr.Port})
	}
	return stun.MustBuild(setters...)
}

// newMappingServers starts the pair of servers the mapping probe needs: a
// primary that advertises the secondary via OTHER-ADDRESS, and the secondary
// itself. Each reports its own mapped address, so passing two different values
// simulates an address-dependent (restricted) mapping.
func newMappingServers(t *testing.T, primaryMapped, otherMapped *net.UDPAddr) *fakeSTUNServer {
	t.Helper()

	other := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
		return bindingSuccess(req, otherMapped, nil)
	})
	return newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
		return bindingSuccess(req, primaryMapped, other.udpAddr())
	})
}

func TestIsRestrictedMapping(t *testing.T) {
	t.Parallel()

	t.Run("address independent mapping is not restricted", func(t *testing.T) {
		t.Parallel()

		primary := newMappingServers(t, mappedAddrA, mappedAddrA)

		restricted, err := isRestrictedMapping(primary.addr(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if restricted {
			t.Error("the same mapped address for both tests must not be reported as restricted")
		}
	})

	t.Run("address dependent mapping is restricted", func(t *testing.T) {
		t.Parallel()

		primary := newMappingServers(t, mappedAddrA, mappedAddrB)

		restricted, err := isRestrictedMapping(primary.addr(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !restricted {
			t.Error("a different mapped address per destination must be reported as restricted")
		}
	})

	t.Run("missing OTHER-ADDRESS is unsupported", func(t *testing.T) {
		t.Parallel()

		// A server without RFC 5780 support cannot be used to classify.
		primary := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
			return bindingSuccess(req, mappedAddrA, nil)
		})

		if _, err := isRestrictedMapping(primary.addr(), nil); err == nil {
			t.Fatal("expected an error when OTHER-ADDRESS is absent")
		}
	})

	t.Run("missing XOR-MAPPED-ADDRESS is an error", func(t *testing.T) {
		t.Parallel()

		primary := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
			return stun.MustBuild(stun.NewTransactionIDSetter(req.TransactionID), stun.BindingSuccess)
		})

		if _, err := isRestrictedMapping(primary.addr(), nil); err == nil {
			t.Fatal("expected an error when XOR-MAPPED-ADDRESS is absent")
		}
	})

	t.Run("unresolvable server", func(t *testing.T) {
		t.Parallel()

		if _, err := isRestrictedMapping("no-such-host.invalid:3478", nil); err == nil {
			t.Fatal("expected an error for an unresolvable server")
		}
	})
}

func TestCheckIfRestrictedNAT(t *testing.T) {
	t.Parallel()

	primary := newMappingServers(t, mappedAddrA, mappedAddrB)

	// Both the deprecated and the proxy-aware entry points must agree with
	// the underlying mapping probe.
	restricted, err := CheckIfRestrictedNAT(primary.addr())
	if err != nil {
		t.Fatalf("CheckIfRestrictedNAT: %v", err)
	}
	if !restricted {
		t.Error("CheckIfRestrictedNAT: expected a restricted result")
	}

	restricted, err = CheckIfRestrictedNATWithProxy(primary.addr(), nil)
	if err != nil {
		t.Fatalf("CheckIfRestrictedNATWithProxy: %v", err)
	}
	if !restricted {
		t.Error("CheckIfRestrictedNATWithProxy: expected a restricted result")
	}
}

func TestDetect3KindNATTypeStrict(t *testing.T) {
	t.Parallel()

	// An address-dependent mapping is enough to classify as strict, so the
	// filtering probe is never reached.
	primary := newMappingServers(t, mappedAddrA, mappedAddrB)

	natType, err := Detect3KindNATType(primary.addr(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if natType != NAT3Strict {
		t.Errorf("got %q, want %q", natType, NAT3Strict)
	}
}

func TestDetect3KindNATTypeOpen(t *testing.T) {
	t.Parallel()

	// Address-independent mapping, and the server's reply to the
	// change-request reaches us, so filtering is not port-dependent.
	other := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
		return bindingSuccess(req, mappedAddrA, nil)
	})
	primary := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
		return bindingSuccess(req, mappedAddrA, other.udpAddr())
	})

	natType, err := Detect3KindNATType(primary.addr(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if natType != NAT3Open {
		t.Errorf("got %q, want %q", natType, NAT3Open)
	}
}

func TestDetect3KindNATTypeModerate(t *testing.T) {
	t.Parallel()

	// The change-request reply is dropped, which the probe can only detect
	// by waiting out the full RoundTrip timeout.
	if testing.Short() {
		t.Skip("skipping: relies on the 10s RoundTrip timeout")
	}

	other := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
		return bindingSuccess(req, mappedAddrA, nil)
	})
	primary := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
		if isChangeRequest(req) {
			return nil // filtered by our NAT
		}
		return bindingSuccess(req, mappedAddrA, other.udpAddr())
	})

	natType, err := Detect3KindNATType(primary.addr(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if natType != NAT3Moderate {
		t.Errorf("got %q, want %q", natType, NAT3Moderate)
	}
}

func TestDetect3KindNATTypeUnknownOnError(t *testing.T) {
	t.Parallel()

	t.Run("mapping probe fails", func(t *testing.T) {
		t.Parallel()

		natType, err := Detect3KindNATType("no-such-host.invalid:3478", nil)
		if err == nil {
			t.Fatal("expected an error")
		}
		if natType != NATUnknown {
			t.Errorf("got %q, want %q", natType, NATUnknown)
		}
	})

	t.Run("filtering probe fails", func(t *testing.T) {
		t.Parallel()

		// The mapping probe succeeds, then the server stops answering, so
		// the filtering probe cannot get its first response either.
		other := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
			return bindingSuccess(req, mappedAddrA, nil)
		})
		var seen int
		primary := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
			seen++
			if seen > 1 {
				// Reply without XOR-MAPPED-ADDRESS so the filtering
				// probe fails immediately rather than timing out.
				return stun.MustBuild(stun.NewTransactionIDSetter(req.TransactionID), stun.BindingSuccess)
			}
			return bindingSuccess(req, mappedAddrA, other.udpAddr())
		})

		natType, err := Detect3KindNATType(primary.addr(), nil)
		if err == nil {
			t.Fatal("expected an error")
		}
		if natType != NATUnknown {
			t.Errorf("got %q, want %q", natType, NATUnknown)
		}
	})
}

func TestStunServerConnAddOtherAddr(t *testing.T) {
	t.Parallel()

	server := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
		return bindingSuccess(req, mappedAddrA, nil)
	})

	conn, err := connect(server.addr(), nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	if err := conn.AddOtherAddr("127.0.0.1:3478"); err != nil {
		t.Fatalf("AddOtherAddr: %v", err)
	}
	if conn.OtherAddr == nil || conn.OtherAddr.Port != 3478 {
		t.Errorf("OtherAddr was not set: %v", conn.OtherAddr)
	}

	if err := conn.AddOtherAddr("not an address"); err == nil {
		t.Error("expected an error for a malformed address")
	}
}

func TestStunServerConnRoundTrip(t *testing.T) {
	t.Parallel()

	server := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
		return bindingSuccess(req, mappedAddrA, nil)
	})

	conn, err := connect(server.addr(), nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	resp, err := conn.RoundTrip(message, conn.PrimaryAddr)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(resp); err != nil {
		t.Fatalf("decoding XOR-MAPPED-ADDRESS: %v", err)
	}
	if got, want := xorAddr.String(), mappedAddrA.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// Once the connection is closed, listen closes the message channel and
	// RoundTrip must report that rather than blocking until the timeout.
	conn.Close()
	done := make(chan error, 1)
	go func() {
		_, err := conn.RoundTrip(message, conn.PrimaryAddr)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("expected an error from RoundTrip on a closed connection")
		}
	case <-time.After(5 * time.Second):
		t.Error("RoundTrip did not return after the connection was closed")
	}
}

func TestConnectUnresolvableAddress(t *testing.T) {
	t.Parallel()

	if _, err := connect("no-such-host.invalid:3478", nil); err == nil {
		t.Fatal("expected an error for an unresolvable address")
	}
}

func TestListenClosesChannelOnUndecodableMessage(t *testing.T) {
	t.Parallel()

	// listen treats a packet it cannot decode as fatal and closes the
	// channel, which surfaces to the caller as a RoundTrip error.
	server := newFakeSTUNServer(t, func(req *stun.Message) *stun.Message {
		garbage := new(stun.Message)
		garbage.Raw = []byte{0x00}
		return garbage
	})

	conn, err := connect(server.addr(), nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.RoundTrip(message, conn.PrimaryAddr); err == nil {
		t.Error("expected an error after an undecodable response")
	}
}
