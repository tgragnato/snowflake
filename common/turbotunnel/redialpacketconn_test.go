package turbotunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubAddr is a minimal net.Addr for the static local and remote addresses.
type stubAddr struct{ name string }

func (a stubAddr) Network() string { return "stub" }
func (a stubAddr) String() string  { return a.name }

var (
	testLocalAddr  = stubAddr{"local"}
	testRemoteAddr = stubAddr{"remote"}
)

// fakePacketConn is an in-memory net.PacketConn standing in for one of the
// transient connections a RedialPacketConn dials.
type fakePacketConn struct {
	incoming chan []byte // packets to hand to ReadFrom
	outgoing chan []byte // packets received from WriteTo

	mu       sync.Mutex
	readErr  error
	writeErr error
	closed   bool
	done     chan struct{}
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{
		incoming: make(chan []byte, 16),
		outgoing: make(chan []byte, 16),
		done:     make(chan struct{}),
	}
}

func (c *fakePacketConn) failReads(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.readErr = err
}

func (c *fakePacketConn) failWrites(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.writeErr = err
}

func (c *fakePacketConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.closed
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	err := c.readErr
	c.mu.Unlock()
	if err != nil {
		return 0, nil, err
	}

	select {
	case packet := <-c.incoming:
		return copy(p, packet), stubAddr{"peer"}, nil
	case <-c.done:
		return 0, nil, errors.New("closed")
	}
}

func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	err := c.writeErr
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}

	packet := append([]byte(nil), p...)
	select {
	case c.outgoing <- packet:
		return len(p), nil
	case <-c.done:
		return 0, errors.New("closed")
	}
}

func (c *fakePacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.closed {
		c.closed = true
		close(c.done)
	}
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr                { return testLocalAddr }
func (c *fakePacketConn) SetDeadline(t time.Time) error      { return errNotImplemented }
func (c *fakePacketConn) SetReadDeadline(t time.Time) error  { return errNotImplemented }
func (c *fakePacketConn) SetWriteDeadline(t time.Time) error { return errNotImplemented }

// recv reads one packet from ch, failing the test if none arrives.
func recv(t *testing.T, ch <-chan []byte, what string) []byte {
	t.Helper()

	select {
	case p := <-ch:
		return p
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

func TestRedialPacketConnAddrs(t *testing.T) {
	t.Parallel()

	conn := NewRedialPacketConn(testLocalAddr, testRemoteAddr, func(context.Context) (net.PacketConn, error) {
		return newFakePacketConn(), nil
	})
	defer conn.Close()

	if got := conn.LocalAddr(); got != net.Addr(testLocalAddr) {
		t.Errorf("LocalAddr: got %v, want %v", got, testLocalAddr)
	}
}

func TestRedialPacketConnDeadlinesAreNotImplemented(t *testing.T) {
	t.Parallel()

	conn := NewRedialPacketConn(testLocalAddr, testRemoteAddr, func(context.Context) (net.PacketConn, error) {
		return newFakePacketConn(), nil
	})
	defer conn.Close()

	deadline := time.Now().Add(time.Minute)
	for name, err := range map[string]error{
		"SetDeadline":      conn.SetDeadline(deadline),
		"SetReadDeadline":  conn.SetReadDeadline(deadline),
		"SetWriteDeadline": conn.SetWriteDeadline(deadline),
	} {
		if !errors.Is(err, errNotImplemented) {
			t.Errorf("%s: got %v, want errNotImplemented", name, err)
		}
	}
}

func TestRedialPacketConnWriteTo(t *testing.T) {
	t.Parallel()

	dialed := newFakePacketConn()
	conn := NewRedialPacketConn(testLocalAddr, testRemoteAddr, func(context.Context) (net.PacketConn, error) {
		return dialed, nil
	})
	defer conn.Close()

	packet := []byte("a kcp segment")
	// The addr argument is ignored: the redial conn always writes to its own
	// static remote address.
	n, err := conn.WriteTo(packet, stubAddr{"ignored"})
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(packet) {
		t.Errorf("wrote %d bytes, want %d", n, len(packet))
	}

	if got := recv(t, dialed.outgoing, "the written packet"); string(got) != string(packet) {
		t.Errorf("got %q, want %q", got, packet)
	}
}

func TestRedialPacketConnReadFrom(t *testing.T) {
	t.Parallel()

	dialed := newFakePacketConn()
	conn := NewRedialPacketConn(testLocalAddr, testRemoteAddr, func(context.Context) (net.PacketConn, error) {
		return dialed, nil
	})
	defer conn.Close()

	packet := []byte("an incoming kcp segment")
	dialed.incoming <- packet

	buf := make([]byte, 1500)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(packet) {
		t.Errorf("got %q, want %q", buf[:n], packet)
	}
	// The transient connection's peer address is replaced with the static
	// one, so the session is not disturbed by a change of proxy.
	if addr != net.Addr(testRemoteAddr) {
		t.Errorf("got address %v, want %v", addr, testRemoteAddr)
	}
}

// A read error on the current connection must be invisible to the caller: the
// point of RedialPacketConn is that the KCP session survives a proxy going
// away, and only a dial failure is fatal.
func TestRedialPacketConnRedialsAfterReadError(t *testing.T) {
	t.Parallel()

	first := newFakePacketConn()
	first.failReads(errors.New("proxy went away"))
	second := newFakePacketConn()

	var dials atomic.Int32
	conn := NewRedialPacketConn(testLocalAddr, testRemoteAddr, func(context.Context) (net.PacketConn, error) {
		if dials.Add(1) == 1 {
			return first, nil
		}
		return second, nil
	})
	defer conn.Close()

	// Traffic flows again over the replacement connection.
	packet := []byte("after the redial")
	second.incoming <- packet

	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(packet) {
		t.Errorf("got %q, want %q", buf[:n], packet)
	}

	if got := dials.Load(); got < 2 {
		t.Errorf("dialed %d times, want at least 2", got)
	}
	// The abandoned connection must be released, not leaked.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if first.isClosed() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Error("the abandoned connection was not closed")
}

func TestRedialPacketConnRedialsAfterWriteError(t *testing.T) {
	t.Parallel()

	first := newFakePacketConn()
	first.failWrites(errors.New("proxy went away"))
	second := newFakePacketConn()

	var dials atomic.Int32
	conn := NewRedialPacketConn(testLocalAddr, testRemoteAddr, func(context.Context) (net.PacketConn, error) {
		if dials.Add(1) == 1 {
			return first, nil
		}
		return second, nil
	})
	defer conn.Close()

	// Keep writing until a packet makes it onto the replacement connection.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			conn.WriteTo([]byte("retry"), nil)
			time.Sleep(time.Millisecond)
		}
	}()

	if got := recv(t, second.outgoing, "a packet on the replacement connection"); string(got) != "retry" {
		t.Errorf("got %q, want %q", got, "retry")
	}
}

// A dial failure is the one error the caller has to see: there is no way to
// recover the session without a connection.
func TestRedialPacketConnDialErrorIsFatal(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("no proxies available")
	conn := NewRedialPacketConn(testLocalAddr, testRemoteAddr, func(context.Context) (net.PacketConn, error) {
		return nil, wantErr
	})

	// ReadFrom blocks until the dial loop reports the failure.
	buf := make([]byte, 1500)
	if _, _, err := conn.ReadFrom(buf); !errors.Is(err, wantErr) {
		t.Errorf("ReadFrom: got %v, want %v", err, wantErr)
	}
	if _, err := conn.WriteTo([]byte("x"), nil); !errors.Is(err, wantErr) {
		t.Errorf("WriteTo: got %v, want %v", err, wantErr)
	}

	// The reported error is wrapped in an OpError describing the operation.
	_, _, err := conn.ReadFrom(buf)
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("expected a *net.OpError, got %T", err)
	}
	if opErr.Op != "read" {
		t.Errorf("Op: got %q, want \"read\"", opErr.Op)
	}
}

func TestRedialPacketConnClose(t *testing.T) {
	t.Parallel()

	conn := NewRedialPacketConn(testLocalAddr, testRemoteAddr, func(context.Context) (net.PacketConn, error) {
		return newFakePacketConn(), nil
	})

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After closing, both directions fail with an OpError naming the
	// operation. Note that Close builds its own "operation on closed
	// connection" error rather than reusing errClosedPacketConn, so callers
	// cannot match it with errors.Is the way they can for a QueuePacketConn.
	for _, test := range []struct {
		wantOp string
		err    error
	}{
		{"read", func() error { _, _, err := conn.ReadFrom(make([]byte, 16)); return err }()},
		{"write", func() error { _, err := conn.WriteTo([]byte("x"), nil); return err }()},
	} {
		var opErr *net.OpError
		if !errors.As(test.err, &opErr) {
			t.Errorf("%s: expected a *net.OpError, got %T (%v)", test.wantOp, test.err, test.err)
			continue
		}
		if opErr.Op != test.wantOp {
			t.Errorf("Op: got %q, want %q", opErr.Op, test.wantOp)
		}
		if opErr.Err == nil || opErr.Err.Error() != "operation on closed connection" {
			t.Errorf("%s: got underlying error %v, want \"operation on closed connection\"", test.wantOp, opErr.Err)
		}
	}

	// A second Close reports that it was already closed.
	if err := conn.Close(); err == nil {
		t.Error("expected an error from the second Close")
	}
}

// Close must unblock a reader that is waiting for a packet, rather than
// leaving the goroutine parked forever.
func TestRedialPacketConnCloseUnblocksReader(t *testing.T) {
	t.Parallel()

	conn := NewRedialPacketConn(testLocalAddr, testRemoteAddr, func(context.Context) (net.PacketConn, error) {
		return newFakePacketConn(), nil
	})

	errCh := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(make([]byte, 16))
		errCh <- err
	}()

	// Give the reader a moment to park on the empty queue.
	time.Sleep(50 * time.Millisecond)
	conn.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("expected an error after Close")
		}
	case <-time.After(5 * time.Second):
		t.Error("Close did not unblock the pending read")
	}
}

// The send queue is bounded and lossy on purpose: KCP retransmits, so dropping
// a packet is preferable to blocking the writer.
func TestRedialPacketConnWriteToDropsWhenQueueIsFull(t *testing.T) {
	t.Parallel()

	// Never finish dialing, so nothing drains the send queue.
	blocked := make(chan struct{})
	conn := NewRedialPacketConn(testLocalAddr, testRemoteAddr, func(ctx context.Context) (net.PacketConn, error) {
		<-blocked
		return nil, errors.New("stopped")
	})
	defer close(blocked)
	defer conn.Close()

	packet := []byte("x")
	for i := range queueSize * 2 {
		n, err := conn.WriteTo(packet, nil)
		if err != nil {
			t.Fatalf("write %d: unexpected error: %v", i, err)
		}
		// Even a dropped packet is reported as fully written.
		if n != len(packet) {
			t.Fatalf("write %d: wrote %d bytes, want %d", i, n, len(packet))
		}
	}
}
