package snowflake_proxy

import (
	"io"
	"testing"
	"time"
)

// newTestWebRTCConn builds a webRTCConn without any WebRTC peer behind it. The
// data channel being nil exercises the path where the client has gone away,
// which Write must tolerate rather than panic on.
func newTestWebRTCConn(t *testing.T) (*webRTCConn, *io.PipeWriter, *stubBytesLogger) {
	t.Helper()

	pr, pw := io.Pipe()
	logger := &stubBytesLogger{}
	conn := newWebRTCConn(nil, nil, pr, logger)
	t.Cleanup(func() {
		// Close would dereference the nil peer connection, so stop the
		// timeout goroutine directly.
		conn.cancelTimeoutLoop()
		pw.Close()
	})
	return conn, pw, logger
}

func TestWebRTCConnDeadlinesAreNotImplemented(t *testing.T) {
	t.Parallel()

	conn, _, _ := newTestWebRTCConn(t)

	deadline := time.Now().Add(time.Minute)
	for name, err := range map[string]error{
		"SetDeadline":      conn.SetDeadline(deadline),
		"SetReadDeadline":  conn.SetReadDeadline(deadline),
		"SetWriteDeadline": conn.SetWriteDeadline(deadline),
	} {
		if err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

// The connection has no meaningful local address to report: callers rely on
// this being nil rather than a placeholder that could leak into a log.
func TestWebRTCConnLocalAddrIsNil(t *testing.T) {
	t.Parallel()

	conn, _, _ := newTestWebRTCConn(t)

	if addr := conn.LocalAddr(); addr != nil {
		t.Errorf("got %v, want nil", addr)
	}
}

func TestWebRTCConnRead(t *testing.T) {
	t.Parallel()

	conn, pw, _ := newTestWebRTCConn(t)

	want := []byte("relayed payload")
	go func() {
		pw.Write(want)
		pw.Close()
	}()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Write accounts the payload as inbound traffic (inbound from the relay,
// heading to the client) even when there is no data channel to send it on.
func TestWebRTCConnWriteCountsInboundTraffic(t *testing.T) {
	t.Parallel()

	conn, _, logger := newTestWebRTCConn(t)

	payload := []byte("twelve bytes")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("writing: %v", err)
	}
	if n != len(payload) {
		t.Errorf("wrote %d bytes, want %d", n, len(payload))
	}
	if got := logger.inbound(); got != int64(len(payload)) {
		t.Errorf("logged %d inbound bytes, want %d", got, len(payload))
	}
}

// Every write counts as activity, which is what keeps the inactivity timeout
// from closing a busy connection.
func TestWebRTCConnWriteSignalsActivity(t *testing.T) {
	t.Parallel()

	conn, _, _ := newTestWebRTCConn(t)

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("writing: %v", err)
	}

	select {
	case <-conn.activity:
	case <-time.After(5 * time.Second):
		t.Error("a write did not signal activity")
	}
}

// The activity channel is lossy on purpose: a burst of writes must never block
// on a full channel, because that would stall the relay copy loop.
func TestWebRTCConnWriteDoesNotBlockOnActivityBacklog(t *testing.T) {
	t.Parallel()

	conn, _, logger := newTestWebRTCConn(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// More writes than the activity channel can buffer.
		for range cap(conn.activity) * 2 {
			conn.Write([]byte("x"))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("writes blocked once the activity channel filled up")
	}

	if got, want := logger.inbound(), int64(cap(conn.activity)*2); got != want {
		t.Errorf("logged %d inbound bytes, want %d", got, want)
	}
}

func TestWebRTCConnDefaultInactivityTimeout(t *testing.T) {
	t.Parallel()

	conn, _, _ := newTestWebRTCConn(t)

	// The timeout is what eventually reclaims a connection whose client
	// vanished without closing the data channel.
	if got, want := conn.inactivityTimeout, 30*time.Second; got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Note: the inactivity timeout firing, and Close, are not covered here. Both
// call PeerConnection.Close, so they need a real WebRTC peer rather than the
// nil placeholder these tests use.
