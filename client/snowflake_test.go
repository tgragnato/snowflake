package main

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	sf "tgragnato.it/snowflake/client/lib"
	"tgragnato.it/snowflake/common/event"
)

// The event logger is handed to the transport, so it has to accept any event
// without panicking, whatever the tor process does with the log line.
func TestPTEventLogger(t *testing.T) {
	t.Parallel()

	logger := NewPTEventLogger()
	if logger == nil {
		t.Fatal("NewPTEventLogger() = nil")
	}
	for _, e := range []event.SnowflakeEvent{
		event.EventOnSnowflakeConnected{},
		event.EventOnSnowflakeConnectionFailed{Error: io.EOF},
		event.EventOnBrokerRendezvous{},
	} {
		logger.OnNewSnowflakeEvent(e)
	}
}

// copyLoop shuttles bytes both ways between the SOCKS connection and the
// snowflake connection, and returns as soon as either direction is done.
func TestCopyLoop(t *testing.T) {
	t.Parallel()

	socksLocal, socksRemote := net.Pipe()
	sfLocal, sfRemote := net.Pipe()

	done := make(chan struct{})
	go func() {
		copyLoop(socksLocal, sfLocal)
		close(done)
	}()

	// From the snowflake towards SOCKS.
	go sfRemote.Write([]byte("downstream"))
	buf := make([]byte, len("downstream"))
	if _, err := io.ReadFull(socksRemote, buf); err != nil {
		t.Fatalf("reading downstream: %v", err)
	}
	if string(buf) != "downstream" {
		t.Errorf("downstream = %q, want %q", buf, "downstream")
	}

	// And back from SOCKS towards the snowflake.
	go socksRemote.Write([]byte("upstream"))
	buf = make([]byte, len("upstream"))
	if _, err := io.ReadFull(sfRemote, buf); err != nil {
		t.Fatalf("reading upstream: %v", err)
	}
	if string(buf) != "upstream" {
		t.Errorf("upstream = %q, want %q", buf, "upstream")
	}

	// Closing one side ends the loop, which is what lets the handler tear the
	// connection down.
	sfRemote.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("copyLoop did not return after one side closed")
	}
	socksLocal.Close()
	socksRemote.Close()
	sfLocal.Close()
}

// A closed listener ends the accept loop instead of spinning on errors.
func TestSocksAcceptLoopStopsOnClosedListener(t *testing.T) {
	t.Parallel()

	ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenSocks: %v", err)
	}
	ln.Close()

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		socksAcceptLoop(ln, sf.ClientConfig{}, make(chan struct{}), &wg)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("socksAcceptLoop did not return after the listener closed")
	}
	wg.Wait()
}

// A SOCKS client asking for an unusable configuration must be rejected rather
// than left hanging: here the "max" argument is not a number.
func TestSocksAcceptLoopRejectsBadArguments(t *testing.T) {
	t.Parallel()

	ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenSocks: %v", err)
	}

	var wg sync.WaitGroup
	shutdown := make(chan struct{})
	done := make(chan struct{})
	go func() {
		socksAcceptLoop(ln, sf.ClientConfig{BrokerURL: "https://broker.example.com"}, shutdown, &wg)
		close(done)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialing the SOCKS listener: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// SOCKS5 greeting with the username/password method, which is how tor
	// passes pluggable transport arguments.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("writing the SOCKS greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reading the SOCKS greeting reply: %v", err)
	}
	if reply[1] != 0x02 {
		t.Fatalf("SOCKS method = %#x, want username/password", reply[1])
	}

	// The arguments are carried in the username field, split across the
	// username and password if needed.
	username := "max=not-a-number"
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, 0x01, 0x00)
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("writing the SOCKS arguments: %v", err)
	}
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reading the SOCKS auth reply: %v", err)
	}

	// CONNECT to an arbitrary destination; the transport never dials it.
	host := "snowflake.example.com"
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	request = append(request, host...)
	request = append(request, 0x00, 0x50)
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("writing the SOCKS request: %v", err)
	}

	response := make([]byte, 10)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("reading the SOCKS response: %v", err)
	}
	if response[1] == 0x00 {
		t.Error("the SOCKS request was granted despite the invalid max argument")
	}

	ln.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("socksAcceptLoop did not return after the listener closed")
	}
	close(shutdown)
	wg.Wait()
}

// The listener reports the SOCKS version it speaks; tor is told about it in the
// CMETHOD line.
func TestSocksListenerVersion(t *testing.T) {
	t.Parallel()

	ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenSocks: %v", err)
	}
	defer ln.Close()

	if got := ln.Version(); !strings.Contains(got, "socks") {
		t.Errorf("Version() = %q, want a socks version", got)
	}
}
