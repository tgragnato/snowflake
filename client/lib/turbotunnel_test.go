package snowflake_client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"tgragnato.it/snowflake/common/encapsulation"
)

// pipeReadWriteCloser adapts a pair of pipes into the io.ReadWriteCloser that
// encapsulationPacketConn wraps, standing in for a WebRTC data channel.
type pipeReadWriteCloser struct {
	io.Reader
	io.WriteCloser
}

func (p pipeReadWriteCloser) Close() error { return p.WriteCloser.Close() }

func newTestPacketConn(t *testing.T) (*encapsulationPacketConn, *bytes.Buffer, *io.PipeWriter) {
	t.Helper()

	// Reads come from a pipe the test writes into; writes land in a buffer
	// the test inspects.
	pr, pw := io.Pipe()
	var written bytes.Buffer
	conn := newEncapsulationPacketConn(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2},
		pipeReadWriteCloser{Reader: pr, WriteCloser: nopWriteCloser{&written}},
	)
	t.Cleanup(func() { pw.Close() })
	return conn, &written, pw
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func TestEncapsulationPacketConnAddrs(t *testing.T) {
	t.Parallel()

	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
	conn := newEncapsulationPacketConn(local, remote, pipeReadWriteCloser{
		Reader:      bytes.NewReader(nil),
		WriteCloser: nopWriteCloser{io.Discard},
	})

	if got := conn.LocalAddr(); got != local {
		t.Errorf("LocalAddr: got %v, want %v", got, local)
	}
}

func TestEncapsulationPacketConnDeadlinesAreNotImplemented(t *testing.T) {
	t.Parallel()

	conn, _, _ := newTestPacketConn(t)

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

func TestEncapsulationPacketConnWriteTo(t *testing.T) {
	t.Parallel()

	conn, written, _ := newTestPacketConn(t)

	packet := []byte("a turbotunnel packet")
	// WriteTo ignores the address argument by design: the stream already
	// determines the peer.
	n, err := conn.WriteTo(packet, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 9})
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(packet) {
		t.Errorf("wrote %d bytes, want %d", n, len(packet))
	}

	// The payload must be on the wire in encapsulated form, and readable
	// back through the same encoding.
	got := make([]byte, len(packet))
	readBack, err := encapsulation.ReadData(bytes.NewReader(written.Bytes()), got)
	if err != nil {
		t.Fatalf("reading back the encapsulated packet: %v", err)
	}
	if !bytes.Equal(got[:readBack], packet) {
		t.Errorf("got %q, want %q", got[:readBack], packet)
	}
}

// WriteTo must flush, otherwise a packet could sit in the buffered writer
// while the peer waits for it.
func TestEncapsulationPacketConnWriteToFlushes(t *testing.T) {
	t.Parallel()

	conn, written, _ := newTestPacketConn(t)

	if _, err := conn.WriteTo([]byte("x"), nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if written.Len() == 0 {
		t.Error("WriteTo did not flush the packet to the underlying stream")
	}
}

func TestEncapsulationPacketConnWriteToError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("stream broken")
	conn := newEncapsulationPacketConn(nil, nil, pipeReadWriteCloser{
		Reader:      bytes.NewReader(nil),
		WriteCloser: nopWriteCloser{errWriter{wantErr}},
	})

	n, err := conn.WriteTo([]byte("x"), nil)
	if err == nil {
		t.Fatal("expected an error from a failing stream")
	}
	if n != 0 {
		t.Errorf("wrote %d bytes on error, want 0", n)
	}
}

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

func TestEncapsulationPacketConnReadFrom(t *testing.T) {
	t.Parallel()

	conn, _, pw := newTestPacketConn(t)

	packet := []byte("an incoming packet")
	go func() {
		encapsulation.WriteData(pw, packet)
		pw.Close()
	}()

	buf := make([]byte, len(packet))
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], packet) {
		t.Errorf("got %q, want %q", buf[:n], packet)
	}
	// Every packet is attributed to the single static remote address.
	if addr == nil || addr.String() != "127.0.0.1:2" {
		t.Errorf("got address %v, want 127.0.0.1:2", addr)
	}
}

// A packet larger than the caller's buffer is truncated rather than reported
// as an error, matching how a UDP socket behaves.
func TestEncapsulationPacketConnReadFromShortBuffer(t *testing.T) {
	t.Parallel()

	conn, _, pw := newTestPacketConn(t)

	packet := []byte("a packet that will not fit")
	go func() {
		encapsulation.WriteData(pw, packet)
		pw.Close()
	}()

	buf := make([]byte, 4)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: expected no error on a short buffer, got %v", err)
	}
	if n != len(buf) {
		t.Errorf("read %d bytes, want %d", n, len(buf))
	}
	if !bytes.Equal(buf, packet[:len(buf)]) {
		t.Errorf("got %q, want %q", buf, packet[:len(buf)])
	}
}

func TestEncapsulationPacketConnReadFromClosedStream(t *testing.T) {
	t.Parallel()

	conn, _, pw := newTestPacketConn(t)
	pw.Close()

	if _, _, err := conn.ReadFrom(make([]byte, 16)); err == nil {
		t.Error("expected an error once the stream is closed")
	}
}

func TestEncapsulationPacketConnRoundTrip(t *testing.T) {
	t.Parallel()

	// Wire the conn's write side into its own read side, so packets written
	// come back out, exercising both encodings against each other.
	pr, pw := io.Pipe()
	conn := newEncapsulationPacketConn(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2},
		pipeReadWriteCloser{Reader: pr, WriteCloser: pw},
	)
	defer conn.Close()

	packets := [][]byte{
		[]byte("first"),
		{},
		[]byte("third, a bit longer than the first"),
	}

	go func() {
		for _, p := range packets {
			if _, err := conn.WriteTo(p, nil); err != nil {
				return
			}
		}
	}()

	for i, want := range packets {
		buf := make([]byte, 1500)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("packet %d: ReadFrom: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Errorf("packet %d: got %q, want %q", i, buf[:n], want)
		}
	}
}
