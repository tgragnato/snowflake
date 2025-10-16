// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package net implements DTLS specific networking primitives.
package net

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func equalInt(t *testing.T, expected, actual int) {
	t.Helper()

	if expected != actual {
		t.Errorf("Expected %d got %d", expected, actual)
	}
}

func equalUDPAddr(t *testing.T, expected, actual net.Addr) {
	t.Helper()

	if expected == nil && actual == nil {
		return
	}
	if expected.String() != actual.String() {
		t.Errorf("Expected %v got %v", expected, actual)
	}
}

func equalBytes(t *testing.T, expected, actual []byte) {
	t.Helper()

	if !bytes.Equal(expected, actual) {
		t.Errorf("Expected %v got %v", expected, actual)
	}
}

func TestBuffer(t *testing.T) {
	buffer := NewPacketBuffer()
	packet := make([]byte, 4)
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		t.Fatal(err)
	}

	// Write once.
	n, err := buffer.WriteTo([]byte{0, 1}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 2, n)

	// Read once.
	var raddr net.Addr
	if n, raddr, err = buffer.ReadFrom(packet); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 2, n)
	equalBytes(t, []byte{0, 1}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Read deadline.
	if err = buffer.SetReadDeadline(time.Unix(0, 1)); err != nil {
		t.Fatal(err)
	}
	n, raddr, err = buffer.ReadFrom(packet)
	if !errors.Is(ErrTimeout, err) {
		t.Fatalf("Unexpected err %v wanted ErrTimeout", err)
	}
	equalInt(t, 0, n)
	equalUDPAddr(t, nil, raddr)

	// Reset deadline.
	if err = buffer.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	// Write twice.
	if n, err = buffer.WriteTo([]byte{2, 3, 4}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)

	if n, err = buffer.WriteTo([]byte{5, 6, 7}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)

	// Read twice.
	if n, raddr, err = buffer.ReadFrom(packet); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)
	equalBytes(t, []byte{2, 3, 4}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	if n, raddr, err = buffer.ReadFrom(packet); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)
	equalBytes(t, []byte{5, 6, 7}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Write once prior to close.
	if _, err = buffer.WriteTo([]byte{3}, addr); err != nil {
		t.Fatal(err)
	}

	// Close.
	if err = buffer.Close(); err != nil {
		t.Fatal(err)
	}

	// Future writes will error.
	if _, err = buffer.WriteTo([]byte{4}, addr); err == nil {
		t.Fatal("Expected error")
	}

	// But we can read the remaining data.
	if n, raddr, err = buffer.ReadFrom(packet); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 1, n)
	equalBytes(t, []byte{3}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Until EOF.
	if _, _, err = buffer.ReadFrom(packet); !errors.Is(err, io.EOF) {
		t.Fatalf("Unexpected err %v wanted io.EOF", err)
	}
}

func TestShortBuffer(t *testing.T) {
	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		t.Fatal(err)
	}

	// Write once.
	n, err := buffer.WriteTo([]byte{0, 1, 2, 3}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 4, n)

	// Try to read with a short buffer.
	packet := make([]byte, 3)
	var raddr net.Addr
	n, raddr, err = buffer.ReadFrom(packet)
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Unexpected err %v wanted io.ErrShortBuffer", err)
	}
	equalUDPAddr(t, nil, raddr)
	equalInt(t, 0, n)

	// Close.
	if err = buffer.Close(); err != nil {
		t.Fatal(err)
	}

	// Make sure you can Close twice.
	if err = buffer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestResizeWraparound(t *testing.T) {
	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		t.Fatal(err)
	}

	n, err := buffer.WriteTo([]byte{1}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 1, n)

	// Trigger resize from 1 -> 2.
	n, err = buffer.WriteTo([]byte{2}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 1, n)

	// Read once to ensure the read index is non-zero when the next resize
	// happens.
	dst := make([]byte, 1)
	n, _, err = buffer.ReadFrom(dst)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 1, n)
	equalBytes(t, []byte{1}, dst[:n])

	// Trigger resize from 2 -> 4.
	n, err = buffer.WriteTo([]byte{3}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 1, n)

	// Write another packet after resizing to ensure we retain buffered packets
	// before and after the resize.
	n, err = buffer.WriteTo([]byte{4}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 1, n)

	// Read out all buffered packets. They should 1) all be readable from the
	// buffer and 2) be read in order.
	for i := 2; i < 5; i++ {
		n, _, err = buffer.ReadFrom(dst)
		if err != nil {
			t.Fatal(err)
		}
		equalInt(t, 1, n)
		equalBytes(t, []byte{byte(i)}, dst[:n])
	}
}

func TestWraparound(t *testing.T) {
	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		t.Fatal(err)
	}

	// Write multiple.
	n, err := buffer.WriteTo([]byte{0, 1, 2, 3}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 4, n)

	if n, err = buffer.WriteTo([]byte{4, 5}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 2, n)

	if n, err = buffer.WriteTo([]byte{6, 7, 8}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)

	// Verify underlying buffer length.
	// Packet 1: buffer does not grow.
	// Packet 2: buffer doubles from 1 to 2.
	// Packet 3: buffer doubles from 2 to 4.
	equalInt(t, 4, len(buffer.packets))

	// Read once.
	packet := make([]byte, 4)
	var raddr net.Addr
	if n, raddr, err = buffer.ReadFrom(packet); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 4, n)
	equalBytes(t, []byte{0, 1, 2, 3}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Write again.
	if n, err = buffer.WriteTo([]byte{9, 10, 11}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)

	// Verify underlying buffer length.
	// No change in buffer size.
	equalInt(t, 4, len(buffer.packets))

	// Write again and verify buffer grew.
	if n, err = buffer.WriteTo([]byte{12, 13, 14, 15, 16, 17, 18, 19}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 8, n)
	equalInt(t, 4, len(buffer.packets))

	// Close.
	if err = buffer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBufferAsync(t *testing.T) {
	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		t.Fatal(err)
	}

	// Start up a goroutine to start a blocking read.
	done := make(chan string)
	go func() {
		packet := make([]byte, 4)

		n, raddr, rErr := buffer.ReadFrom(packet)
		if rErr != nil {
			done <- rErr.Error()

			return
		}

		equalInt(t, 2, n)
		equalBytes(t, []byte{0, 1}, packet[:n])
		equalUDPAddr(t, addr, raddr)

		_, _, readErr := buffer.ReadFrom(packet)
		if !errors.Is(readErr, io.EOF) {
			done <- fmt.Sprintf("Unexpected err %v wanted io.EOF", readErr)
		} else {
			close(done)
		}
	}()

	// Wait for the reader to start reading.
	time.Sleep(time.Millisecond)

	// Write once
	n, err := buffer.WriteTo([]byte{0, 1}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 2, n)

	// Wait for the reader to start reading again.
	time.Sleep(time.Millisecond)

	// Close will unblock the reader.
	if err = buffer.Close(); err != nil {
		t.Fatal(err)
	}

	if routineFail, ok := <-done; ok {
		t.Fatal(routineFail)
	}
}

func benchmarkBufferWR(b *testing.B, size int64, write bool, grow int) {
	b.Helper()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		b.Fatalf("net.ResolveUDPAddr: %v", err)
	}
	buffer := NewPacketBuffer()
	packet := make([]byte, size)

	// Grow the buffer first
	pad := make([]byte, 1022)
	for len(buffer.packets) < grow {
		if _, err := buffer.WriteTo(pad, addr); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}
	for buffer.read != buffer.write {
		if _, _, err := buffer.ReadFrom(pad); err != nil {
			b.Fatalf("ReadFrom: %v", err)
		}
	}

	if write {
		if _, err := buffer.WriteTo(packet, addr); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}

	b.SetBytes(size)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := buffer.WriteTo(packet, addr); err != nil {
			b.Fatalf("Write: %v", err)
		}
		if _, _, err := buffer.ReadFrom(packet); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}
}

// In this benchmark, the buffer is often empty, which is hopefully
// typical of real usage.
func BenchmarkBufferWR14(b *testing.B) {
	benchmarkBufferWR(b, 14, false, 128)
}

func BenchmarkBufferWR140(b *testing.B) {
	benchmarkBufferWR(b, 140, false, 128)
}

func BenchmarkBufferWR1400(b *testing.B) {
	benchmarkBufferWR(b, 1400, false, 128)
}

// Here, the buffer never becomes empty, which forces wraparound.
func BenchmarkBufferWWR14(b *testing.B) {
	benchmarkBufferWR(b, 14, true, 128)
}

func BenchmarkBufferWWR140(b *testing.B) {
	benchmarkBufferWR(b, 140, true, 128)
}

func BenchmarkBufferWWR1400(b *testing.B) {
	benchmarkBufferWR(b, 1400, true, 128)
}

func benchmarkBuffer(b *testing.B, size int64) {
	b.Helper()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		b.Fatalf("net.ResolveUDPAddr: %v", err)
	}
	buffer := NewPacketBuffer()
	b.SetBytes(size)

	done := make(chan struct{})
	go func() {
		packet := make([]byte, size)

		for {
			_, _, err := buffer.ReadFrom(packet)
			if errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				b.Error(err)

				break
			}
		}

		close(done)
	}()

	packet := make([]byte, size)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var err error
		for {
			_, err = buffer.WriteTo(packet, addr)
			if !errors.Is(err, bytes.ErrTooLarge) {
				break
			}
			time.Sleep(time.Microsecond)
		}
		if err != nil {
			b.Fatal(err)
		}
	}

	if err := buffer.Close(); err != nil {
		b.Fatal(err)
	}

	<-done
}

func BenchmarkBuffer14(b *testing.B) {
	benchmarkBuffer(b, 14)
}

func BenchmarkBuffer140(b *testing.B) {
	benchmarkBuffer(b, 140)
}

func BenchmarkBuffer1400(b *testing.B) {
	benchmarkBuffer(b, 1400)
}

func FuzzPacketBuffer_WriteReadRoundTrip(f *testing.F) {
	// mixed seeds.
	f.Add([]byte{0, 1, 2}, []byte{3, 4}, uint16(2))
	f.Add([]byte{}, []byte{9, 9, 9}, uint16(0))
	f.Add([]byte{7}, []byte{}, uint16(1))
	f.Add(make([]byte, 64), make([]byte, 5), uint16(4))

	f.Fuzz(func(t *testing.T, p1 []byte, p2 []byte, readCap uint16) {
		buf := NewPacketBuffer()
		defer func() { _ = buf.Close() }()

		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5684}

		n, err := buf.WriteTo(p1, addr)
		if err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
		if n != len(p1) {
			t.Fatalf("Expected %d bytes written, got %d", len(p1), n)
		}

		n, err = buf.WriteTo(p2, addr)
		if err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
		if n != len(p2) {
			t.Fatalf("Expected %d bytes written, got %d", len(p2), n)
		}

		readOnce := func(expect []byte) {
			rb := make([]byte, int(readCap))
			n, raddr, errRead := buf.ReadFrom(rb)

			if len(expect) == 0 {
				if len(rb) == 0 {
					if errRead != nil {
						t.Fatalf("ReadFrom returned error: %v", errRead)
					}
					if n != 0 {
						t.Fatalf("Expected 0 bytes read, got %d", n)
					}
					if raddr == nil {
						t.Fatalf("Expected non-nil remote addr")
					}
					if raddr.String() != addr.String() {
						t.Fatalf("Expected addr %v got %v", addr.String(), raddr.String())
					}
				} else {
					if !errors.Is(errRead, io.EOF) {
						t.Fatalf("Unexpected err %v wanted io.EOF", errRead)
					}
					if n != 0 {
						t.Fatalf("Expected 0 bytes read, got %d", n)
					}
				}

				return
			}

			if errors.Is(errRead, io.ErrShortBuffer) {
				rb = make([]byte, len(expect))
				n, raddr, errRead = buf.ReadFrom(rb)
			}

			if errRead != nil {
				t.Fatalf("ReadFrom returned error: %v", errRead)
			}
			if n != len(expect) {
				t.Fatalf("Expected %d bytes read, got %d", len(expect), n)
			}
			if !bytes.Equal(expect, rb[:n]) {
				t.Fatalf("Expected %v got %v", expect, rb[:n])
			}
			if raddr == nil {
				t.Fatalf("Expected non-nil remote addr")
			}
			if raddr.String() != addr.String() {
				t.Fatalf("Expected addr %v got %v", addr.String(), raddr.String())
			}
		}

		readOnce(p1)
		readOnce(p2)

		if err := buf.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		_, err = buf.WriteTo([]byte{1}, addr)
		if err == nil {
			t.Fatalf("Expected error from WriteTo after Close")
		}

		rb := make([]byte, int(readCap))
		_, _, err = buf.ReadFrom(rb)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Unexpected err %v wanted io.EOF", err)
		}
	})
}

func FuzzPacketBuffer_DeadlineAndShortBuffer(f *testing.F) {
	// mixed seeds.
	f.Add([]byte{1, 2, 3, 4}, uint16(2))
	f.Add([]byte{}, uint16(0))
	f.Add(make([]byte, 32), uint16(0))

	f.Fuzz(func(t *testing.T, payload []byte, readCap uint16) {
		buf := NewPacketBuffer()
		defer func() { _ = buf.Close() }()

		if err := buf.SetReadDeadline(time.Unix(0, 1)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		rb := make([]byte, int(readCap))
		n, addr, err := buf.ReadFrom(rb)
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("Unexpected err %v wanted ErrTimeout", err)
		}
		if n != 0 {
			t.Fatalf("Expected 0 got %d", n)
		}
		if addr != nil {
			t.Fatalf("Expected nil addr got %v", addr)
		}

		if err := buf.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}

		ua := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
		n, err = buf.WriteTo(payload, ua)
		if err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
		if n != len(payload) {
			t.Fatalf("Expected %d bytes written, got %d", len(payload), n)
		}

		n, addr, err = buf.ReadFrom(rb)
		if errors.Is(err, io.ErrShortBuffer) {
			rb = make([]byte, len(payload))
			n, addr, err = buf.ReadFrom(rb)
		}

		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		if n != len(payload) {
			t.Fatalf("Expected %d bytes read, got %d", len(payload), n)
		}
		if !bytes.Equal(payload, rb[:n]) {
			t.Fatalf("Expected %v got %v", payload, rb[:n])
		}

		if addr == nil {
			t.Fatalf("Expected non-nil remote addr")
		}
		if addr.String() != ua.String() {
			t.Fatalf("Expected addr %v got %v", ua.String(), addr.String())
		}
	})
}

func FuzzPacketBuffer_CloseSemantics(f *testing.F) {
	f.Add([]byte{0, 1}, []byte{2, 3, 4})
	f.Add([]byte{}, []byte{9})
	f.Add(make([]byte, 8), make([]byte, 0))

	f.Fuzz(func(t *testing.T, first []byte, second []byte) {
		buf := NewPacketBuffer()
		addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4242}

		if _, err := buf.WriteTo(first, addr); err != nil {
			t.Fatalf("WriteTo(first): %v", err)
		}
		if _, err := buf.WriteTo(second, addr); err != nil {
			t.Fatalf("WriteTo(second): %v", err)
		}

		if err := buf.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		readAll := func(expect []byte) {
			rb := make([]byte, len(expect))
			n, raddr, errRead := buf.ReadFrom(rb)
			if errRead != nil {
				t.Fatalf("ReadFrom: %v", errRead)
			}
			if n != len(expect) {
				t.Fatalf("Expected %d bytes read, got %d", len(expect), n)
			}
			if !bytes.Equal(expect, rb[:n]) {
				t.Fatalf("Expected %v got %v", expect, rb[:n])
			}
			if raddr == nil {
				t.Fatalf("Expected non-nil remote addr")
			}
		}

		readAll(first)
		readAll(second)

		if _, _, err := buf.ReadFrom(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("Unexpected err %v wanted io.EOF", err)
		}

		if _, err := buf.WriteTo([]byte{1}, addr); err == nil {
			t.Fatalf("Expected error from WriteTo after Close")
		}
	})
}
