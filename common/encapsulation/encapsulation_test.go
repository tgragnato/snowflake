package encapsulation

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand/v2"
	"testing"
)

// Return a byte slice with cryptographically secure random contents.
func pseudorandomBuffer(n int) []byte {
	p := make([]byte, n)
	_, err := rand.Read(p)
	if err != nil {
		for i := 0; i < len(p); i++ {
			p[i] = byte(mrand.Int64() & 0xff)
		}
	}
	return p
}

func mustWriteData(w io.Writer, p []byte) int {
	n, err := WriteData(w, p)
	if err != nil {
		panic(err)
	}
	return n
}

func mustWritePadding(w io.Writer, n int) int {
	n, err := WritePadding(w, n)
	if err != nil {
		panic(err)
	}
	return n
}

// Test that ReadData(WriteData()) recovers the original data.
func TestRoundtrip(t *testing.T) {
	t.Parallel()

	// Test above and below interesting thresholds.
	for _, i := range []int{
		0x00, 0x01,
		0x3e, 0x3f, 0x40, 0x41,
		0xfe, 0xff, 0x100, 0x101,
		0x1ffe, 0x1fff, 0x2000, 0x2001,
		0xfffe, 0xffff, 0x10000, 0x10001,
		0xffffe, 0xfffff,
	} {
		original := pseudorandomBuffer(i)
		var enc bytes.Buffer
		n, err := WriteData(&enc, original)
		if err != nil {
			t.Fatalf("size %d, WriteData returned error %v", i, err)
		}
		if enc.Len() != n {
			t.Fatalf("size %d, returned length was %d, written length was %d",
				i, n, enc.Len())
		}
		inverse := make([]byte, i)
		n, err = ReadData(&enc, inverse)
		if err != nil {
			t.Fatalf("size %d, ReadData returned error %v", i, err)
		}
		if !bytes.Equal(inverse[:n], original) {
			t.Fatalf("size %d, got <%x>, expected <%x>", i, inverse[:n], original)
		}
	}
}

// Test that WritePadding writes exactly as much as requested.
func TestPaddingLength(t *testing.T) {
	t.Parallel()

	// Test above and below interesting thresholds. WritePadding also gets
	// values above 0xfffff, the maximum value of a single length prefix.
	for _, i := range []int{
		0x00, 0x01,
		0x3f, 0x40, 0x41, 0x42,
		0xff, 0x100, 0x101, 0x102,
		0x2000, 0x2001, 0x2002, 0x2003,
		0x10000, 0x10001, 0x10002, 0x10003,
		0x100001, 0x100002, 0x100003, 0x100004,
	} {
		var enc bytes.Buffer
		n, err := WritePadding(&enc, i)
		if err != nil {
			t.Fatalf("size %d, WritePadding returned error %v", i, err)
		}
		if n != i {
			t.Fatalf("requested %d bytes, returned %d", i, n)
		}
		if enc.Len() != n {
			t.Fatalf("requested %d bytes, wrote %d bytes", i, enc.Len())
		}
	}
}

// Test that ReadData skips over padding.
func TestSkipPadding(t *testing.T) {
	t.Parallel()

	var data = [][]byte{{}, {}, []byte("hello"), {}, []byte("world")}
	var enc bytes.Buffer
	mustWritePadding(&enc, 10)
	mustWritePadding(&enc, 100)
	mustWriteData(&enc, data[0])
	mustWriteData(&enc, data[1])
	mustWritePadding(&enc, 10)
	mustWriteData(&enc, data[2])
	mustWriteData(&enc, data[3])
	mustWritePadding(&enc, 10)
	mustWriteData(&enc, data[4])
	mustWritePadding(&enc, 10)
	mustWritePadding(&enc, 10)
	for i, expected := range data {
		var actual [10]byte
		n, err := ReadData(&enc, actual[:])
		if err != nil {
			t.Fatalf("slice %d, got error %v, expected %v", i, err, nil)
		}
		if !bytes.Equal(actual[:n], expected) {
			t.Fatalf("slice %d, got <%x>, expected <%x>", i, actual[:n], expected)
		}
	}
	n, err := ReadData(&enc, nil)
	if n != 0 || err != io.EOF {
		t.Fatalf("got (%v, %v), expected (%v, %v)", n, err, 0, io.EOF)
	}
}

// Test that EOF before a length prefix returns io.EOF.
func TestEOF(t *testing.T) {
	t.Parallel()

	n, err := ReadData(bytes.NewReader(nil), nil)
	if n != 0 || err != io.EOF {
		t.Fatalf("got (%v, %v), expected (%v, %v)", n, err, 0, io.EOF)
	}
}

// Test that an EOF while reading a length prefix, or while reading the
// subsequent data/padding, returns io.ErrUnexpectedEOF.
func TestUnexpectedEOF(t *testing.T) {
	t.Parallel()

	for _, test := range [][]byte{
		{0x40},                  // expecting a second length byte
		{0xc0},                  // expecting a second length byte
		{0x41, 0x80},            // expecting a third length byte
		{0xc1, 0x80},            // expecting a third length byte
		{0x02},                  // expecting 2 bytes of padding
		{0x82},                  // expecting 2 bytes of data
		{0x02, 'X'},             // expecting 1 byte of padding
		{0x82, 'X'},             // expecting 1 byte of data
		{0x41, 0x00},            // expecting 128 bytes of padding
		{0xc1, 0x00},            // expecting 128 bytes of data
		{0x41, 0x00, 'X'},       // expecting 127 bytes of padding
		{0xc1, 0x00, 'X'},       // expecting 127 bytes of data
		{0x41, 0x80, 0x00},      // expecting 32768 bytes of padding
		{0xc1, 0x80, 0x00},      // expecting 32768 bytes of data
		{0x41, 0x80, 0x00, 'X'}, // expecting 32767 bytes of padding
		{0xc1, 0x80, 0x00, 'X'}, // expecting 32767 bytes of data
	} {
		n, err := ReadData(bytes.NewReader(test), nil)
		if n != 0 || err != io.ErrUnexpectedEOF {
			t.Fatalf("<%x> got (%v, %v), expected (%v, %v)", test, n, err, 0, io.ErrUnexpectedEOF)
		}
	}
}

// Test that length encodings that are longer than they could be are still
// interpreted.
func TestNonMinimalLengthEncoding(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		enc      []byte
		expected []byte
	}{
		{[]byte{0x81, 'X'}, []byte("X")},
		{[]byte{0xc0, 0x01, 'X'}, []byte("X")},
		{[]byte{0xc0, 0x80, 0x01, 'X'}, []byte("X")},
	} {
		var p [10]byte
		n, err := ReadData(bytes.NewReader(test.enc), p[:])
		if err != nil {
			t.Fatalf("<%x> got error %v, expected %v", test.enc, err, nil)
		}
		if !bytes.Equal(p[:n], test.expected) {
			t.Fatalf("<%x> got <%x>, expected <%x>", test.enc, p[:n], test.expected)
		}
	}
}

// Test that ReadData only reads up to 3 bytes of length prefix.
func TestReadLimits(t *testing.T) {
	t.Parallel()

	// Test the maximum length that's possible with 3 bytes of length
	// prefix.
	maxLength := (0x3f << 14) | (0x7f << 7) | 0x7f
	data := bytes.Repeat([]byte{'X'}, maxLength)
	prefix := []byte{0xff, 0xff, 0x7f} // encodes 0xfffff
	var p [0xfffff]byte
	n, err := ReadData(bytes.NewReader(append(prefix, data...)), p[:])
	if err != nil {
		t.Fatalf("got error %v, expected %v", err, nil)
	}
	if !bytes.Equal(p[:n], data) {
		t.Fatalf("got %d bytes unequal to %d bytes", len(p), len(data))
	}
	// Test a 4-byte prefix.
	prefix = []byte{0xc0, 0xc0, 0x80, 0x80} // encodes 0x100000
	data = bytes.Repeat([]byte{'X'}, maxLength+1)
	n, err = ReadData(bytes.NewReader(append(prefix, data...)), nil)
	if n != 0 || err != ErrTooLong {
		t.Fatalf("got (%v, %v), expected (%v, %v)", n, err, 0, ErrTooLong)
	}
	// Test that 4 bytes don't work, even when they encode an integer that
	// would fix in 3 bytes.
	prefix = []byte{0xc0, 0x80, 0x80, 0x80} // encodes 0x0
	data = []byte{}
	n, err = ReadData(bytes.NewReader(append(prefix, data...)), nil)
	if n != 0 || err != ErrTooLong {
		t.Fatalf("got (%v, %v), expected (%v, %v)", n, err, 0, ErrTooLong)
	}

	// Do the same tests with padding lengths.
	data = []byte("hello")
	prefix = []byte{0x7f, 0xff, 0x7f} // encodes 0xfffff
	padding := bytes.Repeat([]byte{'X'}, maxLength)
	enc := bytes.NewBuffer(append(prefix, padding...))
	mustWriteData(enc, data)
	n, err = ReadData(enc, p[:])
	if err != nil {
		t.Fatalf("got error %v, expected %v", err, nil)
	}
	if !bytes.Equal(p[:n], data) {
		t.Fatalf("got <%x>, expected <%x>", p[:n], data)
	}
	prefix = []byte{0x40, 0xc0, 0x80, 0x80} // encodes 0x100000
	padding = bytes.Repeat([]byte{'X'}, maxLength+1)
	enc = bytes.NewBuffer(append(prefix, padding...))
	mustWriteData(enc, data)
	n, err = ReadData(enc, nil)
	if n != 0 || err != ErrTooLong {
		t.Fatalf("got (%v, %v), expected (%v, %v)", n, err, 0, ErrTooLong)
	}
	prefix = []byte{0x40, 0x80, 0x80, 0x80} // encodes 0x0
	padding = []byte{}
	enc = bytes.NewBuffer(append(prefix, padding...))
	mustWriteData(enc, data)
	n, err = ReadData(enc, nil)
	if n != 0 || err != ErrTooLong {
		t.Fatalf("got (%v, %v), expected (%v, %v)", n, err, 0, ErrTooLong)
	}
}

// Test that WriteData and WritePadding only accept lengths that can be encoded
// in up to 3 bytes of length prefix.
func TestWriteLimits(t *testing.T) {
	t.Parallel()

	maxLength := (0x3f << 14) | (0x7f << 7) | 0x7f
	var enc bytes.Buffer
	n, err := WriteData(&enc, bytes.Repeat([]byte{'X'}, maxLength))
	if n != maxLength+3 || err != nil {
		t.Fatalf("got (%d, %v), expected (%d, %v)", n, err, maxLength, nil)
	}
	enc.Reset()
	n, err = WriteData(&enc, bytes.Repeat([]byte{'X'}, maxLength+1))
	if n != 0 || err != ErrTooLong {
		t.Fatalf("got (%d, %v), expected (%d, %v)", n, err, 0, ErrTooLong)
	}

	// Padding gets an extra 3 bytes because the prefix is counted as part
	// of the length.
	enc.Reset()
	n, err = WritePadding(&enc, maxLength+3)
	if n != maxLength+3 || err != nil {
		t.Fatalf("got (%d, %v), expected (%d, %v)", n, err, maxLength+3, nil)
	}
	// Writing a too-long padding is okay because WritePadding will break it
	// into smaller chunks.
	enc.Reset()
	n, err = WritePadding(&enc, maxLength+4)
	if n != maxLength+4 || err != nil {
		t.Fatalf("got (%d, %v), expected (%d, %v)", n, err, maxLength+4, nil)
	}
}

// Test that WritePadding panics when given a negative length.
func TestNegativeLength(t *testing.T) {
	t.Parallel()

	for _, n := range []int{-1, ^0} {
		var enc bytes.Buffer
		panicked, nn, err := testNegativeLengthSub(t, &enc, n)
		if !panicked {
			t.Fatalf("WritePadding(%d) returned (%d, %v) instead of panicking", n, nn, err)
		}
	}
}

// Calls WritePadding(w, n) and augments the return value with a flag indicating
// whether the call panicked.
func testNegativeLengthSub(t *testing.T, w io.Writer, n int) (panicked bool, nn int, err error) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	t.Helper()
	nn, err = WritePadding(w, n)
	return false, n, err
}

// Test that MaxDataForSize panics when given a 0 length.
func TestMaxDataForSizeZero(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("didn't panic")
		}
	}()
	MaxDataForSize(0)
}

// Test thresholds of available sizes for MaxDataForSize.
func TestMaxDataForSize(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		size     int
		expected int
	}{
		{0x01, 0x00},
		{0x02, 0x01},
		{0x3f, 0x3e},
		{0x40, 0x3e},
		{0x41, 0x3f},
		{0x1fff, 0x1ffd},
		{0x2000, 0x1ffd},
		{0x2001, 0x1ffe},
		{0xfffff, 0xffffc},
		{0x100000, 0xffffc},
		{0x100001, 0xffffc},
		{0x7fffffff, 0xffffc},
	} {
		max := MaxDataForSize(test.size)
		if max != test.expected {
			t.Fatalf("size %d, got %d, expected %d", test.size, max, test.expected)
		}
	}
}

// Test that ReadData truncates the data when the destination slice is too
// short.
func TestReadDataTruncate(t *testing.T) {
	t.Parallel()

	var enc bytes.Buffer
	mustWriteData(&enc, []byte("12345678"))
	mustWriteData(&enc, []byte("abcdefgh"))
	var p [4]byte
	// First ReadData should return truncated "1234".
	n, err := ReadData(&enc, p[:])
	if err != io.ErrShortBuffer {
		t.Fatalf("got error %v, expected %v", err, io.ErrShortBuffer)
	}
	if !bytes.Equal(p[:n], []byte("1234")) {
		t.Fatalf("got <%x>, expected <%x>", p[:n], []byte("1234"))
	}
	// Second ReadData should return truncated "abcd", not the rest of
	// "12345678".
	n, err = ReadData(&enc, p[:])
	if err != io.ErrShortBuffer {
		t.Fatalf("got error %v, expected %v", err, io.ErrShortBuffer)
	}
	if !bytes.Equal(p[:n], []byte("abcd")) {
		t.Fatalf("got <%x>, expected <%x>", p[:n], []byte("abcd"))
	}
	// Last ReadData should give io.EOF.
	n, err = ReadData(&enc, p[:])
	if err != io.EOF {
		t.Fatalf("got error %v, expected %v", err, io.EOF)
	}
}

// Test that even when the result is truncated, ReadData fills the provided
// buffer as much as possible (and not stop at the boundary of an internal Read,
// say).
func TestReadDataTruncateFull(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	go func() {
		// Send one data chunk that will be delivered across two Read
		// calls.
		pw.Write([]byte{0x8a, 'h', 'e', 'l', 'l', 'o'})
		pw.Write([]byte{'w', 'o', 'r', 'l', 'd'})
	}()
	var p [8]byte
	n, err := ReadData(pr, p[:])
	if err != io.ErrShortBuffer {
		t.Fatalf("got error %v, expected %v", err, io.ErrShortBuffer)
	}
	// Should not stop after "hello".
	if !bytes.Equal(p[:n], []byte("hellowor")) {
		t.Fatalf("got <%x>, expected <%x>", p[:n], []byte("hellowor"))
	}
}

// Benchmark the ReadData function when reading from a stream of data packets of
// different sizes.
func BenchmarkReadData(b *testing.B) {
	pr, pw := io.Pipe()
	go func() {
		for {
			for length := 0; length < 128; length++ {
				WriteData(pw, paddingBuffer[:length])
			}
		}
	}()

	var p [128]byte
	for i := 0; i < b.N; i++ {
		_, err := ReadData(pr, p[:])
		if err != nil {
			b.Fatal(err)
		}
	}
}
