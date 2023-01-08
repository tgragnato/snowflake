package turbotunnel

import (
	"testing"
	"time"
)

type emptyAddr struct{}

func (_ emptyAddr) Network() string { return "empty" }
func (_ emptyAddr) String() string  { return "empty" }

// Run with -benchmem to see memory allocations.
func BenchmarkQueueIncoming(b *testing.B) {
	conn := NewQueuePacketConn(emptyAddr{}, 1*time.Hour)
	defer conn.Close()

	b.ResetTimer()
	s := 500
	for i := 0; i < b.N; i++ {
		// Use a variable for the length to stop the compiler from
		// optimizing out the allocation.
		p := make([]byte, s)
		conn.QueueIncoming(p, emptyAddr{})
	}
	b.StopTimer()
}

// BenchmarkWriteTo benchmarks the QueuePacketConn.WriteTo function.
func BenchmarkWriteTo(b *testing.B) {
	conn := NewQueuePacketConn(emptyAddr{}, 1*time.Hour)
	defer conn.Close()

	b.ResetTimer()
	s := 500
	for i := 0; i < b.N; i++ {
		// Use a variable for the length to stop the compiler from
		// optimizing out the allocation.
		p := make([]byte, s)
		conn.WriteTo(p, emptyAddr{})
	}
	b.StopTimer()
}
