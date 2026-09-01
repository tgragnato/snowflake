package snowflake_client

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// The null logger is the default, and must accept traffic accounting without
// doing anything with it.
func TestBytesNullLogger(t *testing.T) {
	t.Parallel()

	var logger bytesLogger = bytesNullLogger{}

	logger.addInbound(100)
	logger.addOutbound(200)
}

// The logger must never block its callers: addInbound and addOutbound are
// called from the data channel and the copy loop, so a full channel would
// stall the tunnel rather than just lose an accounting event.
func TestBytesSyncLoggerDoesNotBlock(t *testing.T) {
	t.Parallel()

	logger := newBytesSyncLogger()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Far more events than the channels can buffer.
		for range 1000 {
			logger.addInbound(1)
			logger.addOutbound(1)
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("the logger blocked its caller")
	}
}

// syncBuffer is a bytes.Buffer safe for the logging goroutine to write to
// while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.buf.String()
}

// TestBytesSyncLoggerLogsTotals is slow by construction: LogTimeInterval is a
// constant, so the only way to observe the periodic line is to wait for it.
func TestBytesSyncLoggerLogsTotals(t *testing.T) {
	if testing.Short() {
		t.Skipf("skipping: waits out the %v log interval", LogTimeInterval)
	}

	var output syncBuffer
	original := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(original) })

	logger := newBytesSyncLogger()
	logger.addInbound(300)
	logger.addOutbound(100)
	logger.addOutbound(40)

	// One inbound event of 300, two outbound events totalling 140.
	want := "Traffic Bytes (in|out): 300 | 140 -- (1 OnMessages, 2 Sends)"

	// Two intervals of headroom, so a slow machine does not fail the test.
	// Other tests in this package log through the same global writer, so the
	// expected line is searched for among all of them rather than assumed to
	// be the only one.
	deadline := time.Now().Add(2*LogTimeInterval + time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(output.String(), want) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("never logged %q within %v:\n%s", want, 2*LogTimeInterval, output.String())
}
