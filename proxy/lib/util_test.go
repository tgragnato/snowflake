package snowflake_proxy

import (
	"testing"
	"time"
)

func TestLog(t *testing.T) {
	t.Parallel()

	b := newBytesSyncLogger()

	b.AddOutbound(100)
	b.AddInbound(200)
	time.Sleep(500 * time.Millisecond)

	in, out := b.GetStat()
	if in != 200 {
		t.Errorf("Expected inbound bytes to be 200, got %d", in)
	}
	if out != 100 {
		t.Errorf("Expected outbound bytes to be 100, got %d", out)
	}
}
