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

// drainStat calls GetStat until the reported totals add up to wantIn and
// wantOut. The logger feeds its counters from buffered channels, so a single
// GetStat may observe only part of what was added; the remainder is reported
// by a later call rather than lost.
func drainStat(t *testing.T, b *bytesSyncLogger, wantIn, wantOut int64) {
	t.Helper()

	var in, out int64
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		i, o := b.GetStat()
		in += i
		out += o
		if in == wantIn && out == wantOut {
			return
		}
		if in > wantIn || out > wantOut {
			t.Fatalf("over-counted: got in=%d out=%d, want in=%d out=%d", in, out, wantIn, wantOut)
		}
	}
	t.Fatalf("timed out: got in=%d out=%d, want in=%d out=%d", in, out, wantIn, wantOut)
}

// GetStat is the summary interval's read-and-reset: once everything added has
// been reported, the next interval must start from zero, otherwise the
// periodic summaries would report running totals instead of per-interval ones.
func TestBytesSyncLoggerGetStatResets(t *testing.T) {
	t.Parallel()

	b := newBytesSyncLogger()

	b.AddInbound(10)
	b.AddOutbound(20)
	drainStat(t, b, 10, 20)

	if in, out := b.GetStat(); in != 0 || out != 0 {
		t.Errorf("after draining: got in=%d out=%d, want both 0", in, out)
	}

	// A new interval accumulates independently of the previous one.
	b.AddInbound(3)
	drainStat(t, b, 3, 0)
}

func TestBytesSyncLoggerAccumulates(t *testing.T) {
	t.Parallel()

	b := newBytesSyncLogger()

	for range 5 {
		b.AddInbound(7)
		b.AddOutbound(11)
	}

	drainStat(t, b, 35, 55)
}

func TestFormatTraffic(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		amount    int64
		wantValue int64
	}{
		{"zero", 0, 0},
		{"below one kilobyte is truncated", 999, 0},
		{"exactly one kilobyte", 1000, 1},
		{"truncates towards zero", 1999, 1},
		{"megabyte", 1_500_000, 1500},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			value, unit := formatTraffic(test.amount)
			if value != test.wantValue {
				t.Errorf("value: got %d, want %d", value, test.wantValue)
			}
			if unit != "KB" {
				t.Errorf("unit: got %q, want \"KB\"", unit)
			}
		})
	}
}
