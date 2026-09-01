package snowflake_proxy

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"tgragnato.it/snowflake/common/event"
)

// syncBuffer is a bytes.Buffer that is safe to write from the logger and read
// from the test.
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

func TestProxyEventLogger(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		event        event.SnowflakeEvent
		disableStats bool
		wantLogged   bool
	}{
		{
			name:       "proxy starting is logged",
			event:      event.EventOnProxyStarting{},
			wantLogged: true,
		},
		{
			name:       "nat type is logged",
			event:      event.EventOnCurrentNATTypeDetermined{CurNATType: "moderate"},
			wantLogged: true,
		},
		{
			name:       "stats are logged by default",
			event:      event.EventOnProxyStats{SummaryInterval: time.Hour},
			wantLogged: true,
		},
		{
			name:         "stats are suppressed when disabled",
			event:        event.EventOnProxyStats{SummaryInterval: time.Hour},
			disableStats: true,
			wantLogged:   false,
		},
		{
			// Per-client events would let an observer of the log
			// correlate individual connections.
			name:       "client connected is suppressed",
			event:      event.EventOnProxyClientConnected{},
			wantLogged: false,
		},
		{
			name:       "connection over is suppressed",
			event:      event.EventOnProxyConnectionOver{Country: "IT"},
			wantLogged: false,
		},
		{
			name:       "connection failed is suppressed",
			event:      event.EventOnProxyConnectionFailed{},
			wantLogged: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var output syncBuffer
			logger := NewProxyEventLogger(&output, test.disableStats)
			logger.OnNewSnowflakeEvent(test.event)

			got := output.String()
			if test.wantLogged && !strings.Contains(got, test.event.String()) {
				t.Errorf("expected the event to be logged, got %q", got)
			}
			if !test.wantLogged && strings.Contains(got, test.event.String()) {
				t.Errorf("expected the event to be suppressed, got %q", got)
			}
		})
	}
}

// The startup notice about local time is what tells an operator their log is
// not safe to share as-is, so it must appear exactly when UTC is not in use.
func TestProxyEventLoggerLocalTimeNotice(t *testing.T) {
	const notice = "Local time is being used for logging"

	for _, test := range []struct {
		name       string
		flags      int
		wantNotice bool
	}{
		{"local time warns", log.LstdFlags, true},
		{"utc does not warn", log.LstdFlags | log.LUTC, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			// NewProxyEventLogger snapshots the global log flags, so
			// this cannot run in parallel with the other subtests.
			original := log.Flags()
			log.SetFlags(test.flags)
			t.Cleanup(func() { log.SetFlags(original) })

			var output syncBuffer
			logger := NewProxyEventLogger(&output, false)
			logger.OnNewSnowflakeEvent(event.EventOnProxyStarting{})

			got := output.String()
			if !strings.Contains(got, "Proxy starting") {
				t.Errorf("the startup event was not logged: %q", got)
			}
			if containsNotice := strings.Contains(got, notice); containsNotice != test.wantNotice {
				t.Errorf("notice present = %v, want %v, in %q", containsNotice, test.wantNotice, got)
			}
		})
	}
}

// stubDispatcher captures the events a periodicProxyStats emits.
type stubDispatcher struct {
	mu     sync.Mutex
	events []event.SnowflakeEvent
}

func (s *stubDispatcher) OnNewSnowflakeEvent(e event.SnowflakeEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, e)
}

func (s *stubDispatcher) AddSnowflakeEventListener(event.SnowflakeEventReceiver)    {}
func (s *stubDispatcher) RemoveSnowflakeEventListener(event.SnowflakeEventReceiver) {}

func (s *stubDispatcher) last() event.SnowflakeEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.events) == 0 {
		return nil
	}
	return s.events[len(s.events)-1]
}

// stubBytesLogger returns a fixed pair of totals from GetStat, and records
// what was added to it.
type stubBytesLogger struct {
	mu       sync.Mutex
	in, out  int64 // reported by GetStat
	addedIn  int64
	addedOut int64
}

func (s *stubBytesLogger) AddOutbound(amount int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.addedOut += amount
}

func (s *stubBytesLogger) AddInbound(amount int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.addedIn += amount
}

func (s *stubBytesLogger) GetStat() (in int64, out int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.in, s.out
}

func (s *stubBytesLogger) inbound() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.addedIn
}

func TestPeriodicProxyStatsCountsConnections(t *testing.T) {
	t.Parallel()

	dispatcher := &stubDispatcher{}
	// A one hour period means the scheduled tick never fires during the
	// test, so logTick is driven by hand and the result is deterministic.
	stats := newPeriodicProxyStats(time.Hour, dispatcher, &stubBytesLogger{in: 3_000, out: 5_000})
	defer stats.Close()

	stats.OnNewSnowflakeEvent(event.EventOnProxyConnectionOver{Country: "IT"})
	stats.OnNewSnowflakeEvent(event.EventOnProxyConnectionOver{Country: "FR"})
	stats.OnNewSnowflakeEvent(event.EventOnProxyConnectionFailed{})
	// Events it does not care about must not disturb the counts.
	stats.OnNewSnowflakeEvent(event.EventOnProxyClientConnected{})

	if err := stats.logTick(); err != nil {
		t.Fatalf("logTick: %v", err)
	}

	e, ok := dispatcher.last().(event.EventOnProxyStats)
	if !ok {
		t.Fatalf("expected an EventOnProxyStats, got %T", dispatcher.last())
	}
	if e.ConnectionCount != 2 {
		t.Errorf("ConnectionCount: got %d, want 2", e.ConnectionCount)
	}
	if e.FailedConnectionCount != 1 {
		t.Errorf("FailedConnectionCount: got %d, want 1", e.FailedConnectionCount)
	}
	if e.SummaryInterval != time.Hour {
		t.Errorf("SummaryInterval: got %v, want 1h", e.SummaryInterval)
	}
	// The byte totals are reported in the unit formatTraffic chose.
	if e.InboundBytes != 3 || e.InboundUnit != "KB" {
		t.Errorf("inbound: got %d %s, want 3 KB", e.InboundBytes, e.InboundUnit)
	}
	if e.OutboundBytes != 5 || e.OutboundUnit != "KB" {
		t.Errorf("outbound: got %d %s, want 5 KB", e.OutboundBytes, e.OutboundUnit)
	}
}

// Each summary covers one interval, so the counters must restart from zero.
func TestPeriodicProxyStatsResetsEachTick(t *testing.T) {
	t.Parallel()

	dispatcher := &stubDispatcher{}
	stats := newPeriodicProxyStats(time.Hour, dispatcher, &stubBytesLogger{})
	defer stats.Close()

	stats.OnNewSnowflakeEvent(event.EventOnProxyConnectionOver{})
	stats.OnNewSnowflakeEvent(event.EventOnProxyConnectionFailed{})
	if err := stats.logTick(); err != nil {
		t.Fatalf("first logTick: %v", err)
	}
	if err := stats.logTick(); err != nil {
		t.Fatalf("second logTick: %v", err)
	}

	e, ok := dispatcher.last().(event.EventOnProxyStats)
	if !ok {
		t.Fatalf("expected an EventOnProxyStats, got %T", dispatcher.last())
	}
	if e.ConnectionCount != 0 || e.FailedConnectionCount != 0 {
		t.Errorf("counters were not reset: got %d completed, %d failed",
			e.ConnectionCount, e.FailedConnectionCount)
	}
}

func TestPeriodicProxyStatsCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	stats := newPeriodicProxyStats(time.Hour, &stubDispatcher{}, &stubBytesLogger{})

	if err := stats.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := stats.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// The scheduled tick must actually fire on its own, not only when driven by
// hand: this is what produces the periodic summary in a running proxy.
func TestPeriodicProxyStatsEmitsOnSchedule(t *testing.T) {
	t.Parallel()

	dispatcher := &stubDispatcher{}
	stats := newPeriodicProxyStats(time.Millisecond, dispatcher, &stubBytesLogger{})
	defer stats.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := dispatcher.last().(event.EventOnProxyStats); ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Error("no stats event was emitted by the scheduled tick")
}
