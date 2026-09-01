package snowflake_proxy

import (
	"testing"

	"tgragnato.it/snowflake/common/event"
)

// stubCollector records the calls an EventMetrics makes, standing in for the
// Prometheus-backed collector.
type stubCollector struct {
	inbound, outbound int64
	countries         []string
	failed            int
}

func (s *stubCollector) TrackInBoundTraffic(value int64)  { s.inbound += value }
func (s *stubCollector) TrackOutBoundTraffic(value int64) { s.outbound += value }
func (s *stubCollector) TrackNewConnection(country string) {
	s.countries = append(s.countries, country)
}
func (s *stubCollector) TrackFailedConnection() { s.failed++ }

func TestEventMetricsProxyStats(t *testing.T) {
	t.Parallel()

	collector := &stubCollector{}
	metrics := NewEventMetrics(collector)

	metrics.OnNewSnowflakeEvent(event.EventOnProxyStats{
		InboundBytes:  120,
		OutboundBytes: 340,
	})

	if collector.inbound != 120 {
		t.Errorf("inbound: got %d, want 120", collector.inbound)
	}
	if collector.outbound != 340 {
		t.Errorf("outbound: got %d, want 340", collector.outbound)
	}
}

func TestEventMetricsConnectionOverCarriesCountry(t *testing.T) {
	t.Parallel()

	collector := &stubCollector{}
	metrics := NewEventMetrics(collector)

	metrics.OnNewSnowflakeEvent(event.EventOnProxyConnectionOver{Country: "IT"})
	metrics.OnNewSnowflakeEvent(event.EventOnProxyConnectionOver{Country: "FR"})
	// An unknown country is still a connection and must be counted.
	metrics.OnNewSnowflakeEvent(event.EventOnProxyConnectionOver{})

	want := []string{"IT", "FR", ""}
	if len(collector.countries) != len(want) {
		t.Fatalf("got %d connections, want %d: %q", len(collector.countries), len(want), collector.countries)
	}
	for i, country := range want {
		if collector.countries[i] != country {
			t.Errorf("connection %d: got %q, want %q", i, collector.countries[i], country)
		}
	}
}

func TestEventMetricsConnectionFailed(t *testing.T) {
	t.Parallel()

	collector := &stubCollector{}
	metrics := NewEventMetrics(collector)

	metrics.OnNewSnowflakeEvent(event.EventOnProxyConnectionFailed{})
	metrics.OnNewSnowflakeEvent(event.EventOnProxyConnectionFailed{})

	if collector.failed != 2 {
		t.Errorf("got %d failed connections, want 2", collector.failed)
	}
}

// Events that carry no metric must be ignored rather than counted as one of
// the tracked outcomes.
func TestEventMetricsIgnoresOtherEvents(t *testing.T) {
	t.Parallel()

	collector := &stubCollector{}
	metrics := NewEventMetrics(collector)

	for _, e := range []event.SnowflakeEvent{
		event.EventOnProxyStarting{},
		event.EventOnProxyClientConnected{},
		event.EventOnCurrentNATTypeDetermined{CurNATType: "open"},
		event.EventOnSnowflakeConnected{},
	} {
		metrics.OnNewSnowflakeEvent(e)
	}

	if collector.inbound != 0 || collector.outbound != 0 {
		t.Errorf("traffic was tracked: in=%d out=%d", collector.inbound, collector.outbound)
	}
	if len(collector.countries) != 0 {
		t.Errorf("connections were tracked: %q", collector.countries)
	}
	if collector.failed != 0 {
		t.Errorf("failures were tracked: %d", collector.failed)
	}
}
