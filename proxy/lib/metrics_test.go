package snowflake_proxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// hasSample reports whether the exposition text contains the given series with
// the given value, ignoring comment lines.
func hasSample(exposition, series, value string) bool {
	for line := range strings.Lines(exposition) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if name, got, ok := strings.Cut(line, " "); ok && name == series && got == value {
			return true
		}
	}
	return false
}

func TestMetricsStartInvalidAddress(t *testing.T) {
	t.Parallel()

	m := NewMetrics()

	// Fails while binding, before anything is registered globally.
	if err := m.Start("127.0.0.1:99999"); err == nil {
		t.Fatal("expected an error for an out-of-range port")
	}
}

// TestMetrics covers the whole of metrics.go through the real exposition
// endpoint. It cannot be split into independent tests, nor run in parallel:
// Start registers on the default Prometheus registry and the default HTTP mux,
// so only one successful call is possible per process.
func TestMetrics(t *testing.T) {
	// Pick a free port, then let Start bind it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	m := NewMetrics()
	if err := m.Start(addr); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// scrape fetches the exposition text from the metrics endpoint, which
	// makes the registry call Describe and Collect on the proxy metrics.
	scrape := func() string {
		t.Helper()

		resp, err := http.Get("http://" + addr + "/internal/metrics")
		if err != nil {
			t.Fatalf("fetching metrics: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got status %d, want 200", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading the response body: %v", err)
		}
		return string(body)
	}

	t.Run("no traffic yet", func(t *testing.T) {
		exposition := scrape()

		// The counters with no labels are exported from the start, so
		// that a scrape of an idle proxy is not a gap in the series.
		for _, series := range []string{
			metricNamespace + "_connection_timeouts_total",
			metricNamespace + "_traffic_inbound_bytes_total",
			metricNamespace + "_traffic_outbound_bytes_total",
		} {
			if !hasSample(exposition, series, "0") {
				t.Errorf("expected %s to be 0 in:\n%s", series, exposition)
			}
		}
	})

	m.TrackInBoundTraffic(100)
	m.TrackInBoundTraffic(50)
	m.TrackOutBoundTraffic(7)
	m.TrackNewConnection("IT")
	m.TrackNewConnection("IT")
	m.TrackNewConnection("FR")
	m.TrackFailedConnection()

	t.Run("tracked values are exported", func(t *testing.T) {
		exposition := scrape()

		for _, test := range []struct{ series, value string }{
			{metricNamespace + "_traffic_inbound_bytes_total", "150"},
			{metricNamespace + "_traffic_outbound_bytes_total", "7"},
			{metricNamespace + `_connections_total{country="IT"}`, "2"},
			{metricNamespace + `_connections_total{country="FR"}`, "1"},
			{metricNamespace + "_connection_timeouts_total", "1"},
		} {
			if !hasSample(exposition, test.series, test.value) {
				t.Errorf("expected %s to be %s in:\n%s", test.series, test.value, exposition)
			}
		}
	})

	t.Run("unseen country is absent", func(t *testing.T) {
		// A country nobody connected from must not appear at all, rather
		// than as a zero-valued series suggesting traffic from there.
		if exposition := scrape(); strings.Contains(exposition, `country="DE"`) {
			t.Errorf("an unseen country was exported:\n%s", exposition)
		}
	})

	t.Run("counters are monotonic across scrapes", func(t *testing.T) {
		// Prometheus computes rates from differences, so a scrape must
		// never reset the counters.
		m.TrackInBoundTraffic(5)

		series := metricNamespace + "_traffic_inbound_bytes_total"
		if exposition := scrape(); !hasSample(exposition, series, "155") {
			t.Errorf("expected %s to be 155 in:\n%s", series, exposition)
		}
	})
}
