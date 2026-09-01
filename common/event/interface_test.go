package event

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEventStrings(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		event SnowflakeEvent
		want  string
	}{
		{
			name:  "offer created",
			event: EventOnOfferCreated{},
			want:  "offer created",
		},
		{
			name:  "broker rendezvous",
			event: EventOnBrokerRendezvous{},
			want:  "broker rendezvous peer received",
		},
		{
			name:  "snowflake connected",
			event: EventOnSnowflakeConnected{},
			want:  "connected",
		},
		{
			name:  "proxy starting",
			event: EventOnProxyStarting{},
			want:  "Proxy starting",
		},
		{
			name:  "proxy client connected",
			event: EventOnProxyClientConnected{},
			want:  "Client connected",
		},
		{
			name:  "proxy connection over",
			event: EventOnProxyConnectionOver{Country: "IT"},
			want:  "Proxy connection closed",
		},
		{
			name:  "proxy connection failed",
			event: EventOnProxyConnectionFailed{},
			want:  "Failed to connect to the client",
		},
		{
			name:  "nat type determined",
			event: EventOnCurrentNATTypeDetermined{CurNATType: "moderate"},
			want:  "NAT type: moderate",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.event.String(); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// EventOnProxyConnectionOver carries a country code for metrics, but it must
// not leak into the log line, which is emitted unscrubbed.
func TestProxyConnectionOverDoesNotLogCountry(t *testing.T) {
	t.Parallel()

	if got := (EventOnProxyConnectionOver{Country: "IT"}).String(); strings.Contains(got, "IT") {
		t.Errorf("country code leaked into the event string: %q", got)
	}
}

func TestEventStringsWithError(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		event      SnowflakeEvent
		wantPrefix string
	}{
		{
			name:       "offer creation failure",
			event:      EventOnOfferCreated{Error: errors.New("no ICE candidates")},
			wantPrefix: "offer creation failure",
		},
		{
			name:       "broker failure",
			event:      EventOnBrokerRendezvous{Error: errors.New("bad status code")},
			wantPrefix: "broker failure",
		},
		{
			name:       "connection failed",
			event:      EventOnSnowflakeConnectionFailed{Error: errors.New("data channel timeout")},
			wantPrefix: "trying a new proxy:",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := test.event.String()
			if !strings.HasPrefix(got, test.wantPrefix) {
				t.Errorf("got %q, want prefix %q", got, test.wantPrefix)
			}
		})
	}
}

// Errors reaching the event log may embed peer addresses. Scrubbing them is a
// privacy invariant, not a formatting detail, so assert the address is gone.
func TestErrorEventsScrubIPAddresses(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		event func(error) SnowflakeEvent
	}{
		{"offer created", func(err error) SnowflakeEvent { return EventOnOfferCreated{Error: err} }},
		{"broker rendezvous", func(err error) SnowflakeEvent { return EventOnBrokerRendezvous{Error: err} }},
		{"connection failed", func(err error) SnowflakeEvent { return EventOnSnowflakeConnectionFailed{Error: err} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, addr := range []string{"192.0.2.42", "2001:db8::1"} {
				err := errors.New("dial failed for " + addr + ": refused")
				if got := test.event(err).String(); strings.Contains(got, addr) {
					t.Errorf("address %q was not scrubbed from %q", addr, got)
				}
			}
		})
	}
}

func TestProxyStatsString(t *testing.T) {
	t.Parallel()

	e := EventOnProxyStats{
		ConnectionCount:       5,
		FailedConnectionCount: 2,
		InboundBytes:          3600,
		InboundUnit:           "KB",
		OutboundBytes:         7200,
		OutboundUnit:          "KB",
		SummaryInterval:       time.Hour,
	}

	want := "In the last 1h0m0s, there were 5 completed successful connections. " +
		"Traffic Relayed ↓ 3600 KB (1.00 KB/s), ↑ 7200 KB (2.00 KB/s)."
	if got := e.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProxyStatsStringZeroTraffic(t *testing.T) {
	t.Parallel()

	e := EventOnProxyStats{
		SummaryInterval: time.Minute,
		InboundUnit:     "KB",
		OutboundUnit:    "KB",
	}

	want := "In the last 1m0s, there were 0 completed successful connections. " +
		"Traffic Relayed ↓ 0 KB (0.00 KB/s), ↑ 0 KB (0.00 KB/s)."
	if got := e.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
