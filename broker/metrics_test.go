package main

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
)

func TestDeniedClientNATMetrics(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	metrics, err := NewMetrics(log.New(buf, "", 0))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	for _, natType := range []string{
		NATRestricted,
		NATUnrestricted,
		NAT3Strict,
		NAT3Moderate,
		NAT3Open,
		NATUnknown,
	} {
		metrics.UpdateClientStats("192.0.2.1", "http", natType, "denied")
	}

	// Denied clients are counted by every supported NAT type. Counts are
	// binned to multiples of 8.
	metrics.printMetrics()
	const wantCounted = `client-denied-count 8
client-restricted-denied-count 8
client-unrestricted-denied-count 8
client-nat-strict-denied-count 8
client-nat-moderate-denied-count 8
client-nat-open-denied-count 8
client-nat-unknown-denied-count 8
`
	if !strings.Contains(buf.String(), wantCounted) {
		t.Errorf("metrics output missing expected counts; got:\n%s", buf.String())
	}

	// printMetrics resets the counters, so a second dump reports zeroes.
	buf.Reset()
	metrics.printMetrics()
	const wantReset = `client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-nat-strict-denied-count 0
client-nat-moderate-denied-count 0
client-nat-open-denied-count 0
client-nat-unknown-denied-count 0
`
	if !strings.Contains(buf.String(), wantReset) {
		t.Errorf("metrics output not reset; got:\n%s", buf.String())
	}
}

// newCountryStats builds a fresh mapping of country stats.
// formatAndClearCountryStats consumes the map, so each subtest needs its own.
func newCountryStats() *sync.Map {
	stats := new(sync.Map)
	for _, record := range []struct {
		cc    string
		count uint64
	}{
		{"IT", 50},
		{"FR", 200},
		{"TZ", 100},
		{"CN", 250},
		{"RU", 150},
		{"CA", 1},
		{"BE", 1},
		{"PH", 1},
		// The next 3 bin to the same value, 112. When not binned, they
		// should go in the order MY,ZA,AT (ordered by count). When binned,
		// they should go in the order AT,MY,ZA (ordered by country code).
		{"AT", 105},
		{"MY", 112},
		{"ZA", 108},
	} {
		stats.Store(record.cc, &record.count)
	}
	return stats
}

func TestFormatAndClearCountryStats(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		binned bool
		want   string
	}{
		{
			name:   "binned=false",
			binned: false,
			want:   "CN=250,FR=200,RU=150,MY=112,ZA=108,AT=105,TZ=100,IT=50,BE=1,CA=1,PH=1",
		},
		{
			name:   "binned=true",
			binned: true,
			want:   "CN=256,FR=200,RU=152,AT=112,MY=112,ZA=112,TZ=104,IT=56,BE=8,CA=8,PH=8",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats := newCountryStats()
			if got := formatAndClearCountryStats(stats, tc.binned); got != tc.want {
				t.Errorf("formatAndClearCountryStats() = %q, want %q", got, tc.want)
			}
			// The map should be cleared on return.
			stats.Range(func(k, _ any) bool {
				t.Errorf("map was not cleared: still holds %v", k)
				return false
			})
		})
	}
}
