/*
We export metrics in the format specified in our broker spec:
https://gitweb.torproject.org/pluggable-transports/snowflake.git/tree/doc/broker-spec.txt
*/

package main

import (
	"fmt"
	"log"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gitlab.torproject.org/tpo/anti-censorship/geoip"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/ptutil/safeprom"
	"tgragnato.it/snowflake/common/messages"
)

const (
	prometheusNamespace = "snowflake"
	metricsResolution   = 60 * 60 * 24 * time.Second //86400 seconds
)

var rendezvoudMethodList = [...]messages.RendezvousMethod{
	messages.RendezvousHttp,
	messages.RendezvousAmpCache,
	messages.RendezvousSqs,
}

type CountryStats struct {
	// map[proxyType][address]bool
	proxies map[string]map[string]bool
	unknown map[string]bool

	natRestricted   map[string]bool
	natUnrestricted map[string]bool
	natUnknown      map[string]bool

	counts map[string]int
}

// Implements Observable
type Metrics struct {
	sync.Mutex

	logger  *log.Logger
	geoipdb *geoip.Geoip

	countryStats                  CountryStats
	clientRoundtripEstimate       time.Duration
	proxyIdleCount                uint
	clientDeniedCount             map[messages.RendezvousMethod]uint
	clientRestrictedDeniedCount   map[messages.RendezvousMethod]uint
	clientUnrestrictedDeniedCount map[messages.RendezvousMethod]uint
	clientProxyMatchCount         map[messages.RendezvousMethod]uint

	rendezvousCountryStats map[messages.RendezvousMethod]map[string]int

	proxyPollWithRelayURLExtension         uint
	proxyPollWithoutRelayURLExtension      uint
	proxyPollRejectedWithRelayURLExtension uint

	promMetrics *PromMetrics
}

type record struct {
	cc    string
	count int
}
type records []record

func (r records) Len() int      { return len(r) }
func (r records) Swap(i, j int) { r[i], r[j] = r[j], r[i] }
func (r records) Less(i, j int) bool {
	if r[i].count == r[j].count {
		return r[i].cc > r[j].cc
	}
	return r[i].count < r[j].count
}

func (s CountryStats) Display() string {
	output := ""

	// Use the records struct to sort our counts map by value.
	rs := records{}
	for cc, count := range s.counts {
		rs = append(rs, record{cc: cc, count: count})
	}
	sort.Sort(sort.Reverse(rs))
	for _, r := range rs {
		output += fmt.Sprintf("%s=%d,", r.cc, r.count)
	}

	// cut off trailing ","
	if len(output) > 0 {
		return output[:len(output)-1]
	}

	return output
}

func (m *Metrics) UpdateCountryStats(addr string, proxyType string, natType string) {
	m.Lock()
	defer m.Unlock()

	var country string
	var ok bool

	addresses, ok := m.countryStats.proxies[proxyType]
	if !ok {
		if m.countryStats.unknown[addr] {
			return
		}
		m.countryStats.unknown[addr] = true
	} else {
		if addresses[addr] {
			return
		}
		addresses[addr] = true
	}

	ip := net.ParseIP(addr)
	if m.geoipdb == nil {
		return
	}
	country, ok = m.geoipdb.GetCountryByAddr(ip)
	if !ok {
		country = "??"
	}
	m.countryStats.counts[country]++

	m.promMetrics.ProxyTotal.With(prometheus.Labels{
		"nat":  natType,
		"type": proxyType,
		"cc":   country,
	}).Inc()

	switch natType {
	case NATRestricted:
		m.countryStats.natRestricted[addr] = true
	case NATUnrestricted:
		m.countryStats.natUnrestricted[addr] = true
	default:
		m.countryStats.natUnknown[addr] = true
	}
}

func (m *Metrics) UpdateRendezvousStats(addr string, rendezvousMethod messages.RendezvousMethod, natType string, matched bool) {
	m.Lock()
	defer m.Unlock()

	ip := net.ParseIP(addr)
	country := "??"
	if m.geoipdb != nil {
		country_by_addr, ok := m.geoipdb.GetCountryByAddr(ip)
		if ok {
			country = country_by_addr
		}
	}

	var status string
	if !matched {
		m.clientDeniedCount[rendezvousMethod]++
		if natType == NATUnrestricted {
			m.clientUnrestrictedDeniedCount[rendezvousMethod]++
		} else {
			m.clientRestrictedDeniedCount[rendezvousMethod]++
		}
		status = "denied"
	} else {
		status = "matched"
		m.clientProxyMatchCount[rendezvousMethod]++
	}
	m.rendezvousCountryStats[rendezvousMethod][country]++
	m.promMetrics.ClientPollTotal.With(prometheus.Labels{
		"nat":               natType,
		"status":            status,
		"rendezvous_method": string(rendezvousMethod),
		"cc":                country,
	}).Inc()
}

func (m *Metrics) UpdateProxyPollStats(pollType string, natType string, proxyType string) {
	m.Lock()
	defer m.Unlock()

	switch pollType {
	case "without_relay_url_extension":
		m.proxyPollWithoutRelayURLExtension++
	case "with_relay_url_extension":
		m.proxyPollWithRelayURLExtension++
	case "rejected_relay_url_extension":
		m.proxyPollRejectedWithRelayURLExtension++
	case "idle":
		m.proxyIdleCount++
	}

	m.promMetrics.ProxyPollWithoutRelayURLExtensionTotal.With(prometheus.Labels{"nat": natType, "type": proxyType}).Inc()
}

func (m *Metrics) DisplayRendezvousStatsByCountry(rendezvoudMethod messages.RendezvousMethod) string {
	output := ""

	// Use the records struct to sort our counts map by value.
	rs := records{}
	for cc, count := range m.rendezvousCountryStats[rendezvoudMethod] {
		rs = append(rs, record{cc: cc, count: count})
	}
	sort.Sort(sort.Reverse(rs))
	for _, r := range rs {
		output += fmt.Sprintf("%s=%d,", r.cc, binCount(uint(r.count)))
	}

	// cut off trailing ","
	if len(output) > 0 {
		return output[:len(output)-1]
	}

	return output
}

func (m *Metrics) LoadGeoipDatabases(geoipDB string, geoip6DB string) (err error) {
	m.Lock()
	defer m.Unlock()
	m.geoipdb, err = geoip.New(geoipDB, geoip6DB)
	return err
}

func NewMetrics(metricsLogger *log.Logger) (*Metrics, error) {
	m := new(Metrics)

	m.clientDeniedCount = make(map[messages.RendezvousMethod]uint)
	m.clientRestrictedDeniedCount = make(map[messages.RendezvousMethod]uint)
	m.clientUnrestrictedDeniedCount = make(map[messages.RendezvousMethod]uint)
	m.clientProxyMatchCount = make(map[messages.RendezvousMethod]uint)

	m.rendezvousCountryStats = make(map[messages.RendezvousMethod]map[string]int)
	for _, rendezvousMethod := range rendezvoudMethodList {
		m.rendezvousCountryStats[rendezvousMethod] = make(map[string]int)
	}

	m.countryStats = CountryStats{
		counts:          make(map[string]int),
		proxies:         make(map[string]map[string]bool),
		unknown:         make(map[string]bool),
		natRestricted:   make(map[string]bool),
		natUnrestricted: make(map[string]bool),
		natUnknown:      make(map[string]bool),
	}
	for pType := range messages.KnownProxyTypes {
		m.countryStats.proxies[pType] = make(map[string]bool)
	}

	m.logger = metricsLogger
	m.promMetrics = initPrometheus()

	// Write to log file every day with updated metrics
	go m.logMetrics()

	return m, nil
}

// Logs metrics in intervals specified by metricsResolution
func (m *Metrics) logMetrics() {
	heartbeat := time.Tick(metricsResolution)
	for range heartbeat {
		m.printMetrics()
		m.zeroMetrics()
	}
}

func (m *Metrics) printMetrics() {
	m.Lock()
	m.logger.Println(
		"snowflake-stats-end",
		time.Now().UTC().Format("2006-01-02 15:04:05"),
		fmt.Sprintf("(%d s)", int(metricsResolution.Seconds())),
	)
	m.logger.Println("snowflake-ips", m.countryStats.Display())
	total := len(m.countryStats.unknown)
	for pType, addresses := range m.countryStats.proxies {
		m.logger.Printf("snowflake-ips-%s %d\n", pType, len(addresses))
		total += len(addresses)
	}
	m.logger.Println("snowflake-ips-total", total)
	m.logger.Println("snowflake-idle-count", binCount(m.proxyIdleCount))
	m.logger.Println("snowflake-proxy-poll-with-relay-url-count", binCount(m.proxyPollWithRelayURLExtension))
	m.logger.Println("snowflake-proxy-poll-without-relay-url-count", binCount(m.proxyPollWithoutRelayURLExtension))
	m.logger.Println("snowflake-proxy-rejected-for-relay-url-count", binCount(m.proxyPollRejectedWithRelayURLExtension))

	m.logger.Println("client-denied-count", binCount(sumMapValues(&m.clientDeniedCount)))
	m.logger.Println("client-restricted-denied-count", binCount(sumMapValues(&m.clientRestrictedDeniedCount)))
	m.logger.Println("client-unrestricted-denied-count", binCount(sumMapValues(&m.clientUnrestrictedDeniedCount)))
	m.logger.Println("client-snowflake-match-count", binCount(sumMapValues(&m.clientProxyMatchCount)))

	for _, rendezvousMethod := range rendezvoudMethodList {
		m.logger.Printf("client-%s-count %d\n", rendezvousMethod, binCount(
			m.clientDeniedCount[rendezvousMethod]+m.clientProxyMatchCount[rendezvousMethod],
		))
		m.logger.Printf("client-%s-ips %s\n", rendezvousMethod, m.DisplayRendezvousStatsByCountry(rendezvousMethod))
	}

	m.logger.Println("snowflake-ips-nat-restricted", len(m.countryStats.natRestricted))
	m.logger.Println("snowflake-ips-nat-unrestricted", len(m.countryStats.natUnrestricted))
	m.logger.Println("snowflake-ips-nat-unknown", len(m.countryStats.natUnknown))
	m.Unlock()
}

// Restores all metrics to original values
func (m *Metrics) zeroMetrics() {
	m.proxyIdleCount = 0
	m.clientDeniedCount = make(map[messages.RendezvousMethod]uint)
	m.clientRestrictedDeniedCount = make(map[messages.RendezvousMethod]uint)
	m.clientUnrestrictedDeniedCount = make(map[messages.RendezvousMethod]uint)
	m.proxyPollRejectedWithRelayURLExtension = 0
	m.proxyPollWithRelayURLExtension = 0
	m.proxyPollWithoutRelayURLExtension = 0
	m.clientProxyMatchCount = make(map[messages.RendezvousMethod]uint)

	m.rendezvousCountryStats = make(map[messages.RendezvousMethod]map[string]int)
	for _, rendezvousMethod := range rendezvoudMethodList {
		m.rendezvousCountryStats[rendezvousMethod] = make(map[string]int)
	}

	m.countryStats.counts = make(map[string]int)
	for pType := range m.countryStats.proxies {
		m.countryStats.proxies[pType] = make(map[string]bool)
	}
	m.countryStats.unknown = make(map[string]bool)
	m.countryStats.natRestricted = make(map[string]bool)
	m.countryStats.natUnrestricted = make(map[string]bool)
	m.countryStats.natUnknown = make(map[string]bool)
}

// Rounds up a count to the nearest multiple of 8.
func binCount(count uint) uint {
	return uint((math.Ceil(float64(count) / 8)) * 8)
}

func sumMapValues(m *map[messages.RendezvousMethod]uint) uint {
	var s uint = 0
	for _, v := range *m {
		s += v
	}
	return s
}

type PromMetrics struct {
	registry         *prometheus.Registry
	ProxyTotal       *prometheus.CounterVec
	ProxyPollTotal   *safeprom.CounterVec
	ClientPollTotal  *safeprom.CounterVec
	AvailableProxies *prometheus.GaugeVec

	ProxyPollWithRelayURLExtensionTotal    *safeprom.CounterVec
	ProxyPollWithoutRelayURLExtensionTotal *safeprom.CounterVec

	ProxyPollRejectedForRelayURLExtensionTotal *safeprom.CounterVec
}

// Initialize metrics for prometheus exporter
func initPrometheus() *PromMetrics {
	promMetrics := &PromMetrics{}

	promMetrics.registry = prometheus.NewRegistry()

	promMetrics.ProxyTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Name:      "proxy_total",
			Help:      "The number of unique snowflake IPs",
		},
		[]string{"type", "nat", "cc"},
	)

	promMetrics.AvailableProxies = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: prometheusNamespace,
			Name:      "available_proxies",
			Help:      "The number of currently available snowflake proxies",
		},
		[]string{"type", "nat"},
	)

	promMetrics.ProxyPollTotal = safeprom.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Name:      "rounded_proxy_poll_total",
			Help:      "The number of snowflake proxy polls, rounded up to a multiple of 8",
		},
		[]string{"nat", "status"},
	)

	promMetrics.ProxyPollWithRelayURLExtensionTotal = safeprom.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Name:      "rounded_proxy_poll_with_relay_url_extension_total",
			Help:      "The number of snowflake proxy polls with Relay URL Extension, rounded up to a multiple of 8",
		},
		[]string{"nat", "type"},
	)

	promMetrics.ProxyPollWithoutRelayURLExtensionTotal = safeprom.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Name:      "rounded_proxy_poll_without_relay_url_extension_total",
			Help:      "The number of snowflake proxy polls without Relay URL Extension, rounded up to a multiple of 8",
		},
		[]string{"nat", "type"},
	)

	promMetrics.ProxyPollRejectedForRelayURLExtensionTotal = safeprom.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Name:      "rounded_proxy_poll_rejected_relay_url_extension_total",
			Help:      "The number of snowflake proxy polls rejected by Relay URL Extension, rounded up to a multiple of 8",
		},
		[]string{"nat", "type"},
	)

	promMetrics.ClientPollTotal = safeprom.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Name:      "rounded_client_poll_total",
			Help:      "The number of snowflake client polls, rounded up to a multiple of 8",
		},
		[]string{"nat", "status", "cc", "rendezvous_method"},
	)

	// We need to register our metrics so they can be exported.
	promMetrics.registry.MustRegister(
		promMetrics.ClientPollTotal, promMetrics.ProxyPollTotal,
		promMetrics.ProxyTotal, promMetrics.AvailableProxies,
		promMetrics.ProxyPollWithRelayURLExtensionTotal,
		promMetrics.ProxyPollWithoutRelayURLExtensionTotal,
		promMetrics.ProxyPollRejectedForRelayURLExtensionTotal,
	)

	return promMetrics
}
