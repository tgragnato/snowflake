package snowflake_proxy

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// metricNamespace represent prometheus namespace
	metricNamespace = "tor_snowflake_proxy"
)

type Metrics struct {
	totalInBoundTraffic  prometheus.Counter
	totalOutBoundTraffic prometheus.Counter
	totalConnections     prometheus.Counter
}

func NewMetrics() *Metrics {
	return &Metrics{
		totalConnections: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "connections_total",
			Help:      "The total number of connections handled by the snowflake proxy",
		}),
		totalInBoundTraffic: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "traffic_inbound_bytes_total",
			Help:      "The total in bound traffic by the snowflake proxy (KB)",
		}),
		totalOutBoundTraffic: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "traffic_outbound_bytes_total",
			Help:      "The total out bound traffic by the snowflake proxy (KB)",
		}),
	}
}

// Start register the metrics server and serve them on the given address
func (m *Metrics) Start(addr string) error {
	go func() {
		http.Handle("/internal/metrics", promhttp.Handler())
		if err := http.ListenAndServe(addr, nil); err != nil {
			panic(err)
		}
	}()

	return prometheus.Register(m)
}

func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	m.totalConnections.Collect(ch)
	m.totalInBoundTraffic.Collect(ch)
	m.totalOutBoundTraffic.Collect(ch)
}

func (m *Metrics) Describe(descs chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(m, descs)
}

// TrackInBoundTraffic counts the received traffic by the snowflake proxy
func (m *Metrics) TrackInBoundTraffic(value int64) {
	m.totalInBoundTraffic.Add(float64(value))
}

// TrackOutBoundTraffic counts the transmitted traffic by the snowflake proxy
func (m *Metrics) TrackOutBoundTraffic(value int64) {
	m.totalOutBoundTraffic.Add(float64(value))
}

// TrackNewConnection counts the new connections
func (m *Metrics) TrackNewConnection() {
	m.totalConnections.Inc()
}
