package snowflake_proxy

import (
	"github.com/tgragnato/snowflake.git/v2/common/event"
)

type EventCollector interface {
	TrackInBoundTraffic(value int64)
	TrackOutBoundTraffic(value int64)
	TrackNewConnection()
}

type EventMetrics struct {
	collector EventCollector
}

func NewEventMetrics(collector EventCollector) *EventMetrics {
	return &EventMetrics{collector: collector}
}

func (em *EventMetrics) OnNewSnowflakeEvent(e event.SnowflakeEvent) {
	switch e.(type) {
	case event.EventOnProxyStats:
		e := e.(event.EventOnProxyStats)
		em.collector.TrackInBoundTraffic(e.InboundBytes)
		em.collector.TrackOutBoundTraffic(e.OutboundBytes)
	case event.EventOnProxyConnectionOver:
		em.collector.TrackNewConnection()
	}
}
