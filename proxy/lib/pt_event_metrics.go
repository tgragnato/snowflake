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
	case event.EventOnProxyConnectionOver:
		e := e.(event.EventOnProxyConnectionOver)
		em.collector.TrackInBoundTraffic(e.InboundTraffic)
		em.collector.TrackOutBoundTraffic(e.OutboundTraffic)
		em.collector.TrackNewConnection()
	}
}
