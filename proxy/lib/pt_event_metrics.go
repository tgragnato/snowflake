package snowflake_proxy

import (
	"tgragnato.it/snowflake/common/event"
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
	switch v := e.(type) {
	case event.EventOnProxyStats:
		em.collector.TrackInBoundTraffic(v.InboundBytes)
		em.collector.TrackOutBoundTraffic(v.OutboundBytes)
	case event.EventOnProxyConnectionOver:
		em.collector.TrackNewConnection()
	}
}
