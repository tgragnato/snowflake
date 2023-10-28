package snowflake_proxy

import (
	"fmt"
	"io"
	"log"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/task"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
)

func NewProxyEventLogger(output io.Writer) event.SnowflakeEventReceiver {
	logger := log.New(output, "", log.LstdFlags|log.LUTC)
	return &proxyEventLogger{logger: logger}
}

type proxyEventLogger struct {
	logger *log.Logger
}

func (p *proxyEventLogger) OnNewSnowflakeEvent(e event.SnowflakeEvent) {
	p.logger.Println(e.String())
}

type periodicProxyStats struct {
	inboundSum      int64
	outboundSum     int64
	connectionCount int
	logPeriod       time.Duration
	task            *task.Periodic
	dispatcher      event.SnowflakeEventDispatcher
}

func newPeriodicProxyStats(logPeriod time.Duration, dispatcher event.SnowflakeEventDispatcher) *periodicProxyStats {
	el := &periodicProxyStats{logPeriod: logPeriod, dispatcher: dispatcher}
	el.task = &task.Periodic{Interval: logPeriod, Execute: el.logTick}
	el.task.WaitThenStart()
	return el
}

func (p *periodicProxyStats) OnNewSnowflakeEvent(e event.SnowflakeEvent) {
	switch e.(type) {
	case event.EventOnProxyConnectionOver:
		e := e.(event.EventOnProxyConnectionOver)
		p.inboundSum += e.InboundTraffic
		p.outboundSum += e.OutboundTraffic
		p.connectionCount += 1
	}
}

func (p *periodicProxyStats) logTick() error {
	inbound, inboundUnit := formatTraffic(p.inboundSum)
	outbound, outboundUnit := formatTraffic(p.outboundSum)
	statString := fmt.Sprintf("In the last %v, there were %v connections. Traffic Relayed ↓ %v %v, ↑ %v %v.\n",
		p.logPeriod.String(), p.connectionCount, inbound, inboundUnit, outbound, outboundUnit)
	p.dispatcher.OnNewSnowflakeEvent(&event.EventOnProxyStats{StatString: statString})
	p.outboundSum = 0
	p.inboundSum = 0
	p.connectionCount = 0
	return nil
}

func (p *periodicProxyStats) Close() error {
	return p.task.Close()
}
