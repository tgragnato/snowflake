package snowflake_proxy

import (
	"fmt"
	"io"
	"log"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/task"
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
	bytesLogger     bytesLogger
	connectionCount int
	logPeriod       time.Duration
	task            *task.Periodic
	dispatcher      event.SnowflakeEventDispatcher
}

func newPeriodicProxyStats(logPeriod time.Duration, dispatcher event.SnowflakeEventDispatcher, bytesLogger bytesLogger) *periodicProxyStats {
	el := &periodicProxyStats{logPeriod: logPeriod, dispatcher: dispatcher, bytesLogger: bytesLogger}
	el.task = &task.Periodic{Interval: logPeriod, Execute: el.logTick}
	el.task.WaitThenStart()
	return el
}

func (p *periodicProxyStats) OnNewSnowflakeEvent(e event.SnowflakeEvent) {
	switch e.(type) {
	case event.EventOnProxyConnectionOver:
		p.connectionCount += 1
	}
}

func (p *periodicProxyStats) logTick() error {
	inboundSum, outboundSum := p.bytesLogger.GetStat()
	inbound, inboundUnit := formatTraffic(inboundSum)
	outbound, outboundUnit := formatTraffic(outboundSum)
	statString := fmt.Sprintf("In the last %v, there were %v completed connections. Traffic Relayed ↓ %v %v, ↑ %v %v.",
		p.logPeriod.String(), p.connectionCount, inbound, inboundUnit, outbound, outboundUnit)
	p.dispatcher.OnNewSnowflakeEvent(&event.EventOnProxyStats{StatString: statString})
	p.connectionCount = 0
	return nil
}

func (p *periodicProxyStats) Close() error {
	return p.task.Close()
}
