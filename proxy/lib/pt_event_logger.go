package snowflake_proxy

import (
	"io"
	"log"
	"time"

	"github.com/tgragnato/snowflake.git/v2/common/event"
	"github.com/tgragnato/snowflake.git/v2/common/task"
)

func NewProxyEventLogger(output io.Writer, disableStats bool) event.SnowflakeEventReceiver {
	logger := log.New(output, "", log.LstdFlags|log.LUTC)
	return &proxyEventLogger{logger: logger, disableStats: disableStats}
}

type proxyEventLogger struct {
	logger       *log.Logger
	disableStats bool
}

func (p *proxyEventLogger) OnNewSnowflakeEvent(e event.SnowflakeEvent) {
	switch e.(type) {
	case event.EventOnProxyStats:
		if !p.disableStats {
			p.logger.Println(e.String())
		}
	default:
		p.logger.Println(e.String())
	}
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
	e := event.EventOnProxyStats{
		SummaryInterval: p.logPeriod,
		ConnectionCount: p.connectionCount,
	}
	e.InboundBytes, e.InboundUnit = formatTraffic(inboundSum)
	e.OutboundBytes, e.OutboundUnit = formatTraffic(outboundSum)
	p.dispatcher.OnNewSnowflakeEvent(e)
	p.connectionCount = 0
	return nil
}

func (p *periodicProxyStats) Close() error {
	return p.task.Close()
}
