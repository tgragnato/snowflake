package snowflake_proxy

import (
	"io"
	"log"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/task"
)

func NewProxyEventLogger(output io.Writer, disableStats bool) event.SnowflakeEventReceiver {
	logger := log.New(output, "", log.Flags())
	return &proxyEventLogger{logger: logger, disableStats: disableStats}
}

type proxyEventLogger struct {
	logger       *log.Logger
	disableStats bool
}

func (p *proxyEventLogger) OnNewSnowflakeEvent(e event.SnowflakeEvent) {
	switch e.(type) {
	case event.EventOnProxyStarting:
		p.logger.Println(e.String())

		if p.logger.Flags()&log.LUTC == 0 {
			p.logger.Println("Local time is being used for logging. If you want to " +
				"share your log, consider to modify the date/time for more anonymity.")
		}
	case event.EventOnProxyStats:
		if !p.disableStats {
			p.logger.Println(e.String())
		}
	case event.EventOnProxyConnectionOver:
		// Suppress logs of this event
		// https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/issues/40310
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
