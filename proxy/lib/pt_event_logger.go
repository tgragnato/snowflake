package snowflake_proxy

import (
	"io"
	"log"
	"sync/atomic"
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
	case event.EventOnCurrentNATTypeDetermined:
		p.logger.Println(e.String())
	default:
		// Suppress logs of these events
		// https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/issues/40310
		// https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/issues/40413
	}
}

type periodicProxyStats struct {
	bytesLogger bytesLogger
	// Completed successful connections.
	connectionCount atomic.Int32
	// Connections that failed to establish.
	failedConnectionCount atomic.Uint32
	logPeriod             time.Duration
	task                  *task.Periodic
	dispatcher            event.SnowflakeEventDispatcher
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
		p.connectionCount.Add(1)
	case event.EventOnProxyConnectionFailed:
		p.failedConnectionCount.Add(1)
	}
}

func (p *periodicProxyStats) logTick() error {
	inboundSum, outboundSum := p.bytesLogger.GetStat()
	e := event.EventOnProxyStats{
		SummaryInterval:       p.logPeriod,
		ConnectionCount:       int(p.connectionCount.Swap(0)),
		FailedConnectionCount: uint(p.failedConnectionCount.Swap(0)),
	}
	e.InboundBytes, e.InboundUnit = formatTraffic(inboundSum)
	e.OutboundBytes, e.OutboundUnit = formatTraffic(outboundSum)
	p.dispatcher.OnNewSnowflakeEvent(e)
	return nil
}

func (p *periodicProxyStats) Close() error {
	return p.task.Close()
}
