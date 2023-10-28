package snowflake_proxy

import (
	"time"
)

// bytesLogger is an interface which is used to allow logging the throughput
// of the Snowflake. A default bytesLogger(bytesNullLogger) does nothing.
type bytesLogger interface {
	AddOutbound(int64)
	AddInbound(int64)
	GetStat() (in int64, out int64)
}

// bytesNullLogger Default bytesLogger does nothing.
type bytesNullLogger struct{}

// AddOutbound in bytesNullLogger does nothing
func (b bytesNullLogger) AddOutbound(amount int64) {}

// AddInbound in bytesNullLogger does nothing
func (b bytesNullLogger) AddInbound(amount int64) {}

func (b bytesNullLogger) GetStat() (in int64, out int64) { return -1, -1 }

// bytesSyncLogger uses channels to safely log from multiple sources with output
// occuring at reasonable intervals.
type bytesSyncLogger struct {
	outboundChan, inboundChan chan int64
	outbound, inbound         int64
	outEvents, inEvents       int
	start                     time.Time
}

// newBytesSyncLogger returns a new bytesSyncLogger and starts it loggin.
func newBytesSyncLogger() *bytesSyncLogger {
	b := &bytesSyncLogger{
		outboundChan: make(chan int64, 5),
		inboundChan:  make(chan int64, 5),
	}
	go b.log()
	b.start = time.Now()
	return b
}

func (b *bytesSyncLogger) log() {
	for {
		select {
		case amount := <-b.outboundChan:
			b.outbound += amount
			b.outEvents++
		case amount := <-b.inboundChan:
			b.inbound += amount
			b.inEvents++
		}
	}
}

// AddOutbound add a number of bytes to the outbound total reported by the logger
func (b *bytesSyncLogger) AddOutbound(amount int64) {
	b.outboundChan <- amount
}

// AddInbound add a number of bytes to the inbound total reported by the logger
func (b *bytesSyncLogger) AddInbound(amount int64) {
	b.inboundChan <- amount
}

func (b *bytesSyncLogger) GetStat() (in int64, out int64) { return b.inbound, b.outbound }

func formatTraffic(amount int64) (value int64, unit string) { return amount / 1000, "KB" }
