/*
Broker acts as the HTTP signaling channel.
It matches clients and snowflake proxies by passing corresponding
SessionDescriptions in order to negotiate a WebRTC connection.
*/
package main

import (
	"container/heap"
	"flag"
	"io"
	"log"
	"net"
	"net/rpc"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"git.torproject.org/pluggable-transports/snowflake.git/common/safelog"
	// "github.com/prometheus/client_golang/prometheus"
)

type BrokerContext struct {
	snowflakes           *SnowflakeHeap
	restrictedSnowflakes *SnowflakeHeap
	// Maps keeping track of snowflakeIDs required to match SDP answers from
	// the second http POST. Restricted snowflakes can only be matched up with
	// clients behind an unrestricted NAT.
	idToSnowflake map[string]*Snowflake
	// Synchronization for the snowflake map and heap
	snowflakeLock sync.Mutex
	proxyPolls    chan *ProxyPoll
	metrics       *Metrics
}

func NewBrokerContext(metricsLogger *log.Logger) *BrokerContext {
	snowflakes := new(SnowflakeHeap)
	heap.Init(snowflakes)
	rSnowflakes := new(SnowflakeHeap)
	heap.Init(rSnowflakes)
	metrics, err := NewMetrics(metricsLogger)

	if err != nil {
		panic(err.Error())
	}

	if metrics == nil {
		panic("Failed to create metrics")
	}

	return &BrokerContext{
		snowflakes:           snowflakes,
		restrictedSnowflakes: rSnowflakes,
		idToSnowflake:        make(map[string]*Snowflake),
		proxyPolls:           make(chan *ProxyPoll),
		metrics:              metrics,
	}
}

// Proxies may poll for client offers concurrently.
type ProxyPoll struct {
	id           string
	proxyType    string
	natType      string
	offerChannel chan *ClientOffer
}

// Registers a Snowflake and waits for some Client to send an offer,
// as part of the polling logic of the proxy handler.
func (ctx *BrokerContext) RequestOffer(id string, proxyType string, natType string) *ClientOffer {
	request := new(ProxyPoll)
	request.id = id
	request.proxyType = proxyType
	request.natType = natType
	request.offerChannel = make(chan *ClientOffer)
	ctx.proxyPolls <- request
	// Block until an offer is available, or timeout which sends a nil offer.
	offer := <-request.offerChannel
	return offer
}

// goroutine which matches clients to proxies and sends SDP offers along.
// Safely processes proxy requests, responding to them with either an available
// client offer or nil on timeout / none are available.
func (ctx *BrokerContext) Broker() {
	for request := range ctx.proxyPolls {
		snowflake := ctx.AddSnowflake(request.id, request.proxyType, request.natType)
		// Wait for a client to avail an offer to the snowflake.
		go func(request *ProxyPoll) {
			select {
			case offer := <-snowflake.offerChannel:
				request.offerChannel <- offer
			case <-time.After(time.Second * ProxyTimeout):
				// This snowflake is no longer available to serve clients.
				ctx.snowflakeLock.Lock()
				defer ctx.snowflakeLock.Unlock()
				if snowflake.index != -1 {
					if request.natType == NATUnrestricted {
						heap.Remove(ctx.snowflakes, snowflake.index)
					} else {
						heap.Remove(ctx.restrictedSnowflakes, snowflake.index)
					}
					// ctx.metrics.promMetrics.AvailableProxies.With(prometheus.Labels{"nat": request.natType, "type": request.proxyType}).Dec()
					delete(ctx.idToSnowflake, snowflake.id)
					close(request.offerChannel)
				}
			}
		}(request)
	}
}

// Create and add a Snowflake to the heap.
// Required to keep track of proxies between providing them
// with an offer and awaiting their second POST with an answer.
func (ctx *BrokerContext) AddSnowflake(id string, proxyType string, natType string) *Snowflake {
	snowflake := new(Snowflake)
	snowflake.id = id
	snowflake.clients = 0
	snowflake.proxyType = proxyType
	snowflake.natType = natType
	snowflake.offerChannel = make(chan *ClientOffer)
	snowflake.answerChannel = make(chan string)
	ctx.snowflakeLock.Lock()
	if natType == NATUnrestricted {
		heap.Push(ctx.snowflakes, snowflake)
	} else {
		heap.Push(ctx.restrictedSnowflakes, snowflake)
	}
	// ctx.metrics.promMetrics.AvailableProxies.With(prometheus.Labels{"nat": natType, "type": proxyType}).Inc()
	ctx.snowflakeLock.Unlock()
	ctx.idToSnowflake[id] = snowflake
	return snowflake
}

// Client offer contains an SDP and the NAT type of the client
type ClientOffer struct {
	natType string
	sdp     []byte
}

func main() {
	var geoipDatabase string
	var geoip6Database string
	var disableGeoip bool

	var metricsFilename string
	var unsafeLogging bool

	var socket string

	flag.StringVar(&geoipDatabase, "geoipdb", "/usr/share/tor/geoip", "path to correctly formatted geoip database mapping IPv4 address ranges to country codes")
	flag.StringVar(&geoip6Database, "geoip6db", "/usr/share/tor/geoip6", "path to correctly formatted geoip database mapping IPv6 address ranges to country codes")
	flag.BoolVar(&disableGeoip, "disable-geoip", false, "don't use geoip for stats collection")

	flag.StringVar(&metricsFilename, "metrics-log", "", "path to metrics logging output")
	flag.BoolVar(&unsafeLogging, "unsafe-logging", false, "prevent logs from being scrubbed")

	flag.StringVar(&socket, "socket", "/tmp/broker.sock", "path to ipc socket")

	flag.Parse()

	var err error
	var metricsFile io.Writer

	var logOutput io.Writer = os.Stderr
	if unsafeLogging {
		log.SetOutput(logOutput)
	} else {
		// We want to send the log output through our scrubber first
		log.SetOutput(&safelog.LogScrubber{Output: logOutput})
	}
	log.SetFlags(log.LstdFlags | log.LUTC)

	if metricsFilename != "" {
		metricsFile, err = os.OpenFile(metricsFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

		if err != nil {
			log.Fatal(err.Error())
		}
	} else {
		metricsFile = os.Stdout
	}

	metricsLogger := log.New(metricsFile, "", 0)

	ctx := NewBrokerContext(metricsLogger)

	if !disableGeoip {
		err = ctx.metrics.LoadGeoipDatabases(geoipDatabase, geoip6Database)
		if err != nil {
			log.Fatal(err.Error())
		}
	}

	go ctx.Broker()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	// go routine to handle a SIGHUP signal to allow the broker operator to send
	// a SIGHUP signal when the geoip database files are updated, without requiring
	// a restart of the broker
	go func() {
		for {
			signal := <-sigChan
			log.Printf("Received signal: %s. Reloading geoip databases.", signal)
			if err = ctx.metrics.LoadGeoipDatabases(geoipDatabase, geoip6Database); err != nil {
				log.Fatalf("reload of Geo IP databases on signal %s returned error: %v", signal, err)
			}
		}
	}()

	// if err := os.RemoveAll(socket); err != nil {
	// 	log.Fatal(err)
	// }

	ipc := &IPC{ctx}
	rpc.Register(ipc)

	l, err := net.Listen("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	rpc.Accept(l)
}
