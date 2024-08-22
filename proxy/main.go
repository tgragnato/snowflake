package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/ptutil/safelog"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/version"
	sf "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/proxy/lib"
)

const minPollInterval = 2 * time.Second

func main() {
	pollInterval := flag.Duration("poll-interval", sf.DefaultPollInterval,
		fmt.Sprint("how often to ask the broker for a new client. Keep in mind that asking for a client will not always result in getting one. Minumum value is ", minPollInterval, ". Valid time units are \"ms\", \"s\", \"m\", \"h\"."))
	capacity := flag.Uint("capacity", 0, "maximum concurrent clients (default is to accept an unlimited number of clients)")
	stunURL := flag.String("stun", sf.DefaultSTUNURL, "STUN URL")
	logFilename := flag.String("log", "", "log filename")
	rawBrokerURL := flag.String("broker", sf.DefaultBrokerURL, "broker URL")
	unsafeLogging := flag.Bool("unsafe-logging", false, "prevent logs from being scrubbed")
	keepLocalAddresses := flag.Bool("keep-local-addresses", false, "keep local LAN address ICE candidates")
	relayURL := flag.String("relay", sf.DefaultRelayURL, "websocket relay URL")
	probeURL := flag.String("nat-probe-server", sf.DefaultNATProbeURL, "NAT check probe server URL")
	outboundAddress := flag.String("outbound-address", "", "prefer the given address as outbound address")
	allowedRelayHostNamePattern := flag.String("allowed-relay-hostname-pattern", "snowflake.torproject.net$", "a pattern to specify allowed hostname pattern for relay URL.")
	allowNonTLSRelay := flag.Bool("allow-non-tls-relay", false, "allow relay without tls encryption")
	NATTypeMeasurementInterval := flag.Duration("nat-retest-interval", time.Hour*24,
		"the time interval in second before NAT type is retested, 0s disables retest. Valid time units are \"s\", \"m\", \"h\". ")
	summaryInterval := flag.Duration("summary-interval", time.Hour,
		"the time interval to output summary, 0s disables summaries. Valid time units are \"s\", \"m\", \"h\". ")
	disableStatsLogger := flag.Bool("disable-stats-logger", false, "disable the exposing mechanism for stats using logs")
	enableMetrics := flag.Bool("metrics", false, "enable the exposing mechanism for stats using metrics")
	metricsAddress := flag.String("metrics-address", "localhost", "set listen address for metrics service")
	metricsPort := flag.Int("metrics-port", 9999, "set port for the metrics service")
	verboseLogging := flag.Bool("verbose", false, "increase log verbosity")
	ephemeralPortsRangeFlag := flag.String("ephemeral-ports-range", "", "ICE UDP ephemeral ports range (format:\"<min>:<max>\")")
	versionFlag := flag.Bool("version", false, "display version info to stderr and quit")

	var ephemeralPortsRange []uint16 = []uint16{0, 0}

	flag.Parse()

	if *versionFlag {
		fmt.Fprintf(os.Stderr, "snowflake-proxy %s", version.ConstructResult())
		os.Exit(0)
	}

	if *pollInterval < minPollInterval {
		log.Fatalf("poll-interval must be >= %v", minPollInterval)
	}

	if *outboundAddress != "" && *keepLocalAddresses {
		log.Fatal("Cannot keep local address candidates when outbound address is specified")
	}

	eventLogger := event.NewSnowflakeEventDispatcher()

	if *ephemeralPortsRangeFlag != "" {
		ephemeralPortsRangeParts := strings.Split(*ephemeralPortsRangeFlag, ":")
		if len(ephemeralPortsRangeParts) == 2 {
			ephemeralMinPort, err := strconv.ParseUint(ephemeralPortsRangeParts[0], 10, 16)
			if err != nil {
				log.Fatal(err)
			}

			ephemeralMaxPort, err := strconv.ParseUint(ephemeralPortsRangeParts[1], 10, 16)
			if err != nil {
				log.Fatal(err)
			}

			if ephemeralMinPort == 0 || ephemeralMaxPort == 0 {
				log.Fatal("Ephemeral port cannot be zero")
			}
			if ephemeralMinPort > ephemeralMaxPort {
				log.Fatal("Invalid port range: min > max")
			}

			ephemeralPortsRange = []uint16{uint16(ephemeralMinPort), uint16(ephemeralMaxPort)}
		} else {
			log.Fatalf("Bad range port format: %v", *ephemeralPortsRangeFlag)
		}
	}

	proxy := sf.SnowflakeProxy{
		PollInterval:       *pollInterval,
		Capacity:           uint(*capacity),
		STUNURL:            *stunURL,
		BrokerURL:          *rawBrokerURL,
		KeepLocalAddresses: *keepLocalAddresses,
		RelayURL:           *relayURL,
		NATProbeURL:        *probeURL,
		OutboundAddress:    *outboundAddress,
		EphemeralMinPort:   ephemeralPortsRange[0],
		EphemeralMaxPort:   ephemeralPortsRange[1],

		NATTypeMeasurementInterval: *NATTypeMeasurementInterval,
		EventDispatcher:            eventLogger,

		RelayDomainNamePattern: *allowedRelayHostNamePattern,
		AllowNonTLSRelay:       *allowNonTLSRelay,

		SummaryInterval: *summaryInterval,
	}

	var logOutput = io.Discard
	var eventlogOutput io.Writer = os.Stderr
	log.SetFlags(log.LstdFlags | log.LUTC)

	if *verboseLogging {
		logOutput = os.Stderr
	}

	if *logFilename != "" {
		f, err := os.OpenFile(*logFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		if *verboseLogging {
			logOutput = io.MultiWriter(logOutput, f)
		}
		eventlogOutput = io.MultiWriter(eventlogOutput, f)
	}

	if *unsafeLogging {
		log.SetOutput(logOutput)
	} else {
		log.SetOutput(&safelog.LogScrubber{Output: logOutput})
	}

	proxyEventLogger := sf.NewProxyEventLogger(eventlogOutput, *disableStatsLogger)
	eventLogger.AddSnowflakeEventListener(proxyEventLogger)

	if *enableMetrics {
		metrics := sf.NewMetrics()

		err := metrics.Start(net.JoinHostPort(*metricsAddress, strconv.Itoa(*metricsPort)))
		if err != nil {
			log.Fatalf("could not enable metrics: %v", err)
		}

		eventLogger.AddSnowflakeEventListener(sf.NewEventMetrics(metrics))
	}

	log.Printf("snowflake-proxy %s\n", version.GetVersion())

	err := proxy.Start()
	if err != nil {
		log.Fatal(err)
	}
}
