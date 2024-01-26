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

	"github.com/tgragnato/snowflake/common/event"
	"github.com/tgragnato/snowflake/common/safelog"
	"github.com/tgragnato/snowflake/common/version"
	sf "github.com/tgragnato/snowflake/proxy/lib"
)

func main() {
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
	NATTypeForceUnrestricted := flag.Bool("nat-type-force-unrestricted", false, "force the NAT type as unrestricted")
	NATTypeMeasurementInterval := flag.Duration("nat-retest-interval", time.Hour*24,
		"the time interval in second before NAT type is retested, 0s disables retest. Valid time units are \"s\", \"m\", \"h\". ")
	summaryInterval := flag.Duration("summary-interval", time.Hour,
		"the time interval to output summary, 0s disables summaries. Valid time units are \"s\", \"m\", \"h\". ")
	disableStatsLogger := flag.Bool("disable-stats-logger", false, "disable the exposing mechanism for stats using logs")
	enableMetrics := flag.Bool("metrics", false, "enable the exposing mechanism for stats using metrics")
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
		STUNURL:            *stunURL,
		BrokerURL:          *rawBrokerURL,
		KeepLocalAddresses: *keepLocalAddresses,
		RelayURL:           *relayURL,
		NATProbeURL:        *probeURL,
		OutboundAddress:    *outboundAddress,
		EphemeralMinPort:   ephemeralPortsRange[0],
		EphemeralMaxPort:   ephemeralPortsRange[1],

		NATTypeForceUnrestricted:   *NATTypeForceUnrestricted,
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

		err := metrics.Start(net.JoinHostPort("localhost", strconv.Itoa(*metricsPort)))
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
