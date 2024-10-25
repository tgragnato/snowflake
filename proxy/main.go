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
	stunURL := flag.String("stun", sf.DefaultSTUNURL, "Comma-separated STUN server `URL`s that this proxy will use will use to, among some other things, determine its public IP address")
	logFilename := flag.String("log", "", "log `filename`. If not specified, logs will be output to stderr (console).")
	rawBrokerURL := flag.String("broker", sf.DefaultBrokerURL, "The `URL` of the broker server that the proxy will be using to find clients")
	unsafeLogging := flag.Bool("unsafe-logging", false, "keep IP addresses and other sensitive info in the logs")
	logLocalTime := flag.Bool("log-local-time", false, "Use local time for logging (default: UTC)")
	keepLocalAddresses := flag.Bool("keep-local-addresses", false, "keep local LAN address ICE candidates.\nThis is usually pointless because Snowflake clients don't usually reside on the same local network as the proxy.")
	defaultRelayURL := flag.String("relay", sf.DefaultRelayURL, "The default `URL` of the server (relay) that this proxy will forward client connections to, in case the broker itself did not specify the said URL")
	probeURL := flag.String("nat-probe-server", sf.DefaultNATProbeURL, "The `URL` of the server that this proxy will use to check its network NAT type.\nDetermining NAT type helps to understand whether this proxy is compatible with certain clients' NAT")
	outboundAddress := flag.String("outbound-address", "", "prefer the given `address` as outbound address for client connections")
	allowedRelayHostNamePattern := flag.String("allowed-relay-hostname-pattern", "snowflake.torproject.net$", "this proxy will only be allowed to forward client connections to relays (servers) whose URL matches this pattern.\nNote that a pattern \"example.com$\" will match \"subdomain.example.com\" as well as \"other-domain-example.com\".\nIn order to only match \"example.com\", prefix the pattern with \"^\": \"^example.com$\"")
	allowProxyingToPrivateAddresses := flag.Bool("allow-proxying-to-private-addresses", false, "allow forwarding client connections to private IP addresses.\nUseful when a Snowflake server (relay) is hosted on the same private network as this proxy.")
	allowNonTLSRelay := flag.Bool("allow-non-tls-relay", false, "allow this proxy to pass client's data to the relay in an unencrypted form.\nThis is only useful if the relay doesn't support encryption, e.g. for testing / development purposes.")
	NATTypeMeasurementInterval := flag.Duration("nat-retest-interval", time.Hour*24,
		"the time interval between NAT type is retests (see \"nat-probe-server\"). 0s disables retest. Valid time units are \"s\", \"m\", \"h\".")
	summaryInterval := flag.Duration("summary-interval", time.Hour,
		"the time interval between summary log outputs, 0s disables summaries. Valid time units are \"s\", \"m\", \"h\".")
	disableStatsLogger := flag.Bool("disable-stats-logger", false, "disable the exposing mechanism for stats using logs")
	enableMetrics := flag.Bool("metrics", false, "enable the exposing mechanism for stats using metrics")
	metricsAddress := flag.String("metrics-address", "localhost", "set listen `address` for metrics service")
	metricsPort := flag.Int("metrics-port", 9999, "set port for the metrics service")
	verboseLogging := flag.Bool("verbose", false, "increase log verbosity")
	ephemeralPortsRangeFlag := flag.String("ephemeral-ports-range", "", "Set the `range` of ports used for client connections (format:\"<min>:<max>\").\nIf omitted, the ports will be chosen automatically.")
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
		RelayURL:           *defaultRelayURL,
		NATProbeURL:        *probeURL,
		OutboundAddress:    *outboundAddress,
		EphemeralMinPort:   ephemeralPortsRange[0],
		EphemeralMaxPort:   ephemeralPortsRange[1],

		NATTypeMeasurementInterval: *NATTypeMeasurementInterval,
		EventDispatcher:            eventLogger,

		RelayDomainNamePattern:          *allowedRelayHostNamePattern,
		AllowProxyingToPrivateAddresses: *allowProxyingToPrivateAddresses,
		AllowNonTLSRelay:                *allowNonTLSRelay,

		SummaryInterval: *summaryInterval,
	}

	var logOutput = io.Discard
	var eventlogOutput io.Writer = os.Stderr

	loggerFlags := log.LstdFlags

	if !*logLocalTime {
		loggerFlags |= log.LUTC
	}

	log.SetFlags(loggerFlags)

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
