/*
Broker acts as the HTTP signaling channel.
It matches clients and snowflake proxies by passing corresponding
SessionDescriptions in order to negotiate a WebRTC connection.
*/
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/ptutil/safelog"
	"tgragnato.it/snowflake/common/ipsetsink/sinkcluster"
	"golang.org/x/crypto/acme/autocert"
	"tgragnato.it/snowflake/common/bridgefingerprint"
	"tgragnato.it/snowflake/common/namematcher"
)

type BrokerContext struct {
	unrestrictedPool *SnowflakePool
	restrictedPool   *SnowflakePool
	// Maps keeping track of snowflakeIDs required to match SDP answers from
	// the second http POST. Restricted snowflakes can only be matched up with
	// clients behind an unrestricted NAT.
	idToSnowflake map[string]*Snowflake
	// Synchronization for the snowflake map
	snowflakeLock sync.Mutex
	proxyPolls    chan *ProxyPoll
	metrics       *Metrics

	bridgeList          BridgeListHolderFileBased
	allowedRelayPattern string
}

func (ctx *BrokerContext) GetBridgeInfo(fingerprint bridgefingerprint.Fingerprint) (BridgeInfo, error) {
	return ctx.bridgeList.GetBridgeInfo(fingerprint)
}

func NewBrokerContext(
	metricsLogger *log.Logger,
	allowedRelayPattern string,
) *BrokerContext {
	metrics, err := NewMetrics(metricsLogger)

	if err != nil {
		panic(err.Error())
	}

	if metrics == nil {
		panic("Failed to create metrics")
	}

	bridgeListHolder := NewBridgeListHolder()

	const DefaultBridges = `{"displayName":"default", "webSocketAddress":"wss://snowflake.torproject.net/", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80A72"}
`
	bridgeListHolder.LoadBridgeInfo(bytes.NewReader([]byte(DefaultBridges)))

	return &BrokerContext{
		unrestrictedPool:    NewSnowflakePool(),
		restrictedPool:      NewSnowflakePool(),
		idToSnowflake:       make(map[string]*Snowflake),
		proxyPolls:          make(chan *ProxyPoll),
		metrics:             metrics,
		bridgeList:          bridgeListHolder,
		allowedRelayPattern: allowedRelayPattern,
	}
}

// Proxies may poll for client offers concurrently.
type ProxyPoll struct {
	id           string
	proxyType    string
	natType      string
	clients      uint64
	offerChannel chan *ClientOffer
}

// Registers a Snowflake and waits for some Client to send an offer,
// as part of the polling logic of the proxy handler.
func (ctx *BrokerContext) RequestOffer(poll *ProxyPoll) *ClientOffer {
	poll.offerChannel = make(chan *ClientOffer)
	ctx.proxyPolls <- poll
	// Block until an offer is available, or timeout which sends a nil offer.
	offer := <-poll.offerChannel
	return offer
}

// goroutine which matches clients to proxies and sends SDP offers along.
// Safely processes proxy requests, responding to them with either an available
// client offer or nil on timeout / none are available.
func (ctx *BrokerContext) Broker() {
	for request := range ctx.proxyPolls {
		pool := ctx.GetPool(request)
		snowflake := NewSnowflake(request.id, request.proxyType, request.natType, request.clients)
		pool.Push(snowflake)
		ctx.snowflakeLock.Lock()
		ctx.idToSnowflake[snowflake.id] = snowflake
		ctx.snowflakeLock.Unlock()
		// Wait for a client to avail an offer to the snowflake.
		go func(request *ProxyPoll) {
			select {
			case offer := <-snowflake.offerChannel:
				request.offerChannel <- offer
			case <-time.After(time.Second * ProxyTimeout):
				// This snowflake is no longer available to serve clients.
				pool.Remove(snowflake)
				ctx.snowflakeLock.Lock()
				delete(ctx.idToSnowflake, snowflake.id)
				ctx.snowflakeLock.Unlock()
				close(request.offerChannel)
			}
		}(request)
	}
}

func (ctx *BrokerContext) GetPool(poll *ProxyPoll) *SnowflakePool {
	if poll.natType == NATUnrestricted {
		return ctx.unrestrictedPool
	}
	return ctx.restrictedPool
}

func (ctx *BrokerContext) InstallBridgeListProfile(reader io.Reader) error {
	if err := ctx.bridgeList.LoadBridgeInfo(reader); err != nil {
		return err
	}
	return nil
}

func (ctx *BrokerContext) CheckProxyRelayPattern(pattern *string) bool {
	if pattern == nil {
		return false
	}
	proxyPattern := namematcher.NewNameMatcher(*pattern)
	brokerPattern := namematcher.NewNameMatcher(ctx.allowedRelayPattern)
	return proxyPattern.IsSupersetOf(brokerPattern)
}

type pollIntervalConfig struct {
	UnrestrictedPollInterval time.Duration `json:"unrestricted_poll_interval"`
	RestrictedPollInterval   time.Duration `json:"restricted_poll_interval"`
}

func (ctx *BrokerContext) LoadPollIntervalFromFile(filename string) error {
	var config pollIntervalConfig
	str, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(str, &config); err != nil {
		return err
	}
	ctx.unrestrictedPool.SetPollInterval(config.UnrestrictedPollInterval * time.Millisecond)
	ctx.restrictedPool.SetPollInterval(config.RestrictedPollInterval * time.Millisecond)
	log.Printf("Loaded unrestricted poll interval: %d ms", config.UnrestrictedPollInterval)
	log.Printf("Loaded restricted poll interval: %d ms", config.RestrictedPollInterval)
	return nil
}

// Client offer contains an SDP, bridge fingerprint and the NAT type of the client
type ClientOffer struct {
	natType     string
	sdp         []byte
	fingerprint []byte
}

func main() {
	var acmeEmail string
	var acmeHostnamesCommas string
	var acmeCertCacheDir string
	var addr string
	var geoipDatabase string
	var geoip6Database string
	var bridgeListFilePath, allowedRelayPattern string
	var brokerSQSQueueName, brokerSQSQueueRegion, sqsProfiles string
	var disableTLS bool
	var certFilename, keyFilename string
	var disableGeoip bool
	var metricsFilename string
	var ipCountPrefix string
	var ipCountInterval time.Duration
	var unsafeLogging bool
	var pollIntervalFilepath string

	flag.StringVar(&acmeEmail, "acme-email", "", "optional contact email for Let's Encrypt notifications")
	flag.StringVar(&acmeHostnamesCommas, "acme-hostnames", "", "comma-separated hostnames for TLS certificate")
	flag.StringVar(&certFilename, "cert", "", "TLS certificate file")
	flag.StringVar(&keyFilename, "key", "", "TLS private key file")
	flag.StringVar(&acmeCertCacheDir, "acme-cert-cache", "acme-cert-cache", "directory in which certificates should be cached")
	flag.StringVar(&addr, "addr", ":443", "address to listen on")
	flag.StringVar(&geoipDatabase, "geoipdb", "/usr/share/tor/geoip", "path to correctly formatted geoip database mapping IPv4 address ranges to country codes")
	flag.StringVar(&geoip6Database, "geoip6db", "/usr/share/tor/geoip6", "path to correctly formatted geoip database mapping IPv6 address ranges to country codes")
	flag.StringVar(&bridgeListFilePath, "bridge-list-path", "", "file path for bridgeListFile")
	flag.StringVar(&allowedRelayPattern, "allowed-relay-pattern", "", "allowed pattern for relay host name. The broker will reject proxies whose AcceptedRelayPattern is more restrictive than this")
	flag.StringVar(&brokerSQSQueueName, "broker-sqs-name", "", "name of broker SQS queue to listen for incoming messages on")
	flag.StringVar(&brokerSQSQueueRegion, "broker-sqs-region", "", "name of AWS region of broker SQS queue")
	flag.StringVar(&sqsProfiles, "sqs-profiles", "", "comma-separated list of AWS profiles for SQS credentials")
	flag.BoolVar(&disableTLS, "disable-tls", false, "don't use HTTPS")
	flag.BoolVar(&disableGeoip, "disable-geoip", false, "don't use geoip for stats collection")
	flag.StringVar(&metricsFilename, "metrics-log", "", "path to metrics logging output")
	flag.StringVar(&ipCountPrefix, "ip-count-prefix", "", "path prefix to ip count logging output")
	flag.DurationVar(&ipCountInterval, "ip-count-interval", time.Hour, "time interval between each chunk")
	flag.BoolVar(&unsafeLogging, "unsafe-logging", false, "prevent logs from being scrubbed")
	flag.StringVar(&pollIntervalFilepath, "poll-interval-filepath", "", "path to file with a poll interval")
	flag.Parse()

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
		var err error
		metricsFile, err = os.OpenFile(metricsFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

		if err != nil {
			log.Fatal(err.Error())
		}
	} else {
		metricsFile = os.Stdout
	}

	metricsLogger := log.New(metricsFile, "", 0)

	ctx := NewBrokerContext(metricsLogger, allowedRelayPattern)

	if bridgeListFilePath != "" {
		bridgeListFile, err := os.Open(bridgeListFilePath)
		if err != nil {
			log.Fatal(err.Error())
		}
		err = ctx.InstallBridgeListProfile(bridgeListFile)
		if err != nil {
			log.Fatal(err.Error())
		}
	}

	if !disableGeoip {
		err := ctx.metrics.LoadGeoipDatabases(geoipDatabase, geoip6Database)
		if err != nil {
			log.Fatal(err.Error())
		}
	}

	if ipCountPrefix != "" {
		var err error
		files := make(map[string]*os.File)
		for _, name := range []string{"restricted", "unrestricted",
			"standalone", "browser", "mobile", "unknown"} {

			files[name], err = os.OpenFile(fmt.Sprintf("%s-%s-%s.log", ipCountPrefix,
				name, time.Now().Format(time.RFC3339)), os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal(err.Error())
			}
		}

		var ipCountMaskingKey [32]byte
		if n, err := rand.Read(ipCountMaskingKey[:]); (n < 32) || (err != nil) {
			panic(err)
		}
		ctx.metrics.distinctIPWriter = sinkcluster.NewClusterWriter(
			map[string]sinkcluster.WriteSyncer{
				"restricted":   files["restricted"],
				"unrestricted": files["unrestricted"],
				"standalone":   files["standalone"],
				"browser":      files["browser"],
				"mobile":       files["mobile"],
				"unknown":      files["unknown"],
			}, ipCountMaskingKey, ipCountInterval)
	}
	if pollIntervalFilepath != "" {
		if err := ctx.LoadPollIntervalFromFile(pollIntervalFilepath); err != nil {
			log.Printf("failed to load poll interval from file: %s", err.Error())
		}
	}

	go ctx.Broker()

	i := &IPC{ctx}

	http.HandleFunc("/robots.txt", robotsTxtHandler)

	http.Handle("/proxy", SnowflakeHandler{i, proxyPolls})
	http.Handle("/client", SnowflakeHandler{i, clientOffers})
	http.Handle("/answer", SnowflakeHandler{i, proxyAnswers})
	http.Handle("/debug", SnowflakeHandler{i, debugHandler})
	http.Handle("/metrics", MetricsHandler{metricsFilename, metricsHandler})
	http.Handle("/prometheus", promhttp.HandlerFor(ctx.metrics.promMetrics.registry, promhttp.HandlerOpts{}))

	http.Handle("/amp/client/", SnowflakeHandler{i, ampClientOffers})

	server := http.Server{
		Addr:              addr,
		ReadHeaderTimeout: time.Second,
	}

	// Run SQS Handler to continuously poll and process messages from SQS
	if brokerSQSQueueName != "" && brokerSQSQueueRegion != "" {
		log.Printf("Loading SQSHandler using SQS Queue %s in region %s\n", brokerSQSQueueName, brokerSQSQueueRegion)
		sqsHandlerContext := context.Background()

		startSQS := func(cfg aws.Config) {
			client := sqs.NewFromConfig(cfg)
			sqsHandler, err := newSQSHandler(sqsHandlerContext, client, brokerSQSQueueName, brokerSQSQueueRegion, i)
			if err != nil {
				log.Fatal(err)
			}
			go sqsHandler.PollAndHandleMessages(sqsHandlerContext)
		}

		if sqsProfiles != "" {
			profiles := strings.Split(sqsProfiles, ",")
			for _, profile := range profiles {
				cfg, err := config.LoadDefaultConfig(sqsHandlerContext,
					config.WithSharedConfigProfile(profile))
				if err != nil {
					log.Fatal(err)
				}
				startSQS(cfg)
			}
		} else {
			cfg, err := config.LoadDefaultConfig(sqsHandlerContext, config.WithRegion(brokerSQSQueueRegion))
			if err != nil {
				log.Fatal(err)
			}
			startSQS(cfg)
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	// go routine to handle a SIGHUP signal to allow the broker operator to send
	// a SIGHUP signal when the geoip database files are updated, without requiring
	// a restart of the broker
	go func() {
		for {
			signal := <-sigChan
			log.Printf("Received signal: %s. Reloading geoip databases.", signal)
			if err := ctx.metrics.LoadGeoipDatabases(geoipDatabase, geoip6Database); err != nil {
				log.Fatalf("reload of Geo IP databases on signal %s returned error: %v", signal, err)
			}
			if pollIntervalFilepath != "" {
				log.Printf("Reloading poll interval")
				if err := ctx.LoadPollIntervalFromFile(pollIntervalFilepath); err != nil {
					log.Printf("failed to load poll interval from file: %s", err.Error())
				}
			}
		}
	}()

	// Handle the various ways of setting up TLS. The legal configurations
	// are:
	//   --acme-hostnames (with optional --acme-email and/or --acme-cert-cache)
	//   --cert and --key together
	//   --disable-tls
	// The outputs of this block of code are the disableTLS,
	// needHTTP01Listener, certManager, and getCertificate variables.
	var err error
	if acmeHostnamesCommas != "" {
		acmeHostnames := strings.Split(acmeHostnamesCommas, ",")
		log.Printf("ACME hostnames: %q", acmeHostnames)

		var cache autocert.Cache
		if err := os.MkdirAll(acmeCertCacheDir, 0700); err != nil {
			log.Printf("Warning: Couldn't create cache directory %q (reason: %s) so we're *not* using our certificate cache.", acmeCertCacheDir, err)
		} else {
			cache = autocert.DirCache(acmeCertCacheDir)
		}

		certManager := autocert.Manager{
			Cache:      cache,
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(acmeHostnames...),
			Email:      acmeEmail,
		}
		go func() {
			log.Printf("Starting HTTP-01 listener")
			server := &http.Server{
				Addr:              ":80",
				Handler:           certManager.HTTPHandler(nil),
				ReadHeaderTimeout: time.Second,
			}
			log.Fatal(server.ListenAndServe())
		}()

		server.TLSConfig = &tls.Config{
			GetCertificate: certManager.GetCertificate,
			MinVersion:     tls.VersionTLS13,
		}
		err = server.ListenAndServeTLS("", "")
	} else if certFilename != "" && keyFilename != "" {
		if acmeEmail != "" || acmeHostnamesCommas != "" {
			log.Fatalf("The --cert and --key options are not allowed with --acme-email or --acme-hostnames.")
		}
		err = server.ListenAndServeTLS(certFilename, keyFilename)
	} else if disableTLS {
		err = server.ListenAndServe()
	} else {
		log.Fatal("the --acme-hostnames, --cert and --key, or --disable-tls option is required")
	}

	if err != nil {
		log.Fatal(err)
	}
}
