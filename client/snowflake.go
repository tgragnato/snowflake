// Client transport plugin for the Snowflake pluggable transport.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/ptutil/safelog"

	sf "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/proxy"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/version"
)

const (
	DefaultSnowflakeCapacity = 1
)

type ptEventLogger struct {
}

func NewPTEventLogger() event.SnowflakeEventReceiver {
	return &ptEventLogger{}
}

func (p ptEventLogger) OnNewSnowflakeEvent(e event.SnowflakeEvent) {
	pt.Log(pt.LogSeverityNotice, e.String())
}

// Exchanges bytes between two ReadWriters.
// (In this case, between a SOCKS connection and a snowflake transport conn)
func copyLoop(socks, sfconn io.ReadWriter) {
	done := make(chan struct{}, 2)
	go func() {
		if _, err := io.Copy(socks, sfconn); err != nil {
			log.Printf("copying Snowflake to SOCKS resulted in error: %v", err)
		}
		done <- struct{}{}
	}()
	go func() {
		if _, err := io.Copy(sfconn, socks); err != nil {
			log.Printf("copying SOCKS to Snowflake resulted in error: %v", err)
		}
		done <- struct{}{}
	}()
	<-done
	log.Println("copy loop ended")
}

// Accept local SOCKS connections and connect to a Snowflake connection
func socksAcceptLoop(ln *pt.SocksListener, config sf.ClientConfig, shutdown chan struct{}, wg *sync.WaitGroup) {
	defer ln.Close()
	for {
		conn, err := ln.AcceptSocks()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			log.Printf("SOCKS accept error: %s", err)
			break
		}
		log.Printf("SOCKS accepted: %v", conn.Req)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()

			// Check to see if our command line options are overriden by SOCKS options
			if arg, ok := conn.Req.Args.Get("ampcache"); ok {
				config.AmpCacheURL = arg
			}
			if arg, ok := conn.Req.Args.Get("sqsqueue"); ok {
				config.SQSQueueURL = arg
			}
			if arg, ok := conn.Req.Args.Get("sqscreds"); ok {
				config.SQSCredsStr = arg
			}
			if arg, ok := conn.Req.Args.Get("fronts"); ok {
				if arg != "" {
					config.FrontDomains = strings.Split(strings.TrimSpace(arg), ",")
				}
			} else if arg, ok := conn.Req.Args.Get("front"); ok {
				config.FrontDomains = strings.Split(strings.TrimSpace(arg), ",")
			}
			if arg, ok := conn.Req.Args.Get("ice"); ok {
				config.ICEAddresses = strings.Split(strings.TrimSpace(arg), ",")
			}
			if arg, ok := conn.Req.Args.Get("max"); ok {
				max, err := strconv.Atoi(arg)
				if err != nil {
					conn.Reject()
					log.Println("Invalid SOCKS arg: max=", arg)
					return
				}
				config.Max = max
			}
			if arg, ok := conn.Req.Args.Get("url"); ok {
				config.BrokerURL = arg
			}
			if arg, ok := conn.Req.Args.Get("utls-nosni"); ok {
				switch strings.ToLower(arg) {
				case "true":
					fallthrough
				case "yes":
					config.UTLSRemoveSNI = true
				}
			}
			if arg, ok := conn.Req.Args.Get("utls-imitate"); ok {
				config.UTLSClientID = arg
			}
			if arg, ok := conn.Req.Args.Get("fingerprint"); ok {
				config.BridgeFingerprint = arg
			}
			transport, err := sf.NewSnowflakeClient(config)
			if err != nil {
				conn.Reject()
				log.Println("Failed to start snowflake transport: ", err)
				return
			}
			transport.AddSnowflakeEventListener(NewPTEventLogger())
			err = conn.Grant(&net.TCPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				log.Printf("conn.Grant error: %s", err)
				return
			}

			handler := make(chan struct{})
			go func() {
				defer close(handler)
				sconn, err := transport.Dial()
				if err != nil {
					log.Printf("dial error: %s", err)
					return
				}
				defer sconn.Close()
				// copy between the created Snowflake conn and the SOCKS conn
				copyLoop(conn, sconn)
			}()
			select {
			case <-shutdown:
				log.Println("Received shutdown signal")
			case <-handler:
				log.Println("Handler ended")
			}
			return
		}()
	}
}

func main() {
	iceServersCommas := flag.String("ice", "", "comma-separated list of ICE servers")
	brokerURL := flag.String("url", "", "URL of signaling broker")
	frontDomain := flag.String("front", "", "front domain")
	frontDomainsCommas := flag.String("fronts", "", "comma-separated list of front domains")
	ampCacheURL := flag.String("ampcache", "", "URL of AMP cache to use as a proxy for signaling")
	sqsQueueURL := flag.String("sqsqueue", "", "URL of SQS Queue to use as a proxy for signaling")
	sqsCredsStr := flag.String("sqscreds", "", "credentials to access SQS Queue")
	logFilename := flag.String("log", "", "name of log file")
	logToStateDir := flag.Bool("log-to-state-dir", false, "resolve the log file relative to tor's pt state dir")
	keepLocalAddresses := flag.Bool("keep-local-addresses", false, "keep local LAN address ICE candidates.\nThis is usually pointless because Snowflake proxies don't usually reside on the same local network as the client.")
	unsafeLogging := flag.Bool("unsafe-logging", false, "keep IP addresses and other sensitive info in the logs")
	max := flag.Int("max", DefaultSnowflakeCapacity,
		"capacity for number of multiplexed WebRTC peers")
	versionFlag := flag.Bool("version", false, "display version info to stderr and quit")

	// Deprecated
	oldLogToStateDir := flag.Bool("logToStateDir", false, "use -log-to-state-dir instead")
	oldKeepLocalAddresses := flag.Bool("keepLocalAddresses", false, "use -keep-local-addresses instead")

	flag.Parse()

	if *versionFlag {
		fmt.Fprintf(os.Stderr, "snowflake-client %s", version.ConstructResult())
		os.Exit(0)
	}

	log.SetFlags(log.LstdFlags | log.LUTC)

	// Don't write to stderr; versions of tor earlier than about 0.3.5.6 do
	// not read from the pipe, and eventually we will deadlock because the
	// buffer is full.
	// https://bugs.torproject.org/26360
	// https://bugs.torproject.org/25600#comment:14
	var logOutput = io.Discard
	if *logFilename != "" {
		if *logToStateDir || *oldLogToStateDir {
			stateDir, err := pt.MakeStateDir()
			if err != nil {
				log.Fatal(err)
			}
			*logFilename = filepath.Join(stateDir, *logFilename)
		}
		logFile, err := os.OpenFile(*logFilename,
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer logFile.Close()
		logOutput = logFile
	}
	if *unsafeLogging {
		log.SetOutput(logOutput)
	} else {
		// We want to send the log output through our scrubber first
		log.SetOutput(&safelog.LogScrubber{Output: logOutput})
	}

	log.Printf("snowflake-client %s\n", version.GetVersion())

	iceAddresses := strings.Split(strings.TrimSpace(*iceServersCommas), ",")

	var frontDomains []string
	if *frontDomainsCommas != "" {
		frontDomains = strings.Split(strings.TrimSpace(*frontDomainsCommas), ",")
	}

	// Maintain backwards compatability with legacy commandline option
	if (len(frontDomains) == 0) && (*frontDomain != "") {
		frontDomains = []string{*frontDomain}
	}

	config := sf.ClientConfig{
		BrokerURL:          *brokerURL,
		AmpCacheURL:        *ampCacheURL,
		SQSQueueURL:        *sqsQueueURL,
		SQSCredsStr:        *sqsCredsStr,
		FrontDomains:       frontDomains,
		ICEAddresses:       iceAddresses,
		KeepLocalAddresses: *keepLocalAddresses || *oldKeepLocalAddresses,
		Max:                *max,
	}

	// Begin goptlib client process.
	ptInfo, err := pt.ClientSetup(nil)
	if err != nil {
		log.Fatal(err)
	}
	if ptInfo.ProxyURL != nil {
		if err := proxy.CheckProxyProtocolSupport(ptInfo.ProxyURL); err != nil {
			pt.ProxyError("proxy is not supported:" + err.Error())
			os.Exit(1)
		} else {
			config.CommunicationProxy = ptInfo.ProxyURL
			client := proxy.NewSocks5UDPClient(config.CommunicationProxy)
			conn, err := client.ListenPacket("udp", nil)
			if err != nil {
				pt.ProxyError("proxy test failure:" + err.Error())
				os.Exit(1)
			}
			conn.Close()
			pt.ProxyDone()
		}
	}
	pt.ReportVersion("snowflake-client", version.GetVersion())
	listeners := make([]net.Listener, 0)
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	for _, methodName := range ptInfo.MethodNames {
		switch methodName {
		case "snowflake":
			// TODO: Be able to recover when SOCKS dies.
			ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
			if err != nil {
				pt.CmethodError(methodName, err.Error())
				break
			}
			log.Printf("Started SOCKS listener at %v.", ln.Addr())
			go socksAcceptLoop(ln, config, shutdown, &wg)
			pt.Cmethod(methodName, ln.Version(), ln.Addr())
			listeners = append(listeners, ln)
		default:
			pt.CmethodError(methodName, "no such method")
		}
	}
	pt.CmethodsDone()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
		// This environment variable means we should treat EOF on stdin
		// just like SIGTERM: https://bugs.torproject.org/15435.
		go func() {
			if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
				log.Printf("calling io.Copy(io.Discard, os.Stdin) returned error: %v", err)
			}
			log.Printf("synthesizing SIGTERM because of stdin close")
			sigChan <- syscall.SIGTERM
		}()
	}

	// Wait for a signal.
	<-sigChan
	log.Println("stopping snowflake")

	// Signal received, shut down.
	for _, ln := range listeners {
		ln.Close()
	}
	close(shutdown)
	wg.Wait()
	log.Println("snowflake is done.")
}
