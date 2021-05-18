package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/rpc"
	"os"
	"strings"

	// "github.com/prometheus/client_golang/prometheus"
	// "github.com/prometheus/client_golang/prometheus/promhttp"
	"git.torproject.org/pluggable-transports/snowflake.git/common/messages"
	"git.torproject.org/pluggable-transports/snowflake.git/common/safelog"
	"golang.org/x/crypto/acme/autocert"
)

const (
	readLimit = 100000 // Maximum number of bytes to be read from an HTTP request
)

// Implements the http.Handler interface
type SnowflakeHandler struct {
	c      *rpc.Client
	handle func(*rpc.Client, http.ResponseWriter, *http.Request)
}

func (sh SnowflakeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Session-ID")
	// Return early if it's CORS preflight.
	if "OPTIONS" == r.Method {
		return
	}
	sh.handle(sh.c, w, r)
}

// Implements the http.Handler interface
type MetricsHandler struct {
	logFilename string
	handle      func(string, http.ResponseWriter, *http.Request)
}

func (mh MetricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Session-ID")
	// Return early if it's CORS preflight.
	if "OPTIONS" == r.Method {
		return
	}
	mh.handle(mh.logFilename, w, r)
}

func robotsTxtHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := w.Write([]byte("User-agent: *\nDisallow: /\n")); err != nil {
		log.Printf("robotsTxtHandler unable to write, with this error: %v", err)
	}
}

func metricsHandler(metricsFilename string, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if metricsFilename == "" {
		http.NotFound(w, r)
		return
	}
	metricsFile, err := os.OpenFile(metricsFilename, os.O_RDONLY, 0644)
	if err != nil {
		log.Println("Error opening metrics file for reading")
		http.NotFound(w, r)
		return
	}

	if _, err := io.Copy(w, metricsFile); err != nil {
		log.Printf("copying metricsFile returned error: %v", err)
	}
}

func debugHandler(c *rpc.Client, w http.ResponseWriter, r *http.Request) {
	var response string

	err := c.Call("IPC.Debug", new(interface{}), &response)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err := w.Write([]byte(response)); err != nil {
		log.Printf("writing proxy information returned error: %v ", err)
	}
}

/*
For snowflake proxies to request a client from the Broker.
*/
func proxyPolls(c *rpc.Client, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(http.MaxBytesReader(w, r.Body, readLimit))
	if err != nil {
		log.Println("Invalid data.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	arg := messages.Arg{
		Body:       body,
		RemoteAddr: r.RemoteAddr,
	}

	var response []byte
	err = c.Call("IPC.ProxyPolls", arg, &response)
	switch {
	case err == nil:
	case errors.Is(err, messages.ErrBadRequest):
		w.WriteHeader(http.StatusBadRequest)
		return
	case errors.Is(err, messages.ErrInternal):
		fallthrough
	default:
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(response); err != nil {
		log.Printf("proxyPolls unable to write offer with error: %v", err)
	}
}

/*
Expects a WebRTC SDP offer in the Request to give to an assigned
snowflake proxy, which responds with the SDP answer to be sent in
the HTTP response back to the client.
*/
func clientOffers(c *rpc.Client, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(http.MaxBytesReader(w, r.Body, readLimit))
	if err != nil {
		log.Printf("Error reading client request: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Handle the legacy version
	isLegacy := false
	if len(body) > 0 && body[0] == '{' {
		isLegacy = true
		req := messages.ClientPollRequest{
			Offer: string(body),
			NAT:   r.Header.Get("Snowflake-NAT-Type"),
		}
		body, err = req.EncodePollRequest()
		if err != nil {
			log.Printf("Error shimming the legacy request: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	arg := messages.Arg{
		Body:       body,
		RemoteAddr: "",
	}

	var response []byte
	err = c.Call("IPC.ClientOffers", arg, &response)
	if err != nil {
		// Assert err == messages.ErrInternal
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if isLegacy {
		resp, err := messages.DecodeClientPollResponse(response)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch resp.Error {
		case "":
			response = []byte(resp.Answer)
		case "no snowflake proxies currently available":
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		case "timed out waiting for answer!":
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		default:
			panic("unknown error")
		}
	}

	if _, err := w.Write(response); err != nil {
		log.Printf("clientOffers unable to write answer with error: %v", err)
	}
}

/*
Expects snowflake proxies which have previously successfully received
an offer from proxyHandler to respond with an answer in an HTTP POST,
which the broker will pass back to the original client.
*/
func proxyAnswers(c *rpc.Client, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(http.MaxBytesReader(w, r.Body, readLimit))
	if err != nil {
		log.Println("Invalid data.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	arg := messages.Arg{
		Body:       body,
		RemoteAddr: "",
	}

	var response []byte
	err = c.Call("IPC.ProxyAnswers", arg, &response)
	switch {
	case err == nil:
	case errors.Is(err, messages.ErrBadRequest):
		w.WriteHeader(http.StatusBadRequest)
		return
	case errors.Is(err, messages.ErrInternal):
		fallthrough
	default:
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(response); err != nil {
		log.Printf("proxyAnswers unable to write answer response with error: %v", err)
	}
}

func main() {
	var acmeEmail string
	var acmeHostnamesCommas string
	var acmeCertCacheDir string
	var addr string
	var disableTLS bool
	var certFilename, keyFilename string

	var metricsFilename string
	var unsafeLogging bool

	var socket string

	flag.StringVar(&acmeEmail, "acme-email", "", "optional contact email for Let's Encrypt notifications")
	flag.StringVar(&acmeHostnamesCommas, "acme-hostnames", "", "comma-separated hostnames for TLS certificate")
	flag.StringVar(&certFilename, "cert", "", "TLS certificate file")
	flag.StringVar(&keyFilename, "key", "", "TLS private key file")
	flag.StringVar(&acmeCertCacheDir, "acme-cert-cache", "acme-cert-cache", "directory in which certificates should be cached")
	flag.StringVar(&addr, "addr", ":443", "address to listen on")
	flag.BoolVar(&disableTLS, "disable-tls", false, "don't use HTTPS")

	flag.StringVar(&metricsFilename, "metrics-log", "", "path to metrics logging output")
	flag.BoolVar(&unsafeLogging, "unsafe-logging", false, "prevent logs from being scrubbed")

	flag.StringVar(&socket, "socket", "/tmp/broker.sock", "path to ipc socket")

	flag.Parse()

	var logOutput io.Writer = os.Stderr
	if unsafeLogging {
		log.SetOutput(logOutput)
	} else {
		// We want to send the log output through our scrubber first
		log.SetOutput(&safelog.LogScrubber{Output: logOutput})
	}
	log.SetFlags(log.LstdFlags | log.LUTC)

	var c, err = rpc.Dial("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	http.HandleFunc("/robots.txt", robotsTxtHandler)

	http.Handle("/proxy", SnowflakeHandler{c, proxyPolls})
	http.Handle("/client", SnowflakeHandler{c, clientOffers})
	http.Handle("/answer", SnowflakeHandler{c, proxyAnswers})
	http.Handle("/debug", SnowflakeHandler{c, debugHandler})

	http.Handle("/metrics", MetricsHandler{metricsFilename, metricsHandler})
	// http.Handle("/prometheus", promhttp.HandlerFor(ctx.metrics.promMetrics.registry, promhttp.HandlerOpts{}))

	server := http.Server{
		Addr: addr,
	}

	// Handle the various ways of setting up TLS. The legal configurations
	// are:
	//   --acme-hostnames (with optional --acme-email and/or --acme-cert-cache)
	//   --cert and --key together
	//   --disable-tls
	// The outputs of this block of code are the disableTLS,
	// needHTTP01Listener, certManager, and getCertificate variables.
	if acmeHostnamesCommas != "" {
		acmeHostnames := strings.Split(acmeHostnamesCommas, ",")
		log.Printf("ACME hostnames: %q", acmeHostnames)

		var cache autocert.Cache
		if err = os.MkdirAll(acmeCertCacheDir, 0700); err != nil {
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
			log.Fatal(http.ListenAndServe(":80", certManager.HTTPHandler(nil)))
		}()

		server.TLSConfig = &tls.Config{GetCertificate: certManager.GetCertificate}
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
