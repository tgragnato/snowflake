/*
Probe test server to check the reachability of Snowflake proxies from
clients with symmetric NATs.

The probe server receives an offer from a proxy, returns an answer, and then
attempts to establish a datachannel connection to that proxy. The proxy will
self-determine whether the connection opened successfully.
*/
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/ptutil/safelog"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/messages"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/util"

	"github.com/pion/transport/v3/stdnet"
	"github.com/pion/webrtc/v4"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// Maximum number of bytes to be read from an HTTP request
	readLimit = 100000
	// Time after which we assume proxy data channel will not open
	dataChannelOpenTimeout = 20 * time.Second
	// How long to wait after the data channel has been open before closing the peer connection.
	dataChannelCloseTimeout = 5 * time.Second
	// Default STUN URL
	defaultStunUrls = "stun:stun.l.google.com:19302,stun:stun.voip.blackberry.com:3478"
)

type ProbeHandler struct {
	stunURL string
	handle  func(string, http.ResponseWriter, *http.Request)
}

func (h ProbeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handle(h.stunURL, w, r)
}

// Create a PeerConnection from an SDP offer. Blocks until the gathering of ICE
// candidates is complete and the answer is available in LocalDescription.
func makePeerConnectionFromOffer(stunURL string, sdp *webrtc.SessionDescription,
	dataChanOpen chan struct{}, dataChanClosed chan struct{}, iceGatheringTimeout time.Duration) (*webrtc.PeerConnection, error) {

	settingsEngine := webrtc.SettingEngine{}
	// Use the SetNet setting https://pkg.go.dev/github.com/pion/webrtc/v3#SettingEngine.SetNet
	// to functionally revert a new change in pion by silently ignoring
	// when net.Interfaces() fails, rather than throwing an error
	vnet, _ := stdnet.NewNet()
	settingsEngine.SetNet(vnet)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingsEngine))

	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: strings.Split(stunURL, ","),
			},
		},
	}
	pc, err := api.NewPeerConnection(config)
	if err != nil {
		return nil, fmt.Errorf("accept: NewPeerConnection: %s", err)
	}
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		dc.OnOpen(func() {
			close(dataChanOpen)
		})
		dc.OnClose(func() {
			close(dataChanClosed)
			dc.Close()
		})
	})
	// As of v3.0.0, pion-webrtc uses trickle ICE by default.
	// We have to wait for candidate gathering to complete
	// before we send the offer
	done := webrtc.GatheringCompletePromise(pc)
	err = pc.SetRemoteDescription(*sdp)
	if err != nil {
		if inerr := pc.Close(); inerr != nil {
			log.Printf("unable to call pc.Close after pc.SetRemoteDescription with error: %v", inerr)
		}
		return nil, fmt.Errorf("accept: SetRemoteDescription: %s", err)
	}

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		if inerr := pc.Close(); inerr != nil {
			log.Printf("ICE gathering has generated an error when calling pc.Close: %v", inerr)
		}
		return nil, err
	}

	err = pc.SetLocalDescription(answer)
	if err != nil {
		if err = pc.Close(); err != nil {
			log.Printf("pc.Close after setting local description returned : %v", err)
		}
		return nil, err
	}

	// Wait for ICE candidate gathering to complete,
	// or for whatever we managed to gather before the client times out.
	// See https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/issues/40230
	select {
	case <-done:
	case <-time.After(iceGatheringTimeout):
	}
	return pc, nil
}

func probeHandler(stunURL string, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	resp, err := io.ReadAll(http.MaxBytesReader(w, r.Body, readLimit))
	if nil != err {
		log.Println("Invalid data.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	offer, _, err := messages.DecodePollResponse(resp)
	if err != nil {
		log.Printf("Error reading offer: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if offer == "" {
		log.Printf("Error processing session description: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sdp, err := util.DeserializeSessionDescription(offer)
	if err != nil {
		log.Printf("Error processing session description: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	dataChanOpen := make(chan struct{})
	dataChanClosed := make(chan struct{})
	// TODO refactor: DRY this must be below `ResponseHeaderTimeout` in proxy
	// https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/blob/e1d9b4ace69897521cc29585b5084c5f4d1ce874/proxy/lib/snowflake.go#L207
	iceGatheringTimeout := 10 * time.Second
	pc, err := makePeerConnectionFromOffer(stunURL, sdp, dataChanOpen, dataChanClosed, iceGatheringTimeout)
	if err != nil {
		log.Printf("Error making WebRTC connection: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// We'll set this to `false` if the signaling (this function) succeeds.
	closePcOnReturn := true
	defer func() {
		if closePcOnReturn {
			if err := pc.Close(); err != nil {
				log.Printf("Error calling pc.Close: %v", err)
			}
		}
		// Otherwise it must be closed below, wherever `closePcOnReturn` is set to `false`.
	}()

	sdp = &webrtc.SessionDescription{
		Type: pc.LocalDescription().Type,
		SDP:  util.StripLocalAddresses(pc.LocalDescription().SDP),
	}
	answer, err := util.SerializeSessionDescription(sdp)
	if err != nil {
		log.Printf("Error making WebRTC connection: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	body, err := messages.EncodeAnswerRequest(answer, "stub-sid")
	if err != nil {
		log.Printf("Error making WebRTC connection: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(body)
	// Set a timeout on peerconnection. If the connection state has not
	// advanced to PeerConnectionStateConnected in this time,
	// destroy the peer connection and return the token.
	closePcOnReturn = false
	go func() {
		timer := time.NewTimer(dataChannelOpenTimeout)
		defer timer.Stop()

		select {
		case <-dataChanOpen:
			// Let's not close the `PeerConnection` immediately now,
			// instead let's wait for the peer (or timeout)
			// to close the connection,
			// in order to ensure that the DataChannel also gets opened
			// on the proxy's side.
			// Otherwise the proxy might receive the "close PeerConnection"
			// "event" before they receive "dataChannel.OnOpen",
			// which would wrongly result in a "restricted" NAT.
			// See https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/issues/40387
			select {
			case <-dataChanClosed:
			case <-time.After(dataChannelCloseTimeout):
			}
		case <-timer.C:
		}

		if err := pc.Close(); err != nil {
			log.Printf("Error calling pc.Close: %v", err)
		}
	}()
	return

}

func main() {
	var acmeEmail string
	var acmeHostnamesCommas string
	var acmeCertCacheDir string
	var addr string
	var disableTLS bool
	var certFilename, keyFilename string
	var unsafeLogging bool
	var stunURL string

	flag.StringVar(&acmeEmail, "acme-email", "", "optional contact email for Let's Encrypt notifications")
	flag.StringVar(&acmeHostnamesCommas, "acme-hostnames", "", "comma-separated hostnames for TLS certificate")
	flag.StringVar(&acmeCertCacheDir, "acme-cert-cache", "acme-cert-cache", "directory in which certificates should be cached")
	flag.StringVar(&certFilename, "cert", "", "TLS certificate file")
	flag.StringVar(&keyFilename, "key", "", "TLS private key file")
	flag.StringVar(&addr, "addr", ":8443", "address to listen on")
	flag.BoolVar(&disableTLS, "disable-tls", false, "don't use HTTPS")
	flag.BoolVar(&unsafeLogging, "unsafe-logging", false, "prevent logs from being scrubbed")
	flag.StringVar(&stunURL, "stun", defaultStunUrls, "STUN servers to use for NAT traversal (comma-separated)")
	flag.Parse()

	var logOutput io.Writer = os.Stderr
	if unsafeLogging {
		log.SetOutput(logOutput)
	} else {
		// Scrub log output just in case an address ends up there
		log.SetOutput(&safelog.LogScrubber{Output: logOutput})
	}

	log.SetFlags(log.LstdFlags | log.LUTC)

	http.Handle("/probe", ProbeHandler{stunURL, probeHandler})

	server := http.Server{
		Addr: addr,
	}

	var err error
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
		// start certificate manager handler
		go func() {
			log.Printf("Starting HTTP-01 listener")
			log.Fatal(http.ListenAndServe(":80", certManager.HTTPHandler(nil)))
		}()

		server.TLSConfig = &tls.Config{GetCertificate: certManager.GetCertificate}
		err = server.ListenAndServeTLS("", "")
	} else if certFilename != "" && keyFilename != "" {
		err = server.ListenAndServeTLS(certFilename, keyFilename)
	} else if disableTLS {
		err = server.ListenAndServe()
	} else {
		log.Fatal("the --cert and --key, --acme-hostnames, or --disable-tls option is required")
	}

	if err != nil {
		log.Println(err)
	}
}
