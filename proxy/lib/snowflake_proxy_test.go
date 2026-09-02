package snowflake_proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"
	"tgragnato.it/snowflake/common/event"
	"tgragnato.it/snowflake/common/messages"
	"tgragnato.it/snowflake/common/util"
)

// newRelayServer starts a WebSocket server that stands in for the Snowflake
// bridge, and reports the query of every request it accepts.
func newRelayServer(t *testing.T) (wsURL string, queries chan url.Values) {
	t.Helper()

	queries = make(chan url.Values, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case queries <- r.URL.Query():
		default:
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
		if err != nil {
			return
		}
		// Echo until the peer goes away, so the connection stays usable.
		for {
			typ, data, err := conn.Read(r.Context())
			if err != nil {
				conn.Close(websocket.StatusNormalClosure, "")
				return
			}
			if err := conn.Write(r.Context(), typ, data); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	return "ws://" + strings.TrimPrefix(server.URL, "http://"), queries
}

func TestCurrentNATType(t *testing.T) {
	// The NAT type is package-level state shared with the other tests.
	previous := getCurrentNATType()
	t.Cleanup(func() { setCurrentNATType(previous) })

	for _, want := range []string{NAT3Open, NAT3Moderate, NAT3Strict, NATUnknown} {
		setCurrentNATType(want)
		if got := getCurrentNATType(); got != want {
			t.Errorf("getCurrentNATType() = %q, want %q", got, want)
		}
	}
}

// The probe service is asked for a specific connectivity mode through a query
// parameter, without disturbing whatever the operator put in the URL.
func TestProbeURLWithInteractiveConnectivity(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		probeURL string
		mode     string
		want     string
		wantErr  bool
	}{
		{
			name:     "mode is appended",
			probeURL: "https://probe.example.com/probe",
			mode:     "strict",
			want:     "https://probe.example.com/probe?InCoSim=strict",
		},
		{
			name:     "existing query is preserved",
			probeURL: "https://probe.example.com/probe?foo=bar",
			mode:     "moderate",
			want:     "https://probe.example.com/probe?InCoSim=moderate&foo=bar",
		},
		{
			name:     "an unparseable URL is an error",
			probeURL: "://probe.example.com",
			mode:     "strict",
			wantErr:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := probeURLWithInteractiveConnectivity(test.probeURL, test.mode)
			if test.wantErr {
				if err == nil {
					t.Fatalf("probeURLWithInteractiveConnectivity(%q) = %q, want an error", test.probeURL, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("probeURLWithInteractiveConnectivity: %v", err)
			}
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestMakeWebRTCAPI(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		proxy SnowflakeProxy
	}{
		{"default settings", SnowflakeProxy{}},
		{"keeping local addresses", SnowflakeProxy{KeepLocalAddresses: true}},
		{"with an ephemeral port range", SnowflakeProxy{EphemeralMinPort: 40000, EphemeralMaxPort: 40100}},
		{"with an outbound address", SnowflakeProxy{OutboundAddress: "198.51.100.1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if api := test.proxy.makeWebRTCAPI(); api == nil {
				t.Error("makeWebRTCAPI() = nil")
			}
		})
	}
}

// The NAT probe connection is offered to the probe service, so it must carry a
// complete local description by the time it is returned.
func TestMakeNewPeerConnection(t *testing.T) {
	t.Parallel()

	sf := &SnowflakeProxy{KeepLocalAddresses: true}
	pc, err := sf.makeNewPeerConnection(webrtc.Configuration{}, make(chan struct{}))
	if err != nil {
		t.Fatalf("makeNewPeerConnection: %v", err)
	}
	defer pc.Close()

	description := pc.LocalDescription()
	if description == nil {
		t.Fatal("LocalDescription is nil")
	}
	if description.Type != webrtc.SDPTypeOffer {
		t.Errorf("local description type = %v, want an offer", description.Type)
	}
	if !strings.Contains(description.SDP, "a=candidate") {
		t.Error("the offer carries no ICE candidate")
	}
}

// makeClientOffer produces an offer the way a Snowflake client would, with a
// data channel and fully gathered candidates.
func makeClientOffer(t *testing.T) (*webrtc.PeerConnection, *webrtc.DataChannel, *webrtc.SessionDescription) {
	t.Helper()

	settings := webrtc.SettingEngine{}
	settings.SetIncludeLoopbackCandidate(true)
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("NewPeerConnection: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	dc, err := pc.CreateDataChannel("snowflake-test", nil)
	if err != nil {
		t.Fatalf("CreateDataChannel: %v", err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		t.Fatalf("SetLocalDescription: %v", err)
	}
	<-gathered

	return pc, dc, pc.LocalDescription()
}

func TestMakePeerConnectionFromOffer(t *testing.T) {
	t.Parallel()

	sf := &SnowflakeProxy{
		KeepLocalAddresses: true,
		EventDispatcher:    event.NewSnowflakeEventDispatcher(),
		bytesLogger:        &stubBytesLogger{},
	}

	t.Run("answers a client offer", func(t *testing.T) {
		_, _, offer := makeClientOffer(t)

		pc, err := sf.makePeerConnectionFromOffer(offer, webrtc.Configuration{}, make(chan struct{}),
			func(conn *webRTCConn, remoteIP net.IP) {})
		if err != nil {
			t.Fatalf("makePeerConnectionFromOffer: %v", err)
		}
		defer pc.Close()

		answer := pc.LocalDescription()
		if answer == nil {
			t.Fatal("LocalDescription is nil")
		}
		if answer.Type != webrtc.SDPTypeAnswer {
			t.Errorf("local description type = %v, want an answer", answer.Type)
		}
	})

	t.Run("rejects an unusable offer", func(t *testing.T) {
		offer := &webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: "not an SDP body"}

		pc, err := sf.makePeerConnectionFromOffer(offer, webrtc.Configuration{}, make(chan struct{}),
			func(conn *webRTCConn, remoteIP net.IP) {})
		if err == nil {
			pc.Close()
			t.Fatal("makePeerConnectionFromOffer succeeded on a bad offer, want an error")
		}
	})
}

// A full local handshake: the proxy must hand the data channel to the relay
// handler once the client opens it.
func TestPeerConnectionHandsOffOpenDataChannel(t *testing.T) {
	t.Parallel()

	dispatcher := event.NewSnowflakeEventDispatcher()
	sf := &SnowflakeProxy{
		KeepLocalAddresses: true,
		EventDispatcher:    dispatcher,
		bytesLogger:        &stubBytesLogger{},
	}

	clientPC, clientDC, offer := makeClientOffer(t)

	handed := make(chan *webRTCConn, 1)
	dataChan := make(chan struct{})
	proxyPC, err := sf.makePeerConnectionFromOffer(offer, webrtc.Configuration{}, dataChan,
		func(conn *webRTCConn, remoteIP net.IP) {
			handed <- conn
		})
	if err != nil {
		t.Fatalf("makePeerConnectionFromOffer: %v", err)
	}
	defer proxyPC.Close()

	if err := clientPC.SetRemoteDescription(*proxyPC.LocalDescription()); err != nil {
		t.Fatalf("SetRemoteDescription: %v", err)
	}

	select {
	case <-dataChan:
	case <-time.After(30 * time.Second):
		t.Fatal("the proxy never saw the client's data channel")
	}

	var conn *webRTCConn
	select {
	case conn = <-handed:
	case <-time.After(30 * time.Second):
		t.Fatal("the data channel was never handed to the relay handler")
	}
	defer conn.Close()

	// Whatever the client sends must reach the handler's side of the pipe.
	opened := make(chan struct{})
	var once sync.Once
	signalOpen := func() { once.Do(func() { close(opened) }) }
	clientDC.OnOpen(signalOpen)
	if clientDC.ReadyState() == webrtc.DataChannelStateOpen {
		signalOpen()
	}
	select {
	case <-opened:
	case <-time.After(30 * time.Second):
		t.Fatal("the client's data channel never opened")
	}
	if err := clientDC.SendText("hello relay"); err != nil {
		t.Fatalf("SendText: %v", err)
	}

	buf := make([]byte, len("hello relay"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading from the proxied connection: %v", err)
	}
	if string(buf) != "hello relay" {
		t.Errorf("read %q, want %q", buf, "hello relay")
	}

	// The client's address is read back from the offer. Here the client is on
	// the same host, so every candidate is a local address and none of them is
	// reported: only addresses that could belong to a real client are.
	if ip := conn.RemoteIP(); ip != nil {
		t.Errorf("RemoteIP() = %v, want nil for a local client", ip)
	}
}

func TestConnectToRelay(t *testing.T) {
	t.Parallel()

	t.Run("encodes the client address", func(t *testing.T) {
		relayURL, queries := newRelayServer(t)

		conn, err := connectToRelay(relayURL, net.ParseIP("198.51.100.7"))
		if err != nil {
			t.Fatalf("connectToRelay: %v", err)
		}
		defer conn.Close()

		select {
		case query := <-queries:
			if got := query.Get("client_ip"); got != "198.51.100.7" {
				t.Errorf("client_ip = %q, want %q", got, "198.51.100.7")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the relay never received a request")
		}
	})

	t.Run("omits the client address when unknown", func(t *testing.T) {
		relayURL, queries := newRelayServer(t)

		conn, err := connectToRelay(relayURL, nil)
		if err != nil {
			t.Fatalf("connectToRelay: %v", err)
		}
		defer conn.Close()

		select {
		case query := <-queries:
			if _, ok := query["client_ip"]; ok {
				t.Errorf("client_ip = %q, want it to be absent", query.Get("client_ip"))
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the relay never received a request")
		}
	})

	t.Run("rejects an unparseable URL", func(t *testing.T) {
		if _, err := connectToRelay("://relay.example.com", nil); err == nil {
			t.Error("connectToRelay succeeded on a bad URL, want an error")
		}
	})

	t.Run("reports a dial failure", func(t *testing.T) {
		// Port 0 is never listening.
		if _, err := connectToRelay("ws://127.0.0.1:0", nil); err == nil {
			t.Error("connectToRelay succeeded against a dead relay, want an error")
		}
	})
}

// The proxy only polls the broker while the bridge is reachable, so this check
// has to distinguish a working relay from an unreachable one.
func TestCheckBridgeReachability(t *testing.T) {
	t.Parallel()

	t.Run("reachable relay", func(t *testing.T) {
		relayURL, _ := newRelayServer(t)

		sf := &SnowflakeProxy{RelayURL: relayURL}
		if err := sf.checkBridgeReachability(); err != nil {
			t.Errorf("checkBridgeReachability: %v", err)
		}
	})

	t.Run("unreachable relay", func(t *testing.T) {
		sf := &SnowflakeProxy{RelayURL: "ws://127.0.0.1:0"}
		if err := sf.checkBridgeReachability(); err == nil {
			t.Error("checkBridgeReachability succeeded against a dead relay, want an error")
		}
	})
}

// The relay handler is what bridges the client's data channel and the bridge's
// WebSocket; a relay it cannot reach must not take down the proxy.
func TestDatachannelHandlerWithUnreachableRelay(t *testing.T) {
	t.Parallel()

	sf := &SnowflakeProxy{RelayURL: "ws://127.0.0.1:0", shutdown: make(chan struct{})}
	pc, err := sf.makeNewPeerConnection(webrtc.Configuration{}, make(chan struct{}))
	if err != nil {
		t.Fatalf("makeNewPeerConnection: %v", err)
	}
	pr, pw := io.Pipe()
	defer pw.Close()
	conn := newWebRTCConn(pc, nil, pr, &stubBytesLogger{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		sf.datachannelHandler(conn, nil, "")
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("datachannelHandler did not give up on an unreachable relay")
	}
}

// The broker can name the relay for a given client, which overrides the
// proxy's default.
func TestDatachannelHandlerUsesBrokerRelayURL(t *testing.T) {
	t.Parallel()

	sf := &SnowflakeProxy{RelayURL: "ws://127.0.0.1:0", shutdown: make(chan struct{})}
	pc, err := sf.makeNewPeerConnection(webrtc.Configuration{}, make(chan struct{}))
	if err != nil {
		t.Fatalf("makeNewPeerConnection: %v", err)
	}
	pr, pw := io.Pipe()
	defer pw.Close()
	conn := newWebRTCConn(pc, nil, pr, &stubBytesLogger{})

	relayURL, queries := newRelayServer(t)
	adaptor := dataChannelHandlerWithRelayURL{RelayURL: relayURL, sf: sf}

	done := make(chan struct{})
	go func() {
		defer close(done)
		adaptor.datachannelHandler(conn, net.ParseIP("198.51.100.7"))
	}()

	select {
	case query := <-queries:
		if got := query.Get("client_ip"); got != "198.51.100.7" {
			t.Errorf("client_ip = %q, want %q", got, "198.51.100.7")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the relay named by the broker was never contacted")
	}

	conn.Close()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Error("the relay handler did not stop after the connection closed")
	}
}

// evaluateConnectivityWithHelper talks to the probe service; anything other
// than a usable answer must be reported as an error rather than mistaken for a
// successful connection.
func TestEvaluateConnectivityWithHelperErrors(t *testing.T) {
	t.Parallel()

	sf := &SnowflakeProxy{KeepLocalAddresses: true}

	t.Run("unparseable probe URL", func(t *testing.T) {
		if _, err := sf.evaluateConnectivityWithHelper(webrtc.Configuration{}, "://probe"); err == nil {
			t.Error("evaluateConnectivityWithHelper succeeded on a bad URL, want an error")
		}
	})

	t.Run("unreachable probe service", func(t *testing.T) {
		if _, err := sf.evaluateConnectivityWithHelper(webrtc.Configuration{}, "http://127.0.0.1:0"); err == nil {
			t.Error("evaluateConnectivityWithHelper succeeded against a dead probe, want an error")
		}
	})

	t.Run("unreadable probe response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("this is not a probe answer"))
		}))
		defer server.Close()

		if _, err := sf.evaluateConnectivityWithHelper(webrtc.Configuration{}, server.URL); err == nil {
			t.Error("evaluateConnectivityWithHelper succeeded on a garbage answer, want an error")
		}
	})

	t.Run("unusable answer SDP", func(t *testing.T) {
		body, err := (&messages.ProxyAnswerRequest{Answer: `{"type":"answer","sdp":"not an SDP body"}`, Sid: "test"}).Encode()
		if err != nil {
			t.Fatalf("EncodeAnswerRequest: %v", err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(body)
		}))
		defer server.Close()

		if _, err := sf.evaluateConnectivityWithHelper(webrtc.Configuration{}, server.URL); err == nil {
			t.Error("evaluateConnectivityWithHelper succeeded on an unusable answer, want an error")
		}
	})
}

// checkNATType is best-effort: a probe service it cannot use leaves the
// previously measured type alone and reports the failure.
func TestCheckNATType(t *testing.T) {
	previous := getCurrentNATType()
	t.Cleanup(func() { setCurrentNATType(previous) })

	t.Run("forced unrestricted skips the probe", func(t *testing.T) {
		sf := &SnowflakeProxy{NATTypeForceUnrestricted: true}
		setCurrentNATType(NATUnknown)
		if err := sf.checkNATType(webrtc.Configuration{}, "://probe"); err != nil {
			t.Errorf("checkNATType: %v", err)
		}
		if got := getCurrentNATType(); got != NATUnknown {
			t.Errorf("NAT type = %q, want it left at %q", got, NATUnknown)
		}
	})

	t.Run("an unusable probe service is an error", func(t *testing.T) {
		sf := &SnowflakeProxy{KeepLocalAddresses: true}
		if err := sf.checkNATType(webrtc.Configuration{}, "http://127.0.0.1:0"); err == nil {
			t.Error("checkNATType succeeded against a dead probe, want an error")
		}
	})

	t.Run("no connectivity at all means a strict NAT", func(t *testing.T) {
		// The probe service answers with our own offer echoed back as an
		// answer, which never establishes a data channel.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return
			}
			poll, err := messages.DecodeProxyPollResponse(body)
			if err != nil {
				return
			}
			offer, err := util.DeserializeSessionDescription(poll.Offer)
			if err != nil {
				return
			}
			answer, err := util.SerializeSessionDescription(&webrtc.SessionDescription{
				Type: webrtc.SDPTypeAnswer,
				SDP:  offer.SDP,
			})
			if err != nil {
				return
			}
			resp, err := (&messages.ProxyAnswerRequest{Answer: answer, Sid: "test"}).Encode()
			if err != nil {
				return
			}
			w.Write(resp)
		}))
		defer server.Close()

		sf := &SnowflakeProxy{KeepLocalAddresses: true}
		setCurrentNATType(NATUnknown)
		if err := sf.checkNATType(webrtc.Configuration{}, server.URL); err != nil {
			t.Fatalf("checkNATType: %v", err)
		}
		if got := getCurrentNATType(); got != NAT3Strict {
			t.Errorf("NAT type = %q, want %q", got, NAT3Strict)
		}
	})
}

func TestSnowflakeProxyStop(t *testing.T) {
	t.Parallel()

	sf := &SnowflakeProxy{shutdown: make(chan struct{})}
	sf.Stop()

	select {
	case <-sf.shutdown:
	default:
		t.Error("Stop did not signal the shutdown channel")
	}
}

// Start validates its configuration before doing any work, so that a
// misconfigured proxy fails immediately instead of misbehaving later.
func TestStartRejectsBadConfiguration(t *testing.T) {
	for _, test := range []struct {
		name  string
		proxy SnowflakeProxy
	}{
		{
			name:  "unparseable broker URL",
			proxy: SnowflakeProxy{BrokerURL: "://broker.example.com"},
		},
		{
			name:  "invalid relay domain name pattern",
			proxy: SnowflakeProxy{RelayDomainNamePattern: "snowflake.torproject.net"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy := test.proxy
			proxy.NATTypeForceUnrestricted = true
			if err := proxy.Start(); err == nil {
				proxy.Stop()
				t.Error("Start succeeded on a bad configuration, want an error")
			}
		})
	}
}

// A proxy that starts up with a reachable relay polls the broker until it is
// told to stop.
func TestStartPollsUntilStopped(t *testing.T) {
	previous := getCurrentNATType()
	t.Cleanup(func() { setCurrentNATType(previous) })

	relayURL, _ := newRelayServer(t)

	polled := make(chan struct{}, 1)
	brokerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case polled <- struct{}{}:
		default:
		}
		// An empty offer means "no client for you right now".
		body, err := (&messages.ProxyPollResponse{Status: messages.ProxyClientNoMatch}).Encode()
		if err != nil {
			return
		}
		w.Write(body)
	}))
	defer brokerServer.Close()

	sf := &SnowflakeProxy{
		BrokerURL:                brokerServer.URL,
		RelayURL:                 relayURL,
		RelayDomainNamePattern:   "$",
		PollInterval:             50 * time.Millisecond,
		MinPollInterval:          50 * time.Millisecond,
		NATTypeForceUnrestricted: true,
		KeepLocalAddresses:       true,
		SummaryInterval:          time.Hour,
		EventDispatcher:          event.NewSnowflakeEventDispatcher(),
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		if err := sf.Start(); err != nil {
			t.Errorf("Start: %v", err)
		}
	})

	select {
	case <-polled:
	case <-time.After(30 * time.Second):
		t.Fatal("the proxy never polled the broker")
	}

	sf.Stop()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Start did not return after Stop")
	}

	if got := getCurrentNATType(); got != NATUnrestricted {
		t.Errorf("NAT type = %q, want %q", got, NATUnrestricted)
	}
}

// newTimeoutTestConn builds a webRTCConn with a short inactivity timeout and
// starts its timeout loop, the way newWebRTCConn does with the production one.
func newTimeoutTestConn(t *testing.T, pc *webrtc.PeerConnection, pr *io.PipeReader, timeout time.Duration) *webRTCConn {
	t.Helper()

	conn := &webRTCConn{
		pc:                pc,
		pr:                pr,
		bytesLogger:       &stubBytesLogger{},
		activity:          make(chan struct{}, 100),
		sendMoreCh:        make(chan struct{}, 1),
		inactivityTimeout: timeout,
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn.cancelTimeoutLoop = cancel
	t.Cleanup(cancel)
	go conn.timeoutLoop(ctx)

	return conn
}

// The connection is dropped when nothing has been exchanged for a while, so
// that a vanished client does not hold a slot forever.
func TestWebRTCConnClosesOnInactivity(t *testing.T) {
	t.Parallel()

	sf := &SnowflakeProxy{KeepLocalAddresses: true}
	pc, err := sf.makeNewPeerConnection(webrtc.Configuration{}, make(chan struct{}))
	if err != nil {
		t.Fatalf("makeNewPeerConnection: %v", err)
	}
	pr, pw := io.Pipe()
	defer pw.Close()

	// Built by hand rather than with newWebRTCConn, so that the production
	// 30 second timeout can be replaced with one the test can wait for before
	// the loop starts reading it.
	conn := newTimeoutTestConn(t, pc, pr, 50*time.Millisecond)

	// Reads fail once the timeout closes the pipe.
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("Read succeeded after the inactivity timeout, want an error")
	}
	if err := pc.Close(); err != nil {
		t.Errorf("closing the peer connection: %v", err)
	}
}

// Activity resets the inactivity timer rather than merely delaying the close.
func TestWebRTCConnInactivityTimerIsReset(t *testing.T) {
	t.Parallel()

	sf := &SnowflakeProxy{KeepLocalAddresses: true}
	pc, err := sf.makeNewPeerConnection(webrtc.Configuration{}, make(chan struct{}))
	if err != nil {
		t.Fatalf("makeNewPeerConnection: %v", err)
	}
	defer pc.Close()
	pr, pw := io.Pipe()
	defer pw.Close()

	conn := newTimeoutTestConn(t, pc, pr, 200*time.Millisecond)

	for range 5 {
		conn.activity <- struct{}{}
		time.Sleep(50 * time.Millisecond)
	}

	// Still open: every write kept the timer from firing.
	go pw.Write([]byte("x"))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Errorf("the connection was closed despite the activity: %v", err)
	}
}

// Close tears down both the pipe and the peer connection, and must tolerate
// being called more than once.
func TestWebRTCConnCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	sf := &SnowflakeProxy{KeepLocalAddresses: true}
	pc, err := sf.makeNewPeerConnection(webrtc.Configuration{}, make(chan struct{}))
	if err != nil {
		t.Fatalf("makeNewPeerConnection: %v", err)
	}
	pr, pw := io.Pipe()
	defer pw.Close()

	conn := newWebRTCConn(pc, nil, pr, &stubBytesLogger{})
	for range 3 {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("Read succeeded after Close, want an error")
	}
}
