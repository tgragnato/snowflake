package snowflake_client

import (
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"tgragnato.it/snowflake/common/event"
	"tgragnato.it/snowflake/common/nat"
)

// stubRendezvous stands in for a broker: it never touches the network and
// always fails the exchange, which is what lets the WebRTC code paths run to
// completion offline.
type stubRendezvous struct {
	mu    sync.Mutex
	calls int
	resp  []byte
	err   error
}

func (s *stubRendezvous) Exchange([]byte) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.resp, s.err
}

func (s *stubRendezvous) exchanges() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// newStubBroker returns a BrokerChannel whose rendezvous always fails, and that
// keeps local ICE candidates so that gathering completes without a STUN server.
func newStubBroker() *BrokerChannel {
	return &BrokerChannel{
		Rendezvous:         &stubRendezvous{err: errors.New("broker unavailable")},
		keepLocalAddresses: true,
		natType:            nat.NATUnknown,
	}
}

// recordingReceiver collects the events dispatched to it.
type recordingReceiver struct {
	mu     sync.Mutex
	events []event.SnowflakeEvent
}

func (r *recordingReceiver) OnNewSnowflakeEvent(e event.SnowflakeEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recordingReceiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// The KCP session is built over a placeholder address, since the real transport
// is a sequence of WebRTC connections rather than a single socket.
func TestDummyAddr(t *testing.T) {
	t.Parallel()

	var addr dummyAddr
	if got := addr.Network(); got != "dummy" {
		t.Errorf("Network() = %q, want %q", got, "dummy")
	}
	if got := addr.String(); got != "dummy" {
		t.Errorf("String() = %q, want %q", got, "dummy")
	}
}

// A misspelled uTLS client ID must fail loudly at construction time: silently
// falling back to Go's TLS stack would change the client's fingerprint.
func TestNewSnowflakeClientRejectsUnknownUTLSClientID(t *testing.T) {
	t.Parallel()

	_, err := NewSnowflakeClient(ClientConfig{
		BrokerURL:    "https://broker.example.com",
		UTLSClientID: "not-a-browser",
	})
	if err == nil {
		t.Fatal("NewSnowflakeClient succeeded, want an error")
	}
}

func TestNewSnowflakeClientCapacity(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		max     int
		wantMax int
	}{
		{"unset defaults to one", 0, 1},
		{"negative defaults to one", -3, 1},
		{"honoured when above the default", 5, 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport, err := NewSnowflakeClient(ClientConfig{
				BrokerURL: "https://broker.example.com",
				Max:       test.max,
			})
			if err != nil {
				t.Fatalf("NewSnowflakeClient: %v", err)
			}
			if got := transport.dialer.GetMax(); got != test.wantMax {
				t.Errorf("GetMax() = %d, want %d", got, test.wantMax)
			}
		})
	}
}

// The deprecated single FrontDomain field must keep working: torrc files in the
// wild still set it.
func TestNewSnowflakeClientKeepsLegacyFrontDomain(t *testing.T) {
	t.Parallel()

	transport, err := NewSnowflakeClient(ClientConfig{
		BrokerURL:   "https://broker.example.com",
		FrontDomain: "front.example.com",
	})
	if err != nil {
		t.Fatalf("NewSnowflakeClient: %v", err)
	}
	rendezvous, ok := transport.dialer.Rendezvous.(*httpRendezvous)
	if !ok {
		t.Fatalf("Rendezvous = %T, want *httpRendezvous", transport.dialer.Rendezvous)
	}
	if got := rendezvous.fronts; len(got) != 1 || got[0] != "front.example.com" {
		t.Errorf("fronts = %v, want [front.example.com]", got)
	}
}

// At most half of the configured ICE servers are used, so that a client does
// not contact every server in the list on every run.
func TestNewSnowflakeClientSubsetsICEServers(t *testing.T) {
	t.Parallel()

	transport, err := NewSnowflakeClient(ClientConfig{
		BrokerURL: "https://broker.example.com",
		ICEAddresses: []string{
			"stun:stun1.example.com:3478",
			"stun:stun2.example.com:3478",
			"stun:stun3.example.com:3478",
			"stun:stun4.example.com:3478",
		},
	})
	if err != nil {
		t.Fatalf("NewSnowflakeClient: %v", err)
	}
	if got := len(transport.dialer.webrtcConfig.ICEServers); got != 2 {
		t.Errorf("used %d of 4 ICE servers, want 2", got)
	}
}

// The rendezvous method is picked from the configuration; uTLS only changes the
// transport underneath it.
func TestNewBrokerChannelRendezvousSelection(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		config ClientConfig
		want   string
	}{
		{
			name:   "broker URL alone means plain HTTP rendezvous",
			config: ClientConfig{BrokerURL: "https://broker.example.com"},
			want:   "*snowflake_client.httpRendezvous",
		},
		{
			name: "an AMP cache URL switches to AMP rendezvous",
			config: ClientConfig{
				BrokerURL:   "https://broker.example.com",
				AmpCacheURL: "https://amp.example.com/",
			},
			want: "*snowflake_client.ampCacheRendezvous",
		},
		{
			name: "uTLS keeps the selected rendezvous method",
			config: ClientConfig{
				BrokerURL:     "https://broker.example.com",
				UTLSClientID:  "HelloFirefox_Auto",
				UTLSRemoveSNI: true,
			},
			want: "*snowflake_client.httpRendezvous",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			broker, err := newBrokerChannelFromConfig(test.config)
			if err != nil {
				t.Fatalf("newBrokerChannelFromConfig: %v", err)
			}
			if got := fmt.Sprintf("%T", broker.Rendezvous); got != test.want {
				t.Errorf("Rendezvous = %s, want %s", got, test.want)
			}
			if got := broker.GetNATType(); got != nat.NATUnknown {
				t.Errorf("initial NAT type = %q, want %q", got, nat.NATUnknown)
			}
		})
	}
}

// The deprecated dialer constructors have to keep wiring up the event logger,
// since library users still call them.
func TestWebRTCDialerDeprecatedConstructors(t *testing.T) {
	t.Parallel()

	broker := newStubBroker()
	receiver := &recordingReceiver{}

	dialer := NewWebRTCDialerWithEvents(broker, nil, 3, receiver)
	if dialer.eventLogger != receiver {
		t.Error("NewWebRTCDialerWithEvents did not keep the event logger")
	}
	if got := dialer.GetMax(); got != 3 {
		t.Errorf("GetMax() = %d, want 3", got)
	}

	dialer = NewWebRTCDialerWithEventsAndProxy(broker, nil, 1, receiver, nil)
	if dialer.eventLogger != receiver {
		t.Error("NewWebRTCDialerWithEventsAndProxy did not keep the event logger")
	}
	if dialer.proxy != nil {
		t.Errorf("proxy = %v, want nil", dialer.proxy)
	}
}

func TestTransportSetRendezvousMethod(t *testing.T) {
	t.Parallel()

	transport := &Transport{dialer: NewWebRTCDialer(newStubBroker(), nil, 1)}
	replacement := &stubRendezvous{}
	transport.SetRendezvousMethod(replacement)

	if transport.dialer.Rendezvous != replacement {
		t.Error("SetRendezvousMethod did not replace the rendezvous method")
	}
}

func TestTransportEventListeners(t *testing.T) {
	t.Parallel()

	dispatcher := event.NewSnowflakeEventDispatcher()
	transport := &Transport{eventDispatcher: dispatcher}
	receiver := &recordingReceiver{}

	transport.AddSnowflakeEventListener(receiver)
	dispatcher.OnNewSnowflakeEvent(event.EventOnSnowflakeConnected{})
	if got := receiver.count(); got != 1 {
		t.Fatalf("registered listener received %d events, want 1", got)
	}

	transport.RemoveSnowflakeEventListener(receiver)
	dispatcher.OnNewSnowflakeEvent(event.EventOnSnowflakeConnected{})
	if got := receiver.count(); got != 1 {
		t.Errorf("removed listener received %d events, want 1", got)
	}
}

// When no STUN server can tell us our NAT type, we report "unknown" rather than
// leaving the previous value in place: the broker uses it for matching.
func TestUpdateNATTypeFallsBackToUnknown(t *testing.T) {
	t.Parallel()

	broker := newStubBroker()
	broker.SetNATType(nat.NAT3Open)

	// A URL with no host at all fails address resolution immediately.
	updateNATType([]webrtc.ICEServer{{URLs: []string{"stun:"}}}, broker, nil)

	if got := broker.GetNATType(); got != nat.NATUnknown {
		t.Errorf("NAT type = %q, want %q", got, nat.NATUnknown)
	}
}

// With no servers to try there is nothing to learn, so the NAT type must be
// left untouched.
func TestUpdateNATTypeWithoutServersKeepsCurrentType(t *testing.T) {
	t.Parallel()

	broker := newStubBroker()
	broker.SetNATType(nat.NAT3Moderate)

	updateNATType(nil, broker, nil)

	if got := broker.GetNATType(); got != nat.NAT3Moderate {
		t.Errorf("NAT type = %q, want %q", got, nat.NAT3Moderate)
	}
}

// fakeCollector is a SnowflakeCollector that hands out a fixed set of peers.
type fakeCollector struct {
	mu        sync.Mutex
	collected int
	collectFn func() (*WebRTCPeer, error)
	popFn     func() *WebRTCPeer
	melted    chan struct{}
	ended     bool
}

func (f *fakeCollector) Collect() (*WebRTCPeer, error) {
	f.mu.Lock()
	f.collected++
	f.mu.Unlock()
	if f.collectFn != nil {
		return f.collectFn()
	}
	return nil, errors.New("no snowflakes")
}

func (f *fakeCollector) Pop() *WebRTCPeer {
	if f.popFn != nil {
		return f.popFn()
	}
	return nil
}

func (f *fakeCollector) Melted() <-chan struct{} { return f.melted }

func (f *fakeCollector) End() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.ended {
		f.ended = true
		close(f.melted)
	}
}

func (f *fakeCollector) collectCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.collected
}

// The KCP session is created eagerly, before any snowflake is available: a
// proxy is only pulled from the collector once there is a packet to send.
func TestNewSessionDoesNotWaitForASnowflake(t *testing.T) {
	t.Parallel()

	collector := &fakeCollector{melted: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		pconn, sess, err := newSession(collector)
		if err != nil {
			t.Errorf("newSession: %v", err)
			return
		}
		sess.Close()
		pconn.Close()
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("newSession blocked waiting for a snowflake")
	}
}

// Closing the connection must also stop collecting snowflakes, otherwise the
// client would keep occupying proxies after the SOCKS connection is gone.
func TestSnowflakeConnCloseStopsCollecting(t *testing.T) {
	t.Parallel()

	peers := newTestPeers(t, 1)
	pconn, sess, err := newSession(peers)
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	conn := &SnowflakeConn{Stream: stream, sess: sess, pconn: pconn, snowflakes: peers}

	if err := conn.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	select {
	case <-peers.Melted():
	case <-time.After(5 * time.Second):
		t.Error("Close did not end the collection of snowflakes")
	}
	if !sess.IsClosed() {
		t.Error("Close left the smux session open")
	}
}

// connectLoop keeps retrying after a failed collection, and only returns once
// the collector has melted.
func TestConnectLoopRetriesUntilMelted(t *testing.T) {
	t.Parallel()

	collector := &fakeCollector{
		melted: make(chan struct{}),
		collectFn: func() (*WebRTCPeer, error) {
			return nil, errors.New("no proxy available")
		},
	}

	done := make(chan struct{})
	go func() {
		connectLoop(collector)
		close(done)
	}()

	// The first Collect happens immediately, before the retry timer.
	deadline := time.After(5 * time.Second)
	for collector.collectCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("connectLoop never called Collect")
		case <-time.After(10 * time.Millisecond):
		}
	}

	collector.End()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("connectLoop did not stop after the collector melted")
	}
}

// Dial hands back a usable stream even though no proxy has been found yet: the
// stream blocks on I/O rather than on being opened.
func TestTransportDial(t *testing.T) {
	t.Parallel()

	broker := newStubBroker()
	transport := &Transport{
		dialer:          NewWebRTCDialer(broker, nil, 1),
		eventDispatcher: event.NewSnowflakeEventDispatcher(),
	}

	conn, err := transport.Dial()
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if got := conn.LocalAddr(); got == nil {
		t.Error("LocalAddr() = nil, want the placeholder address")
	}
	// Close may report the failure of a redial that was in flight, since no
	// proxy is reachable here; what matters is that it returns.
	conn.Close()
}

// A proxy URL whose scheme we cannot speak must be rejected before any
// connection attempt, rather than being silently ignored.
func TestTransportRejectsUnsupportedProxy(t *testing.T) {
	t.Parallel()

	proxyURL, err := url.Parse("http://127.0.0.1:1080")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	dialer := NewWebRTCDialerWithEventsAndProxy(newStubBroker(), nil, 1, nil, proxyURL)

	if _, err := dialer.Catch(); err == nil {
		t.Error("Catch() succeeded with an unsupported proxy, want an error")
	}
}
