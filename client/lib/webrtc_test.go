package snowflake_client

import (
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"tgragnato.it/snowflake/common/event"
	"tgragnato.it/snowflake/common/messages"
	"tgragnato.it/snowflake/common/util"
)

// newLocalPeer prepares a PeerConnection that gathers only local candidates, so
// that the test needs neither a STUN server nor a reachable network.
func newLocalPeer(t *testing.T) *WebRTCPeer {
	t.Helper()

	peer := &WebRTCPeer{
		id:           "snowflake-test",
		closed:       make(chan struct{}),
		bytesLogger:  &bytesNullLogger{},
		eventsLogger: event.NewSnowflakeEventDispatcher(),
	}
	peer.recvPipe, peer.writePipe = io.Pipe()
	if err := peer.preparePeerConnection(&webrtc.Configuration{}, true); err != nil {
		t.Fatalf("preparePeerConnection: %v", err)
	}
	t.Cleanup(func() { peer.Close() })
	return peer
}

// Each of the deprecated constructors must still reach the broker and report
// its failure, rather than handing back a half-built peer.
func TestNewWebRTCPeerConstructorsReportBrokerFailure(t *testing.T) {
	t.Parallel()

	config := &webrtc.Configuration{}
	proxyURL := (*url.URL)(nil)

	for name, construct := range map[string]func(*BrokerChannel) (*WebRTCPeer, error){
		"NewWebRTCPeer": func(b *BrokerChannel) (*WebRTCPeer, error) {
			return NewWebRTCPeer(config, b)
		},
		"NewWebRTCPeerWithEvents": func(b *BrokerChannel) (*WebRTCPeer, error) {
			return NewWebRTCPeerWithEvents(config, b, event.NewSnowflakeEventDispatcher())
		},
		"NewWebRTCPeerWithEventsAndProxy": func(b *BrokerChannel) (*WebRTCPeer, error) {
			return NewWebRTCPeerWithEventsAndProxy(config, b, nil, proxyURL)
		},
	} {
		t.Run(name, func(t *testing.T) {
			broker := newStubBroker()
			peer, err := construct(broker)
			if err == nil {
				peer.Close()
				t.Fatal("construction succeeded, want an error")
			}
			if peer != nil {
				t.Errorf("peer = %v, want nil on error", peer)
			}
			if got := broker.Rendezvous.(*stubRendezvous).exchanges(); got != 1 {
				t.Errorf("broker exchanges = %d, want 1", got)
			}
		})
	}
}

// An answer that is well-formed at the message layer but not valid SDP has to
// be rejected by the PeerConnection, not passed on to the data channel.
func TestWebRTCPeerRejectsUnusableAnswer(t *testing.T) {
	t.Parallel()

	answer, err := util.SerializeSessionDescription(&webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  "this is not an SDP body",
	})
	if err != nil {
		t.Fatalf("SerializeSessionDescription: %v", err)
	}
	encResp, err := (&messages.ClientPollResponse{Answer: answer}).EncodePollResponse()
	if err != nil {
		t.Fatalf("EncodePollResponse: %v", err)
	}

	broker := newStubBroker()
	broker.Rendezvous = &stubRendezvous{resp: encResp}

	peer, err := NewWebRTCPeer(&webrtc.Configuration{}, broker)
	if err == nil {
		peer.Close()
		t.Fatal("construction succeeded with an unusable answer, want an error")
	}
}

// The broker reporting an error (no proxies available, for instance) must
// surface as a failed connection attempt.
func TestWebRTCPeerReportsBrokerError(t *testing.T) {
	t.Parallel()

	encResp, err := (&messages.ClientPollResponse{Error: "no snowflake proxies currently available"}).EncodePollResponse()
	if err != nil {
		t.Fatalf("EncodePollResponse: %v", err)
	}

	broker := newStubBroker()
	broker.Rendezvous = &stubRendezvous{resp: encResp}

	receiver := &recordingReceiver{}
	peer, err := NewWebRTCPeerWithEvents(&webrtc.Configuration{}, broker, receiver)
	if err == nil {
		peer.Close()
		t.Fatal("construction succeeded, want an error")
	}
	// The offer and the rendezvous outcome are both reported to listeners.
	if got := receiver.count(); got < 2 {
		t.Errorf("listener received %d events, want at least 2", got)
	}
}

// The peer prepares a data channel and a local offer before contacting the
// broker; without them there would be nothing to send.
func TestWebRTCPeerPreparesOffer(t *testing.T) {
	t.Parallel()

	peer := newLocalPeer(t)

	if peer.pc == nil {
		t.Fatal("PeerConnection is nil")
	}
	if peer.transport == nil {
		t.Fatal("DataChannel is nil")
	}
	description := peer.pc.LocalDescription()
	if description == nil {
		t.Fatal("LocalDescription is nil")
	}
	if description.Type != webrtc.SDPTypeOffer {
		t.Errorf("local description type = %v, want an offer", description.Type)
	}
}

// Reads come from the pipe fed by the data channel's OnMessage callback.
func TestWebRTCPeerRead(t *testing.T) {
	t.Parallel()

	peer := &WebRTCPeer{closed: make(chan struct{}), bytesLogger: &bytesNullLogger{}}
	peer.recvPipe, peer.writePipe = io.Pipe()

	want := "payload from the proxy"
	go func() {
		peer.writePipe.Write([]byte(want))
		peer.writePipe.Close()
	}()

	got, err := io.ReadAll(peer)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Writing before the data channel has opened must return an error instead of
// silently dropping the bytes.
func TestWebRTCPeerWriteBeforeOpen(t *testing.T) {
	t.Parallel()

	peer := newLocalPeer(t)

	n, err := peer.Write([]byte("payload"))
	if err == nil {
		t.Fatal("Write succeeded on an unopened data channel, want an error")
	}
	if n != 0 {
		t.Errorf("wrote %d bytes, want 0", n)
	}
}

// Close is called from several goroutines (the staleness check, the data
// channel callbacks, the collector), so it has to be idempotent.
func TestWebRTCPeerCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	peer := newLocalPeer(t)

	if peer.Closed() {
		t.Fatal("a fresh peer reports itself closed")
	}
	for range 3 {
		if err := peer.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
	if !peer.Closed() {
		t.Error("peer does not report itself closed after Close")
	}
}

// A peer that is closed while the staleness check is running must not keep the
// goroutine alive.
func TestWebRTCPeerStalenessStopsOnClose(t *testing.T) {
	t.Parallel()

	peer := &WebRTCPeer{
		closed:       make(chan struct{}),
		eventsLogger: event.NewSnowflakeEventDispatcher(),
	}

	done := make(chan struct{})
	go func() {
		peer.checkForStaleness(time.Minute)
		close(done)
	}()

	peer.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("the staleness check outlived the peer")
	}
}
