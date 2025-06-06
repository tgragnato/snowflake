package snowflake_client

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/transport/v3"
	"github.com/pion/transport/v3/stdnet"
	"github.com/pion/webrtc/v4"
	"tgragnato.it/snowflake/common/event"
	"tgragnato.it/snowflake/common/proxy"
	"tgragnato.it/snowflake/common/util"
)

// WebRTCPeer represents a WebRTC connection to a remote snowflake proxy.
//
// Each WebRTCPeer only ever has one DataChannel that is used as the peer's transport.
type WebRTCPeer struct {
	id        string
	pc        *webrtc.PeerConnection
	transport *webrtc.DataChannel

	recvPipe  *io.PipeReader
	writePipe *io.PipeWriter

	mu          sync.Mutex // protects the following:
	lastReceive time.Time

	open   chan struct{} // Channel to notify when datachannel opens
	closed chan struct{}

	once sync.Once // Synchronization for PeerConnection destruction

	bytesLogger  bytesLogger
	eventsLogger event.SnowflakeEventReceiver
	proxy        *url.URL
}

// Deprecated: Use NewWebRTCPeerWithNatPolicyAndEventsAndProxy Instead.
func NewWebRTCPeer(
	config *webrtc.Configuration, broker *BrokerChannel,
) (*WebRTCPeer, error) {
	return NewWebRTCPeerWithNatPolicyAndEventsAndProxy(
		config, broker, nil, nil, nil,
	)
}

// Deprecated: Use NewWebRTCPeerWithNatPolicyAndEventsAndProxy Instead.
func NewWebRTCPeerWithEvents(
	config *webrtc.Configuration, broker *BrokerChannel,
	eventsLogger event.SnowflakeEventReceiver,
) (*WebRTCPeer, error) {
	return NewWebRTCPeerWithNatPolicyAndEventsAndProxy(
		config, broker, nil, eventsLogger, nil,
	)
}

// Deprecated: Use NewWebRTCPeerWithNatPolicyAndEventsAndProxy Instead.
func NewWebRTCPeerWithEventsAndProxy(
	config *webrtc.Configuration, broker *BrokerChannel,
	eventsLogger event.SnowflakeEventReceiver, proxy *url.URL,
) (*WebRTCPeer, error) {
	return NewWebRTCPeerWithNatPolicyAndEventsAndProxy(
		config, broker, nil, eventsLogger, proxy,
	)
}

// NewWebRTCPeerWithNatPolicyAndEventsAndProxy constructs
// a WebRTC PeerConnection to a snowflake proxy.
//
// The creation of the peer handles the signaling to the Snowflake broker, including
// the exchange of SDP information, the creation of a PeerConnection, and the establishment
// of a DataChannel to the Snowflake proxy.
func NewWebRTCPeerWithNatPolicyAndEventsAndProxy(
	config *webrtc.Configuration, broker *BrokerChannel, natPolicy *NATPolicy,
	eventsLogger event.SnowflakeEventReceiver, proxy *url.URL,
) (*WebRTCPeer, error) {
	if eventsLogger == nil {
		eventsLogger = event.NewSnowflakeEventDispatcher()
	}

	connection := new(WebRTCPeer)
	{
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			panic(err)
		}
		connection.id = "snowflake-" + hex.EncodeToString(buf[:])
	}
	connection.closed = make(chan struct{})

	// Override with something that's not NullLogger to have real logging.
	connection.bytesLogger = &bytesNullLogger{}

	// Pipes remain the same even when DataChannel gets switched.
	connection.recvPipe, connection.writePipe = io.Pipe()

	connection.eventsLogger = eventsLogger
	connection.proxy = proxy

	err := connection.connect(config, broker, natPolicy)
	if err != nil {
		connection.Close()
		return nil, err
	}
	return connection, nil
}

// Read bytes from local SOCKS.
// As part of |io.ReadWriter|
func (c *WebRTCPeer) Read(b []byte) (int, error) {
	return c.recvPipe.Read(b)
}

// Writes bytes out to remote WebRTC.
// As part of |io.ReadWriter|
func (c *WebRTCPeer) Write(b []byte) (int, error) {
	err := c.transport.Send(b)
	if err != nil {
		return 0, err
	}
	c.bytesLogger.addOutbound(int64(len(b)))
	return len(b), nil
}

// Closed returns a boolean indicated whether the peer is closed.
func (c *WebRTCPeer) Closed() bool {
	select {
	case <-c.closed:
		return true
	default:
	}
	return false
}

// Close closes the connection the snowflake proxy.
func (c *WebRTCPeer) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.cleanup()
		log.Printf("WebRTC: Closing")
	})
	return nil
}

// Prevent long-lived broken remotes.
// Should also update the DataChannel in underlying go-webrtc's to make Closes
// more immediate / responsive.
func (c *WebRTCPeer) checkForStaleness(timeout time.Duration) {
	c.mu.Lock()
	c.lastReceive = time.Now()
	c.mu.Unlock()
	for {
		c.mu.Lock()
		lastReceive := c.lastReceive
		c.mu.Unlock()
		if time.Since(lastReceive) > timeout {
			log.Printf("WebRTC: No messages received for %v -- closing stale connection.",
				timeout)
			err := errors.New("no messages received, closing stale connection")
			c.eventsLogger.OnNewSnowflakeEvent(event.EventOnSnowflakeConnectionFailed{Error: err})
			c.Close()
			return
		}
		select {
		case <-c.closed:
			return
		case <-time.After(time.Second):
		}
	}
}

// connect does the bulk of the work: gather ICE candidates, send the SDP offer to broker,
// receive an answer from broker, and wait for data channel to open.
//
// `natPolicy` can be nil, in which case we'll always send our actual
// NAT type to the broker.
func (c *WebRTCPeer) connect(
	config *webrtc.Configuration,
	broker *BrokerChannel,
	natPolicy *NATPolicy,
) error {
	log.Println(c.id, " connecting...")

	err := c.preparePeerConnection(config, broker.keepLocalAddresses)
	localDescription := c.pc.LocalDescription()
	c.eventsLogger.OnNewSnowflakeEvent(event.EventOnOfferCreated{
		WebRTCLocalDescription: localDescription,
		Error:                  err,
	})
	if err != nil {
		return err
	}

	actualNatType := broker.GetNATType()
	var natTypeToSend string
	if natPolicy != nil {
		natTypeToSend = natPolicy.NATTypeToSend(actualNatType)
	} else {
		natTypeToSend = actualNatType
	}
	if natTypeToSend != actualNatType {
		log.Printf(
			"Our NAT type is \"%v\", but let's tell the broker it's \"%v\".",
			actualNatType,
			natTypeToSend,
		)
	} else {
		log.Printf("natTypeToSend: \"%v\" (same as actualNatType)", natTypeToSend)
	}

	answer, err := broker.Negotiate(localDescription, natTypeToSend)
	c.eventsLogger.OnNewSnowflakeEvent(event.EventOnBrokerRendezvous{
		WebRTCRemoteDescription: answer,
		Error:                   err,
	})
	if err != nil {
		return err
	}
	log.Printf("Received Answer.\n")
	err = c.pc.SetRemoteDescription(*answer)
	if nil != err {
		log.Println("WebRTC: Unable to SetRemoteDescription:", err)
		return err
	}

	// Wait for the datachannel to open or time out
	select {
	case <-c.open:
		if natPolicy != nil {
			natPolicy.Success(actualNatType, natTypeToSend)
		}
	case <-time.After(DataChannelTimeout):
		c.transport.Close()
		err := errors.New("timeout waiting for DataChannel.OnOpen")
		if natPolicy != nil {
			natPolicy.Failure(actualNatType, natTypeToSend)
		}
		c.eventsLogger.OnNewSnowflakeEvent(event.EventOnSnowflakeConnectionFailed{Error: err})
		return err
	}

	go c.checkForStaleness(SnowflakeTimeout)
	return nil
}

// preparePeerConnection creates a new WebRTC PeerConnection and returns it
// after non-trickle ICE candidate gathering is complete.
func (c *WebRTCPeer) preparePeerConnection(
	config *webrtc.Configuration,
	keepLocalAddresses bool,
) error {
	s := webrtc.SettingEngine{}

	if !keepLocalAddresses {
		s.SetIPFilter(func(ip net.IP) (keep bool) {
			// `IsLoopback()` and `IsUnspecified` are likely not neded here,
			// but let's keep them just in case.
			// FYI there is similar code in other files in this project.
			keep = !util.IsLocal(ip) && !ip.IsLoopback() && !ip.IsUnspecified()
			return
		})
		s.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	}
	s.SetIncludeLoopbackCandidate(keepLocalAddresses)

	// Use the SetNet setting https://pkg.go.dev/github.com/pion/webrtc/v3#SettingEngine.SetNet
	// to get snowflake working in shadow (where the AF_NETLINK family is not implemented).
	// These two lines of code functionally revert a new change in pion by silently ignoring
	// when net.Interfaces() fails, rather than throwing an error
	var vnet transport.Net
	vnet, _ = stdnet.NewNet()

	if c.proxy != nil {
		if err := proxy.CheckProxyProtocolSupport(c.proxy); err != nil {
			return err
		}
		socksClient := proxy.NewSocks5UDPClient(c.proxy)
		vnet = proxy.NewTransportWrapper(&socksClient, vnet)
	}

	s.SetNet(vnet)

	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	var err error
	c.pc, err = api.NewPeerConnection(*config)
	if err != nil {
		log.Printf("NewPeerConnection ERROR: %s", err)
		return err
	}
	ordered := true
	dataChannelOptions := &webrtc.DataChannelInit{
		Ordered: &ordered,
	}
	// We must create the data channel before creating an offer
	// https://github.com/pion/webrtc/wiki/Release-WebRTC@v3.0.0#a-data-channel-is-no-longer-implicitly-created-with-a-peerconnection
	dc, err := c.pc.CreateDataChannel(c.id, dataChannelOptions)
	if err != nil {
		log.Printf("CreateDataChannel ERROR: %s", err)
		return err
	}
	dc.OnOpen(func() {
		c.eventsLogger.OnNewSnowflakeEvent(event.EventOnSnowflakeConnected{})
		log.Println("WebRTC: DataChannel.OnOpen")
		close(c.open)
	})
	dc.OnClose(func() {
		log.Println("WebRTC: DataChannel.OnClose")
		c.Close()
	})
	dc.OnError(func(err error) {
		c.eventsLogger.OnNewSnowflakeEvent(event.EventOnSnowflakeConnectionFailed{Error: err})
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if len(msg.Data) <= 0 {
			log.Println("0 length message---")
		}
		n, err := c.writePipe.Write(msg.Data)
		c.bytesLogger.addInbound(int64(n))
		if err != nil {
			// TODO: Maybe shouldn't actually close.
			log.Println("Error writing to SOCKS pipe")
			if inerr := c.writePipe.CloseWithError(err); inerr != nil {
				log.Printf("c.writePipe.CloseWithError returned error: %v", inerr)
			}
		}
		c.mu.Lock()
		c.lastReceive = time.Now()
		c.mu.Unlock()
	})
	c.transport = dc
	c.open = make(chan struct{})
	log.Println("WebRTC: DataChannel created")

	offer, err := c.pc.CreateOffer(nil)
	// TODO: Potentially timeout and retry if ICE isn't working.
	if err != nil {
		log.Println("Failed to prepare offer", err)
		c.pc.Close()
		return err
	}
	log.Println("WebRTC: Created offer")

	// Allow candidates to accumulate until ICEGatheringStateComplete.
	done := webrtc.GatheringCompletePromise(c.pc)
	// Start gathering candidates
	err = c.pc.SetLocalDescription(offer)
	if err != nil {
		log.Println("Failed to apply offer", err)
		c.pc.Close()
		return err
	}
	log.Println("WebRTC: Set local description")

	<-done // Wait for ICE candidate gathering to complete.

	return nil
}

// cleanup closes all channels and transports
func (c *WebRTCPeer) cleanup() {
	// Close this side of the SOCKS pipe.
	if c.writePipe != nil { // c.writePipe can be nil in tests.
		c.writePipe.Close()
	}
	if nil != c.transport {
		log.Printf("WebRTC: closing DataChannel")
		c.transport.Close()
	}
	if nil != c.pc {
		log.Printf("WebRTC: closing PeerConnection")
		err := c.pc.Close()
		if nil != err {
			log.Printf("Error closing peerconnection...")
		}
	}
}
