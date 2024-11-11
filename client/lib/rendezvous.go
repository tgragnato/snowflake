// WebRTC rendezvous requires the exchange of SessionDescriptions between
// peers in order to establish a PeerConnection.

package snowflake_client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	utls "github.com/refraction-networking/utls"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/certs"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/messages"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/nat"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/util"
	utlsutil "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/utls"
)

const (
	brokerErrorUnexpected string = "Unexpected error, no answer."
	rendezvousErrorMsg    string = "One of SQS, AmpCache, or Domain Fronting rendezvous methods must be used."

	readLimit = 100000 //Maximum number of bytes to be read from an HTTP response
)

// RendezvousMethod represents a way of communicating with the broker: sending
// an encoded client poll request (SDP offer) and receiving an encoded client
// poll response (SDP answer) in return. RendezvousMethod is used by
// BrokerChannel, which is in charge of encoding and decoding, and all other
// tasks that are independent of the rendezvous method.
type RendezvousMethod interface {
	Exchange([]byte) ([]byte, error)
}

// BrokerChannel uses a RendezvousMethod to communicate with the Snowflake broker.
// The BrokerChannel is responsible for encoding and decoding SDP offers and answers;
// RendezvousMethod is responsible for the exchange of encoded information.
type BrokerChannel struct {
	Rendezvous         RendezvousMethod
	keepLocalAddresses bool
	natType            string
	lock               sync.Mutex
	BridgeFingerprint  string
}

// We make a copy of DefaultTransport because we want the default Dial
// and TLSHandshakeTimeout settings. But we want to disable the default
// ProxyFromEnvironment setting.
func createBrokerTransport(proxy *url.URL) http.RoundTripper {
	tlsConfig := &tls.Config{
		RootCAs: certs.GetRootCAs(),
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	transport.Proxy = nil
	if proxy != nil {
		transport.Proxy = http.ProxyURL(proxy)
	}
	transport.ResponseHeaderTimeout = 15 * time.Second
	return transport
}

func newBrokerChannelFromConfig(config ClientConfig) (*BrokerChannel, error) {
	log.Println("Rendezvous using Broker at:", config.BrokerURL)

	if len(config.FrontDomains) != 0 {
		log.Printf("Domain fronting using a randomly selected domain from: %v", config.FrontDomains)
	}

	brokerTransport := createBrokerTransport(config.CommunicationProxy)

	if config.UTLSClientID != "" {
		utlsClientHelloID, err := utlsutil.NameToUTLSID(config.UTLSClientID)
		if err != nil {
			return nil, fmt.Errorf("unable to create broker channel: %w", err)
		}
		utlsConfig := &utls.Config{
			RootCAs: certs.GetRootCAs(),
		}
		brokerTransport = utlsutil.NewUTLSHTTPRoundTripperWithProxy(utlsClientHelloID, utlsConfig, brokerTransport,
			config.UTLSRemoveSNI, config.CommunicationProxy)
	}

	var rendezvous RendezvousMethod
	var err error
	if config.SQSQueueURL != "" {
		if config.AmpCacheURL != "" || config.BrokerURL != "" {
			log.Fatalln("Multiple rendezvous methods specified. " + rendezvousErrorMsg)
		}
		if config.SQSCredsStr == "" {
			log.Fatalln("sqscreds must be specified to use SQS rendezvous method.")
		}
		log.Println("Through SQS queue at:", config.SQSQueueURL)
		rendezvous, err = newSQSRendezvous(config.SQSQueueURL, config.SQSCredsStr, brokerTransport)
	} else if config.AmpCacheURL != "" && config.BrokerURL != "" {
		log.Println("Through AMP cache at:", config.AmpCacheURL)
		rendezvous, err = newAMPCacheRendezvous(
			config.BrokerURL, config.AmpCacheURL, config.FrontDomains,
			brokerTransport)
	} else if config.BrokerURL != "" {
		rendezvous, err = newHTTPRendezvous(
			config.BrokerURL, config.FrontDomains, brokerTransport)
	} else {
		log.Fatalln("No rendezvous method was specified. " + rendezvousErrorMsg)
	}
	if err != nil {
		return nil, err
	}

	return &BrokerChannel{
		Rendezvous:         rendezvous,
		keepLocalAddresses: config.KeepLocalAddresses,
		natType:            nat.NATUnknown,
		BridgeFingerprint:  config.BridgeFingerprint,
	}, nil
}

// Negotiate uses a RendezvousMethod to send the client's WebRTC SDP offer
// and receive a snowflake proxy WebRTC SDP answer in return.
func (bc *BrokerChannel) Negotiate(offer *webrtc.SessionDescription) (
	*webrtc.SessionDescription, error,
) {
	// Ideally, we could specify an `RTCIceTransportPolicy` that would handle
	// this for us.  However, "public" was removed from the draft spec.
	// See https://developer.mozilla.org/en-US/docs/Web/API/RTCConfiguration#RTCIceTransportPolicy_enum
	if !bc.keepLocalAddresses {
		offer = &webrtc.SessionDescription{
			Type: offer.Type,
			SDP:  util.StripLocalAddresses(offer.SDP),
		}
	}
	offerSDP, err := util.SerializeSessionDescription(offer)
	if err != nil {
		return nil, err
	}

	// Encode the client poll request.
	bc.lock.Lock()
	req := &messages.ClientPollRequest{
		Offer:       offerSDP,
		NAT:         bc.natType,
		Fingerprint: bc.BridgeFingerprint,
	}
	encReq, err := req.EncodeClientPollRequest()
	bc.lock.Unlock()
	if err != nil {
		return nil, err
	}

	// Do the exchange using our RendezvousMethod.
	encResp, err := bc.Rendezvous.Exchange(encReq)
	if err != nil {
		return nil, err
	}
	log.Printf("Received answer: %s", string(encResp))

	// Decode the client poll response.
	resp, err := messages.DecodeClientPollResponse(encResp)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return util.DeserializeSessionDescription(resp.Answer)
}

// SetNATType sets the NAT type of the client so we can send it to the WebRTC broker.
func (bc *BrokerChannel) SetNATType(NATType string) {
	bc.lock.Lock()
	bc.natType = NATType
	bc.lock.Unlock()
	log.Printf("NAT Type: %s", NATType)
}

// WebRTCDialer implements the |Tongue| interface to catch snowflakes, using BrokerChannel.
type WebRTCDialer struct {
	*BrokerChannel
	webrtcConfig *webrtc.Configuration
	max          int

	eventLogger event.SnowflakeEventReceiver
	proxy       *url.URL
}

// Deprecated: Use NewWebRTCDialerWithEventsAndProxy instead
func NewWebRTCDialer(broker *BrokerChannel, iceServers []webrtc.ICEServer, max int) *WebRTCDialer {
	return NewWebRTCDialerWithEventsAndProxy(broker, iceServers, max, nil, nil)
}

// Deprecated: Use NewWebRTCDialerWithEventsAndProxy instead
func NewWebRTCDialerWithEvents(broker *BrokerChannel, iceServers []webrtc.ICEServer, max int, eventLogger event.SnowflakeEventReceiver) *WebRTCDialer {
	return NewWebRTCDialerWithEventsAndProxy(broker, iceServers, max, eventLogger, nil)
}

// NewWebRTCDialerWithEventsAndProxy constructs a new WebRTCDialer.
func NewWebRTCDialerWithEventsAndProxy(broker *BrokerChannel, iceServers []webrtc.ICEServer, max int,
	eventLogger event.SnowflakeEventReceiver, proxy *url.URL,
) *WebRTCDialer {
	config := webrtc.Configuration{
		ICEServers: iceServers,
	}

	return &WebRTCDialer{
		BrokerChannel: broker,
		webrtcConfig:  &config,
		max:           max,

		eventLogger: eventLogger,
		proxy:       proxy,
	}
}

// Catch initializes a WebRTC Connection by signaling through the BrokerChannel.
func (w WebRTCDialer) Catch() (*WebRTCPeer, error) {
	// TODO: [#25591] Fetch ICE server information from Broker.
	// TODO: [#25596] Consider TURN servers here too.
	return NewWebRTCPeerWithEventsAndProxy(w.webrtcConfig, w.BrokerChannel, w.eventLogger, w.proxy)
}

// GetMax returns the maximum number of snowflakes to collect.
func (w WebRTCDialer) GetMax() int {
	return w.max
}
