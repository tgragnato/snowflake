package snowflake_proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/pion/webrtc/v4"
	. "github.com/smartystreets/goconvey/convey"
	"tgragnato.it/snowflake/common/messages"
	"tgragnato.it/snowflake/common/util"
)

// Set up a mock broker to communicate with
type MockTransport struct {
	statusOverride int
	body           []byte
}

// Just returns a response with fake SDP answer.
func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s := io.NopCloser(bytes.NewReader(m.body))
	r := &http.Response{
		StatusCode: m.statusOverride,
		Body:       s,
	}
	return r, nil
}

// Set up a mock faulty transport
type FaultyTransport struct{}

// Just returns a response with fake SDP answer.
func (f *FaultyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("TransportFailed")
}

func TestRemoteIPFromSDP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		sdp      string
		expected net.IP
	}{
		// https://tools.ietf.org/html/rfc4566#section-5
		{`v=0
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5
s=SDP Seminar
i=A Seminar on the session description protocol
u=http://www.example.com/seminars/sdp.pdf
e=j.doe@example.com (Jane Doe)
c=IN IP4 224.2.17.12/127
t=2873397496 2873404696
a=recvonly
m=audio 49170 RTP/AVP 0
m=video 51372 RTP/AVP 99
a=rtpmap:99 h263-1998/90000
`, net.ParseIP("224.2.17.12")},
		// local addresses only
		{`v=0
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5
s=SDP Seminar
i=A Seminar on the session description protocol
u=http://www.example.com/seminars/sdp.pdf
e=j.doe@example.com (Jane Doe)
c=IN IP4 10.47.16.5/127
t=2873397496 2873404696
a=recvonly
m=audio 49170 RTP/AVP 0
m=video 51372 RTP/AVP 99
a=rtpmap:99 h263-1998/90000
`, nil},
		// Remote IP in candidate attribute only
		{`v=0
o=- 4358805017720277108 2 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 56688 DTLS/SCTP 5000
c=IN IP4 0.0.0.0
a=candidate:3769337065 1 udp 2122260223 1.2.3.4 56688 typ host generation 0 network-id 1 network-cost 50
a=ice-ufrag:aMAZ
a=ice-pwd:jcHb08Jjgrazp2dzjdrvPPvV
a=ice-options:trickle
a=fingerprint:sha-256 C8:88:EE:B9:E7:02:2E:21:37:ED:7A:D1:EB:2B:A3:15:A2:3B:5B:1C:3D:D4:D5:1F:06:CF:52:40:03:F8:DD:66
a=setup:actpass
a=mid:data
a=sctpmap:5000 webrtc-datachannel 1024
`, net.ParseIP("1.2.3.4")},
		// Unspecified address
		{`v=0
o=jdoe 2890844526 2890842807 IN IP4 0.0.0.0
s=SDP Seminar
i=A Seminar on the session description protocol
u=http://www.example.com/seminars/sdp.pdf
e=j.doe@example.com (Jane Doe)
t=2873397496 2873404696
a=recvonly
m=audio 49170 RTP/AVP 0
m=video 51372 RTP/AVP 99
a=rtpmap:99 h263-1998/90000
`, nil},
		// Missing c= line
		{`v=0
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5
s=SDP Seminar
i=A Seminar on the session description protocol
u=http://www.example.com/seminars/sdp.pdf
e=j.doe@example.com (Jane Doe)
t=2873397496 2873404696
a=recvonly
m=audio 49170 RTP/AVP 0
m=video 51372 RTP/AVP 99
a=rtpmap:99 h263-1998/90000
`, nil},
		// Single line, IP address only
		{`v=0
o=- 4358805017720277108 2 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 56688 DTLS/SCTP 5000
c=IN IP4 224.2.1.1
`, net.ParseIP("224.2.1.1")},
		// Same, with TTL
		{`v=0
o=- 4358805017720277108 2 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 56688 DTLS/SCTP 5000
c=IN IP4 224.2.1.1/127
`, net.ParseIP("224.2.1.1")},
		// Same, with TTL and multicast addresses
		{`v=0
o=- 4358805017720277108 2 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 56688 DTLS/SCTP 5000
c=IN IP4 224.2.1.1/127/3
`, net.ParseIP("224.2.1.1")},
		// IPv6, address only
		{`v=0
o=- 4358805017720277108 2 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 56688 DTLS/SCTP 5000
c=IN IP6 FF15::101
`, net.ParseIP("ff15::101")},
		// Same, with multicast addresses
		{`v=0
o=- 4358805017720277108 2 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 56688 DTLS/SCTP 5000
c=IN IP6 FF15::101/3
`, net.ParseIP("ff15::101")},
		// Multiple c= lines
		{`v=0
o=- 4358805017720277108 2 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 56688 DTLS/SCTP 5000
c=IN IP4 1.2.3.4
c=IN IP4 5.6.7.8
`, net.ParseIP("1.2.3.4")},
		// Modified from SDP sent by snowflake-client.
		{`v=0
o=- 7860378660295630295 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 54653 DTLS/SCTP 5000
c=IN IP4 1.2.3.4
a=candidate:3581707038 1 udp 2122260223 192.168.0.1 54653 typ host generation 0 network-id 1 network-cost 50
a=candidate:2617212910 1 tcp 1518280447 192.168.0.1 59673 typ host tcptype passive generation 0 network-id 1 network-cost 50
a=candidate:2082671819 1 udp 1686052607 1.2.3.4 54653 typ srflx raddr 192.168.0.1 rport 54653 generation 0 network-id 1 network-cost 50
a=ice-ufrag:IBdf
a=ice-pwd:G3lTrrC9gmhQx481AowtkhYz
a=fingerprint:sha-256 53:F8:84:D9:3C:1F:A0:44:AA:D6:3C:65:80:D3:CB:6F:23:90:17:41:06:F9:9C:10:D8:48:4A:A8:B6:FA:14:A1
a=setup:actpass
a=mid:data
a=sctpmap:5000 webrtc-datachannel 1024
`, net.ParseIP("1.2.3.4")},
		// Improper character within IPv4
		{`v=0
o=- 4358805017720277108 2 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 56688 DTLS/SCTP 5000
c=IN IP4 224.2z.1.1
`, nil},
		// Improper character within IPv6
		{`v=0
o=- 4358805017720277108 2 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 56688 DTLS/SCTP 5000
c=IN IP6 ff15:g::101
`, nil},
		// Bogus "IP7" addrtype
		{`v=0
o=- 4358805017720277108 2 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 56688 DTLS/SCTP 5000
c=IN IP7 1.2.3.4
`, nil},
	}

	for _, test := range tests {
		// https://tools.ietf.org/html/rfc4566#section-5: "The sequence
		// CRLF (0x0d0a) is used to end a record, although parsers
		// SHOULD be tolerant and also accept records terminated with a
		// single newline character." We represent the test cases with
		// LF line endings for convenience, and test them both that way
		// and with CRLF line endings.
		lfSDP := test.sdp
		crlfSDP := strings.Replace(lfSDP, "\n", "\r\n", -1)

		ip := remoteIPFromSDP(lfSDP)
		if !ip.Equal(test.expected) {
			t.Errorf("expected %q, got %q from %q", test.expected, ip, lfSDP)
		}
		ip = remoteIPFromSDP(crlfSDP)
		if !ip.Equal(test.expected) {
			t.Errorf("expected %q, got %q from %q", test.expected, ip, crlfSDP)
		}
	}
}

func TestSessionDescriptions(t *testing.T) {
	t.Parallel()

	Convey("Session description deserialization", t, func() {
		for _, test := range []struct {
			msg string
			ret *webrtc.SessionDescription
		}{
			{
				"test",
				nil,
			},
			{
				`{"type":"answer"}`,
				nil,
			},
			{
				`{"sdp":"test"}`,
				nil,
			},
			{
				`{"type":"test", "sdp":"test"}`,
				nil,
			},
			{
				`{"type":"answer", "sdp":"test"}`,
				&webrtc.SessionDescription{
					Type: webrtc.SDPTypeAnswer,
					SDP:  "test",
				},
			},
			{
				`{"type":"pranswer", "sdp":"test"}`,
				&webrtc.SessionDescription{
					Type: webrtc.SDPTypePranswer,
					SDP:  "test",
				},
			},
			{
				`{"type":"rollback", "sdp":"test"}`,
				&webrtc.SessionDescription{
					Type: webrtc.SDPTypeRollback,
					SDP:  "test",
				},
			},
			{
				`{"type":"offer", "sdp":"test"}`,
				&webrtc.SessionDescription{
					Type: webrtc.SDPTypeOffer,
					SDP:  "test",
				},
			},
		} {
			desc, _ := util.DeserializeSessionDescription(test.msg)
			So(desc, ShouldResemble, test.ret)
		}
	})
	Convey("Session description serialization", t, func() {
		for _, test := range []struct {
			desc *webrtc.SessionDescription
			ret  string
		}{
			{
				&webrtc.SessionDescription{
					Type: webrtc.SDPTypeOffer,
					SDP:  "test",
				},
				`{"type":"offer","sdp":"test"}`,
			},
		} {
			msg, err := util.SerializeSessionDescription(test.desc)
			So(msg, ShouldResemble, test.ret)
			So(err, ShouldBeNil)
		}
	})
}

func TestBrokerInteractions(t *testing.T) {
	t.Parallel()

	const sampleSDP = `"v=0\r\no=- 4358805017720277108 2 IN IP4 8.8.8.8\r\ns=-\r\nt=0 0\r\na=group:BUNDLE data\r\na=msid-semantic: WMS\r\nm=application 56688 DTLS/SCTP 5000\r\nc=IN IP4 8.8.8.8\r\na=candidate:3769337065 1 udp 2122260223 8.8.8.8 56688 typ host generation 0 network-id 1 network-cost 50\r\na=candidate:2921887769 1 tcp 1518280447 8.8.8.8 35441 typ host tcptype passive generation 0 network-id 1 network-cost 50\r\na=ice-ufrag:aMAZ\r\na=ice-pwd:jcHb08Jjgrazp2dzjdrvPPvV\r\na=ice-options:trickle\r\na=fingerprint:sha-256 C8:88:EE:B9:E7:02:2E:21:37:ED:7A:D1:EB:2B:A3:15:A2:3B:5B:1C:3D:D4:D5:1F:06:CF:52:40:03:F8:DD:66\r\na=setup:actpass\r\na=mid:data\r\na=sctpmap:5000 webrtc-datachannel 1024\r\n"`

	const sampleOffer = `{"type":"offer","sdp":` + sampleSDP + `}`
	const sampleAnswer = `{"type":"answer","sdp":` + sampleSDP + `}`

	Convey("Proxy connections to broker", t, func() {
		var err error
		broker, err = newSignalingServer("localhost", false)
		So(err, ShouldBeNil)
		tokens = 0

		//Mock peerConnection
		config = webrtc.Configuration{
			ICEServers: []webrtc.ICEServer{
				{
					URLs: []string{"stun:stun.l.google.com:19302"},
				},
			},
		}
		pc, _ := webrtc.NewPeerConnection(config)
		offer, _ := util.DeserializeSessionDescription(sampleOffer)
		pc.SetRemoteDescription(*offer)
		answer, _ := pc.CreateAnswer(nil)
		pc.SetLocalDescription(answer)

		Convey("polls broker correctly", func() {
			var err error

			b, err := messages.EncodePollResponse(sampleOffer, true, "unknown")
			So(err, ShouldBeNil)
			broker.transport = &MockTransport{
				http.StatusOK,
				b,
			}

			sdp, _ := broker.pollOffer(sampleOffer, DefaultProxyType, "")
			expectedSDP, _ := strconv.Unquote(sampleSDP)
			So(sdp.SDP, ShouldResemble, expectedSDP)
		})
		Convey("handles poll error", func() {
			var err error

			b := []byte("test")
			So(err, ShouldBeNil)
			broker.transport = &MockTransport{
				http.StatusOK,
				b,
			}

			sdp, _ := broker.pollOffer(sampleOffer, DefaultProxyType, "")
			So(sdp, ShouldBeNil)
		})
		Convey("sends answer to broker", func() {
			var err error

			b, err := messages.EncodeAnswerResponse(true)
			So(err, ShouldBeNil)
			broker.transport = &MockTransport{
				http.StatusOK,
				b,
			}

			err = broker.sendAnswer(sampleAnswer, pc)
			if err != nil {
				So(err.Error(), ShouldResemble, "local description should not be nil")
			}

			b, err = messages.EncodeAnswerResponse(false)
			So(err, ShouldBeNil)
			broker.transport = &MockTransport{
				http.StatusOK,
				b,
			}

			err = broker.sendAnswer(sampleAnswer, pc)
			So(err, ShouldNotBeNil)
		})
		Convey("handles answer error", func() {
			//Error if faulty transport
			broker.transport = &FaultyTransport{}
			err := broker.sendAnswer(sampleAnswer, pc)
			So(err, ShouldNotBeNil)

			//Error if status code is not ok
			broker.transport = &MockTransport{
				http.StatusGone,
				[]byte(""),
			}
			err = broker.sendAnswer("test", pc)
			So(err, ShouldNotEqual, nil)
			if err.Error() != "local description should not be nil" {
				So(err.Error(), ShouldResemble,
					"error sending answer to broker: remote returned status code 410")
			}

			//Error if we can't parse broker message
			broker.transport = &MockTransport{
				http.StatusOK,
				[]byte("test"),
			}
			err = broker.sendAnswer("test", pc)
			So(err, ShouldNotBeNil)

			//Error if broker message surpasses read limit
			broker.transport = &MockTransport{
				http.StatusOK,
				make([]byte, 100001),
			}
			err = broker.sendAnswer("test", pc)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestUtilityFuncs(t *testing.T) {
	t.Parallel()

	Convey("LimitedRead", t, func() {
		c, s := net.Pipe()
		Convey("Successful read", func() {
			go func() {
				bytes := make([]byte, 50)
				c.Write(bytes)
				c.Close()
			}()
			bytes, err := limitedRead(s, 60)
			So(len(bytes), ShouldEqual, 50)
			So(err, ShouldBeNil)
		})
		Convey("Large read", func() {
			go func() {
				bytes := make([]byte, 50)
				c.Write(bytes)
				c.Close()
			}()
			bytes, err := limitedRead(s, 49)
			So(len(bytes), ShouldEqual, 49)
			So(err, ShouldEqual, io.ErrUnexpectedEOF)
		})
		Convey("Failed read", func() {
			s.Close()
			bytes, err := limitedRead(s, 49)
			So(len(bytes), ShouldEqual, 0)
			So(err, ShouldEqual, io.ErrClosedPipe)
		})
	})
	Convey("SessionID Generation", t, func() {
		sid1 := genSessionID()
		sid2 := genSessionID()
		So(sid1, ShouldNotEqual, sid2)
	})
	Convey("CopyLoop", t, func() {
		c1, s1 := net.Pipe()
		c2, s2 := net.Pipe()
		go copyLoop(s1, s2, nil)
		go func() {
			bytes := []byte("Hello!")
			c1.Write(bytes)
		}()
		bytes := make([]byte, 6)
		n, err := c2.Read(bytes)
		So(n, ShouldEqual, 6)
		So(err, ShouldBeNil)
		So(bytes, ShouldResemble, []byte("Hello!"))
		s1.Close()

		//Check that copy loop has closed other connection
		_, err = s2.Write(bytes)
		So(err, ShouldNotBeNil)
	})
	Convey("isRelayURLAcceptable", t, func() {
		testingVector := []struct {
			pattern               string
			allowPrivateAddresses bool
			allowNonTLS           bool
			targetURL             string
			expects               error
		}{
			// These are copied from `TestMatchMember`.
			{pattern: "^snowflake.torproject.net$", allowNonTLS: false, targetURL: "wss://snowflake.torproject.net", expects: nil},
			{pattern: "^snowflake.torproject.net$", allowNonTLS: false, targetURL: "wss://faketorproject.net", expects: fmt.Errorf("")},
			{pattern: "snowflake.torproject.net$", allowNonTLS: false, targetURL: "wss://faketorproject.net", expects: fmt.Errorf("")},
			{pattern: "snowflake.torproject.net$", allowNonTLS: false, targetURL: "wss://snowflake.torproject.net", expects: nil},
			{pattern: "snowflake.torproject.net$", allowNonTLS: false, targetURL: "wss://imaginary-01-snowflake.torproject.net", expects: nil},
			{pattern: "snowflake.torproject.net$", allowNonTLS: false, targetURL: "wss://imaginary-aaa-snowflake.torproject.net", expects: nil},
			{pattern: "snowflake.torproject.net$", allowNonTLS: false, targetURL: "wss://imaginary-aaa-snowflake.faketorproject.net", expects: fmt.Errorf("")},

			{pattern: "^torproject.net$", allowNonTLS: false, targetURL: "wss://faketorproject.net", expects: fmt.Errorf("")},
			// Yes, this is how it works if there is no "^".
			{pattern: "torproject.net$", allowNonTLS: false, targetURL: "wss://faketorproject.net", expects: nil},

			// NonTLS
			{pattern: "snowflake.torproject.net$", allowNonTLS: false, targetURL: "ws://snowflake.torproject.net", expects: fmt.Errorf("")},
			{pattern: "snowflake.torproject.net$", allowNonTLS: true, targetURL: "ws://snowflake.torproject.net", expects: nil},

			// Sneaky attempt to use path
			{pattern: "snowflake.torproject.net$", allowNonTLS: false, targetURL: "wss://evil.com/snowflake.torproject.net", expects: fmt.Errorf("")},
			{pattern: "snowflake.torproject.net$", allowNonTLS: false, targetURL: "wss://evil.com/?test=snowflake.torproject.net", expects: fmt.Errorf("")},

			// IP address
			{pattern: "^1.1.1.1$", allowNonTLS: true, targetURL: "ws://1.1.1.1/test?test=test#test", expects: nil},
			{pattern: "^1.1.1.1$", allowNonTLS: true, targetURL: "ws://231.1.1.1/test?test=test#test", expects: fmt.Errorf("")},
			{pattern: "1.1.1.1$", allowNonTLS: true, targetURL: "ws://231.1.1.1/test?test=test#test", expects: nil},
			// Private IP address
			{pattern: "$", allowNonTLS: true, targetURL: "ws://192.168.1.1", expects: fmt.Errorf("")},
			{pattern: "$", allowNonTLS: true, targetURL: "ws://127.0.0.1", expects: fmt.Errorf("")},
			{pattern: "$", allowNonTLS: true, targetURL: "ws://[fc00::]/", expects: fmt.Errorf("")},
			{pattern: "$", allowNonTLS: true, targetURL: "ws://[::1]/", expects: fmt.Errorf("")},
			{pattern: "$", allowNonTLS: true, targetURL: "ws://0.0.0.0/", expects: fmt.Errorf("")},
			{pattern: "$", allowNonTLS: true, targetURL: "ws://169.254.1.1/", expects: fmt.Errorf("")},
			{pattern: "$", allowNonTLS: true, targetURL: "ws://100.111.1.1/", expects: fmt.Errorf("")},
			{pattern: "192.168.1.100$", allowPrivateAddresses: true, allowNonTLS: true, targetURL: "ws://192.168.1.100/test?test=test", expects: nil},
			{pattern: "localhost$", allowPrivateAddresses: true, allowNonTLS: true, targetURL: "ws://localhost/test?test=test", expects: nil},
			{pattern: "::1$", allowPrivateAddresses: true, allowNonTLS: true, targetURL: "ws://[::1]/test?test=test", expects: nil},
			// Multicast IP address. `checkIsRelayURLAcceptable` allows it,
			// but it's not valid in the context of WebSocket
			{pattern: "255.255.255.255$", allowPrivateAddresses: true, allowNonTLS: true, targetURL: "ws://255.255.255.255/test?test=test", expects: nil},

			// Port
			{pattern: "^snowflake.torproject.net$", allowNonTLS: false, targetURL: "wss://snowflake.torproject.net:8080/test?test=test#test", expects: nil},
			// This currently doesn't work as we only check hostname.
			// {pattern: "^snowflake.torproject.net:443$", allowNonTLS: false, targetURL: "wss://snowflake.torproject.net:443", expects: nil},
			// {pattern: "^snowflake.torproject.net:443$", allowNonTLS: false, targetURL: "wss://snowflake.torproject.net:9999", expects: fmt.Errorf("")},

			// Any URL
			{pattern: "$", allowNonTLS: false, targetURL: "wss://any.com/test?test=test#test", expects: nil},
			{pattern: "$", allowNonTLS: false, targetURL: "wss://1.1.1.1/test?test=test#test", expects: nil},

			// Weird / invalid / ambiguous URL
			{pattern: "$", allowNonTLS: true, targetURL: "snowflake.torproject.net", expects: fmt.Errorf("")},
			{pattern: "$", allowNonTLS: true, targetURL: "//snowflake.torproject.net", expects: fmt.Errorf("")},
			{pattern: "$", allowNonTLS: true, targetURL: "/path", expects: fmt.Errorf("")},
			{pattern: "$", allowNonTLS: true, targetURL: "wss://snowflake.torproject .net", expects: fmt.Errorf("")},
			{pattern: "$", allowNonTLS: true, targetURL: "wss://😀", expects: nil},
			{pattern: "$", allowNonTLS: true, targetURL: "wss://пример.рф", expects: nil},

			// Non-websocket protocols
			{pattern: "snowflake.torproject.net$", allowNonTLS: false, targetURL: "https://snowflake.torproject.net", expects: fmt.Errorf("")},
			{pattern: "snowflake.torproject.net$", allowNonTLS: false, targetURL: "ftp://snowflake.torproject.net", expects: fmt.Errorf("")},
			{pattern: "snowflake.torproject.net$", allowNonTLS: true, targetURL: "https://snowflake.torproject.net", expects: fmt.Errorf("")},
			{pattern: "snowflake.torproject.net$", allowNonTLS: true, targetURL: "ftp://snowflake.torproject.net", expects: fmt.Errorf("")},
		}
		for _, v := range testingVector {
			err := checkIsRelayURLAcceptable(v.pattern, v.allowPrivateAddresses, v.allowNonTLS, v.targetURL)
			if v.expects != nil {
				So(err, ShouldNotBeNil)
			} else {
				So(err, ShouldBeNil)
			}
		}
	})
}
