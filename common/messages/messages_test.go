package messages

import (
	"encoding/json"
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDecodeProxyPollRequest(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		for _, test := range []struct {
			sid       string
			proxyType string
			natType   string
			clients   int
			data      string
			err       error

			acceptedRelayPattern string
		}{
			{
				//Version 1.0 proxy message
				sid:       "ymbcCMto7KHNGYlp",
				proxyType: "unknown",
				natType:   "unknown",
				clients:   0,
				data:      `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0"}`,
				err:       nil,
			},
			{
				//Version 1.1 proxy message
				sid:       "ymbcCMto7KHNGYlp",
				proxyType: "standalone",
				natType:   "unknown",
				clients:   0,
				data:      `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.1","Type":"standalone"}`,
				err:       nil,
			},
			{
				//Version 1.2 proxy message
				sid:       "ymbcCMto7KHNGYlp",
				proxyType: "standalone",
				natType:   "restricted",
				clients:   0,
				data:      `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.2","Type":"standalone", "NAT":"restricted"}`,
				err:       nil,
			},
			{
				//Version 1.2 proxy message with clients
				sid:       "ymbcCMto7KHNGYlp",
				proxyType: "standalone",
				natType:   "restricted",
				clients:   24,
				data:      `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.2","Type":"standalone", "NAT":"restricted","Clients":24}`,
				err:       nil,
			},
			{
				//Version 1.3 proxy message with clients and proxyURL
				sid:                  "ymbcCMto7KHNGYlp",
				proxyType:            "standalone",
				natType:              "restricted",
				clients:              24,
				acceptedRelayPattern: "snowflake.torproject.org",
				data:                 `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.2","Type":"standalone", "NAT":"restricted","Clients":24, "AcceptedRelayPattern":"snowflake.torproject.org"}`,
				err:                  nil,
			},
			{
				//no negative client counts
				sid:                  "ymbcCMto7KHNGYlp",
				proxyType:            "standalone",
				natType:              "restricted",
				clients:              0,
				acceptedRelayPattern: "snowflake.torproject.org",
				data:                 `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.2","Type":"standalone", "NAT":"restricted","Clients":-1, "AcceptedRelayPattern":"snowflake.torproject.org"}`,
				err:                  nil,
			},
			{
				//Version 0.X proxy message:
				sid:       "",
				proxyType: "",
				natType:   "",
				clients:   0,
				data:      "",
				err:       &json.SyntaxError{},
			},
			{
				sid:       "",
				proxyType: "",
				natType:   "",
				clients:   0,
				data:      `{"Sid":"ymbcCMto7KHNGYlp"}`,
				err:       fmt.Errorf(""),
			},
			{
				sid:       "",
				proxyType: "",
				natType:   "",
				clients:   0,
				data:      "{}",
				err:       fmt.Errorf(""),
			},
			{
				sid:       "",
				proxyType: "",
				natType:   "",
				clients:   0,
				data:      `{"Version":"1.0"}`,
				err:       fmt.Errorf(""),
			},
			{
				sid:       "",
				proxyType: "",
				natType:   "",
				clients:   0,
				data:      `{"Version":"2.0"}`,
				err:       fmt.Errorf(""),
			},
		} {
			req, err := DecodeProxyPollRequest([]byte(test.data))
			if err == nil {
				So(req.Sid, ShouldResemble, test.sid)
				So(req.Type, ShouldResemble, test.proxyType)
				So(req.NAT, ShouldResemble, test.natType)
				So(req.Clients, ShouldEqual, test.clients)
				if test.acceptedRelayPattern != "" {
					So(*req.AcceptedRelayPattern, ShouldResemble, test.acceptedRelayPattern)
				} else {
					So(req.AcceptedRelayPattern, ShouldBeNil)
				}
			}
			So(err, ShouldHaveSameTypeAs, test.err)
		}

	})
}

func TestEncodeProxyPollRequests(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		req := &ProxyPollRequest{
			Sid:     "ymbcCMto7KHNGYlp",
			Type:    "standalone",
			NAT:     "unknown",
			Clients: 16,
		}
		b, err := req.Encode()
		So(err, ShouldBeNil)
		req, err = DecodeProxyPollRequest(b)
		So(req.Sid, ShouldEqual, "ymbcCMto7KHNGYlp")
		So(req.Type, ShouldEqual, "standalone")
		So(req.NAT, ShouldEqual, "unknown")
		So(req.Clients, ShouldEqual, 16)
		So(err, ShouldBeNil)
	})
}

func TestDecodeProxyPollResponse(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		for _, test := range []struct {
			offer    string
			data     string
			relayURL string
			nextPoll int64
			err      error
		}{
			{
				offer: "fake offer",
				data:  `{"Status":"client match","Offer":"fake offer","NAT":"unknown"}`,
				err:   nil,
			},
			{
				offer:    "fake offer",
				data:     `{"Status":"client match","Offer":"fake offer","NAT":"unknown", "RelayURL":"wss://snowflake.torproject.org/proxy"}`,
				relayURL: "wss://snowflake.torproject.org/proxy",
				err:      nil,
			},
			{
				offer:    "fake offer",
				data:     `{"Status":"client match","Offer":"fake offer","NAT":"unknown", "NextPoll":600}`,
				nextPoll: 600,
				err:      nil,
			},
			{
				offer: "",
				data:  `{"Status":"no match"}`,
				err:   nil,
			},
			{
				offer: "",
				data:  `{"Status":"client match"}`,
				err:   fmt.Errorf("no supplied offer"),
			},
			{
				offer: "",
				data:  `{"Test":"test"}`,
				err:   fmt.Errorf(""),
			},
		} {
			req, err := DecodeProxyPollResponse([]byte(test.data))
			So(err, ShouldHaveSameTypeAs, test.err)
			if err == nil {
				So(req.Offer, ShouldResemble, test.offer)
				So(req.RelayURL, ShouldResemble, test.relayURL)
				So(req.NextPoll, ShouldResemble, test.nextPoll)
			}
		}

	})
}

func TestEncodeProxyPollResponse(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		resp := &ProxyPollResponse{
			Offer:    "fake offer",
			Status:   ProxyClientMatch,
			NAT:      "restricted",
			NextPoll: 600,
		}
		b, err := resp.Encode()
		So(err, ShouldBeNil)
		resp, err = DecodeProxyPollResponse(b)
		So(resp.Offer, ShouldEqual, "fake offer")
		So(resp.NAT, ShouldEqual, "restricted")
		So(err, ShouldBeNil)

		resp = &ProxyPollResponse{
			Status: ProxyClientNoMatch,
			NAT:    "unknown",
		}
		b, err = resp.Encode()
		So(err, ShouldBeNil)
		resp, err = DecodeProxyPollResponse(b)
		So(resp.Offer, ShouldEqual, "")
		So(resp.NAT, ShouldEqual, "unknown")
		So(err, ShouldBeNil)
	})
}

func TestEncodeProxyPollResponseWithProxyURL(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		resp := &ProxyPollResponse{
			Offer:    "fake offer",
			Status:   ProxyClientMatch,
			NAT:      "restricted",
			RelayURL: "wss://test/",
		}
		b, err := resp.Encode()
		So(err, ShouldBeNil)

		resp, err = DecodeProxyPollResponse(b)
		So(resp.Offer, ShouldEqual, "fake offer")
		So(resp.NAT, ShouldEqual, "restricted")
		So(resp.RelayURL, ShouldEqual, "wss://test/")
		So(err, ShouldBeNil)

		resp = &ProxyPollResponse{
			Offer:    "fake offer",
			NAT:      "restricted",
			RelayURL: "wss://test/",
			Status:   "test error reason",
		}
		b, err = resp.Encode()
		So(err, ShouldBeNil)
		_, err = DecodeProxyPollResponse(b)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "test error reason")
	})
}
func TestDecodeProxyAnswerRequest(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		for _, test := range []struct {
			answer string
			sid    string
			data   string
			err    error
		}{
			{
				`{"type":"answer","sdp":"fake"}`,
				"test",
				`{"Version":"1.0","Sid":"test","Answer":"{\"type\":\"answer\",\"sdp\":\"fake\"}"}`,
				nil,
			},
			{
				"",
				"",
				`{"type":"offer","sdp":"v=0\r\no=- 4358805017720277108 2 IN IP4 [scrubbed]\r\ns=-\r\nt=0 0\r\na=group:BUNDLE data\r\na=msid-semantic: WMS\r\nm=application 56688 DTLS/SCTP 5000\r\nc=IN IP4 [scrubbed]\r\na=candidate:3769337065 1 udp 2122260223 [scrubbed] 56688 typ host generation 0 network-id 1 network-cost 50\r\na=candidate:2921887769 1 tcp 1518280447 [scrubbed] 35441 typ host tcptype passive generation 0 network-id 1 network-cost 50\r\na=ice-ufrag:aMAZ\r\na=ice-pwd:jcHb08Jjgrazp2dzjdrvPPvV\r\na=ice-options:trickle\r\na=fingerprint:sha-256 C8:88:EE:B9:E7:02:2E:21:37:ED:7A:D1:EB:2B:A3:15:A2:3B:5B:1C:3D:D4:D5:1F:06:CF:52:40:03:F8:DD:66\r\na=setup:actpass\r\na=mid:data\r\na=sctpmap:5000 webrtc-datachannel 1024\r\n"}`,
				fmt.Errorf(""),
			},
			{
				"",
				"",
				`{"Version":"1.0","Answer":"{\"type\":\"answer\",\"sdp\":\"fake\"}"}`,
				fmt.Errorf(""),
			},
			{
				"",
				"",
				`{"Version":"1.0","Sid":"test"}`,
				fmt.Errorf(""),
			},
		} {
			req, err := DecodeProxyAnswerRequest([]byte(test.data))
			if err == nil {
				So(req.Answer, ShouldResemble, test.answer)
				So(req.Sid, ShouldResemble, test.sid)
			}
			So(err, ShouldHaveSameTypeAs, test.err)
		}

	})
}

func TestEncodeProxyAnswerRequest(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		req := &ProxyAnswerRequest{
			Answer: `{"type":"answer","sdp":"fake"}`,
			Sid:    "test sid",
		}
		b, err := req.Encode()
		So(err, ShouldBeNil)
		req, err = DecodeProxyAnswerRequest(b)
		So(req.Answer, ShouldEqual, `{"type":"answer","sdp":"fake"}`)
		So(req.Sid, ShouldEqual, "test sid")
		So(err, ShouldBeNil)
	})
}

func TestDecodeProxyAnswerResponse(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		for _, test := range []struct {
			success bool
			data    string
			err     error
		}{
			{
				true,
				`{"Status":"success"}`,
				nil,
			},
			{
				false,
				`{"Status":"client gone"}`,
				nil,
			},
			{
				false,
				`{"Test":"test"}`,
				fmt.Errorf(""),
			},
		} {
			success, err := DecodeAnswerResponse([]byte(test.data))
			So(success, ShouldResemble, test.success)
			So(err, ShouldHaveSameTypeAs, test.err)
		}

	})
}

func TestEncodeProxyAnswerResponse(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		b, err := EncodeAnswerResponse(true)
		So(err, ShouldBeNil)
		success, err := DecodeAnswerResponse(b)
		So(success, ShouldEqual, true)
		So(err, ShouldBeNil)

		b, err = EncodeAnswerResponse(false)
		So(err, ShouldBeNil)
		success, err = DecodeAnswerResponse(b)
		So(success, ShouldEqual, false)
		So(err, ShouldBeNil)
	})
}

func TestDecodeClientPollRequest(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		for _, test := range []struct {
			natType string
			offer   string
			data    string
			err     error
		}{
			{
				//version 1.0 client message
				"unknown",
				`{"type":"offer","sdp":"fake"}`,
				`1.0
				{"nat":"unknown","offer":"{\"type\":\"offer\",\"sdp\":\"fake\"}"}`,
				nil,
			},
			{
				//version 1.0 client message
				"unknown",
				`{"type":"offer","sdp":"fake"}`,
				`1.0
				{"offer":"{\"type\":\"offer\",\"sdp\":\"fake\"}"}`,
				nil,
			},
			{
				//unknown version
				"",
				"",
				`{"version":"2.0"}`,
				fmt.Errorf(""),
			},
			{
				//no offer
				"",
				"",
				`1.0
{"nat":"unknown"}`,
				fmt.Errorf(""),
			},
			{
				//malformed offer
				"",
				"",
				`1.0
				{"offer":"{\"type\":0,\"sdp\":\"fake\"}"}`,
				fmt.Errorf(""),
			},
		} {
			req, err := DecodeClientPollRequest([]byte(test.data))
			So(err, ShouldHaveSameTypeAs, test.err)
			if test.err == nil {
				So(req.NAT, ShouldResemble, test.natType)
				So(req.Offer, ShouldResemble, test.offer)
			}
		}

	})
}

func TestEncodeClientPollRequests(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		for i, test := range []struct {
			natType     string
			offer       string
			fingerprint string
			err         error
		}{
			{
				"unknown",
				`{"type":"offer","sdp":"fake"}`,
				"",
				nil,
			},
			{
				"unknown",
				`{"type":"offer","sdp":"fake"}`,
				defaultBridgeFingerprint,
				nil,
			},
			{
				"unknown",
				`{"type":"offer","sdp":"fake"}`,
				"123123",
				fmt.Errorf(""),
			},
		} {
			req1 := &ClientPollRequest{
				NAT:         test.natType,
				Offer:       test.offer,
				Fingerprint: test.fingerprint,
			}
			b, err := req1.EncodeClientPollRequest()
			So(err, ShouldBeNil)
			req2, err := DecodeClientPollRequest(b)
			So(err, ShouldHaveSameTypeAs, test.err)
			if test.err == nil {
				So(req2.Offer, ShouldEqual, req1.Offer)
				So(req2.NAT, ShouldEqual, req1.NAT)
				fingerprint := test.fingerprint
				if i == 0 {
					fingerprint = defaultBridgeFingerprint
				}
				So(req2.Fingerprint, ShouldEqual, fingerprint)
			}
		}
	})
}

func TestDecodeClientPollResponse(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		for _, test := range []struct {
			answer string
			msg    string
			data   string
		}{
			{
				"fake answer",
				"",
				`{"answer":"fake answer"}`,
			},
			{
				"",
				"no snowflakes",
				`{"error":"no snowflakes"}`,
			},
		} {
			resp, err := DecodeClientPollResponse([]byte(test.data))
			So(err, ShouldBeNil)
			So(resp.Answer, ShouldResemble, test.answer)
			So(resp.Error, ShouldResemble, test.msg)
		}

	})
}

func TestEncodeClientPollResponse(t *testing.T) {
	t.Parallel()

	Convey("Context", t, func() {
		resp1 := &ClientPollResponse{
			Answer: "fake answer",
		}
		b, err := resp1.EncodePollResponse()
		So(err, ShouldBeNil)
		resp2, err := DecodeClientPollResponse(b)
		So(err, ShouldBeNil)
		So(resp1, ShouldResemble, resp2)

		resp1 = &ClientPollResponse{
			Error: "failed",
		}
		b, err = resp1.EncodePollResponse()
		So(err, ShouldBeNil)
		resp2, err = DecodeClientPollResponse(b)
		So(err, ShouldBeNil)
		So(resp1, ShouldResemble, resp2)
	})
}
