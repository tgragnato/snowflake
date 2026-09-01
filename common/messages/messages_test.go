package messages

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// checkErrorType asserts that got has the same dynamic type as want. The test
// tables use this to express "this input must fail" without pinning down the
// exact error message.
func checkErrorType(t *testing.T, got, want error) {
	t.Helper()
	if reflect.TypeOf(got) != reflect.TypeOf(want) {
		t.Errorf("err = %v (%T), want an error of type %T", got, got, want)
	}
}

func TestDecodeProxyPollRequest(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		sid       string
		proxyType string
		natType   string
		clients   uint64
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
			if req.Sid != test.sid {
				t.Errorf("Sid = %q, want %q", req.Sid, test.sid)
			}
			if req.Type != test.proxyType {
				t.Errorf("Type = %q, want %q", req.Type, test.proxyType)
			}
			if req.NAT != test.natType {
				t.Errorf("NAT = %q, want %q", req.NAT, test.natType)
			}
			if req.Clients != test.clients {
				t.Errorf("Clients = %d, want %d", req.Clients, test.clients)
			}
			switch {
			case test.acceptedRelayPattern == "":
				if req.AcceptedRelayPattern != nil {
					t.Errorf("AcceptedRelayPattern = %q, want nil", *req.AcceptedRelayPattern)
				}
			case req.AcceptedRelayPattern == nil:
				t.Errorf("AcceptedRelayPattern = nil, want %q", test.acceptedRelayPattern)
			default:
				if *req.AcceptedRelayPattern != test.acceptedRelayPattern {
					t.Errorf("AcceptedRelayPattern = %q, want %q", *req.AcceptedRelayPattern, test.acceptedRelayPattern)
				}
			}
		}
		checkErrorType(t, err, test.err)
	}

}

func TestEncodeProxyPollRequests(t *testing.T) {
	t.Parallel()

	req := &ProxyPollRequest{
		Sid:     "ymbcCMto7KHNGYlp",
		Type:    "standalone",
		NAT:     "unknown",
		Clients: 16,
	}
	b, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeProxyPollRequest(b)
	if err != nil {
		t.Fatalf("DecodeProxyPollRequest: %v", err)
	}
	if *got != *req {
		t.Errorf("round trip = %+v, want %+v", got, req)
	}
}

func TestDecodeProxyPollResponse(t *testing.T) {
	t.Parallel()

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
		checkErrorType(t, err, test.err)
		if err == nil {
			if req.Offer != test.offer {
				t.Errorf("Offer = %q, want %q", req.Offer, test.offer)
			}
			if req.RelayURL != test.relayURL {
				t.Errorf("RelayURL = %q, want %q", req.RelayURL, test.relayURL)
			}
			if req.NextPoll != test.nextPoll {
				t.Errorf("NextPoll = %d, want %d", req.NextPoll, test.nextPoll)
			}
		}
	}

}

// roundTripProxyPollResponse encodes resp and decodes the result back.
func roundTripProxyPollResponse(t *testing.T, resp *ProxyPollResponse) (*ProxyPollResponse, error) {
	t.Helper()
	b, err := resp.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return DecodeProxyPollResponse(b)
}

func TestEncodeProxyPollResponse(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		resp *ProxyPollResponse
	}{
		{
			name: "client match",
			resp: &ProxyPollResponse{
				Offer:    "fake offer",
				Status:   ProxyClientMatch,
				NAT:      "restricted",
				NextPoll: 600,
			},
		},
		{
			name: "no match",
			resp: &ProxyPollResponse{
				Status: ProxyClientNoMatch,
				NAT:    "unknown",
			},
		},
		{
			name: "client match with relay URL",
			resp: &ProxyPollResponse{
				Offer:    "fake offer",
				Status:   ProxyClientMatch,
				NAT:      "restricted",
				RelayURL: "wss://test/",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := roundTripProxyPollResponse(t, tc.resp)
			if err != nil {
				t.Fatalf("DecodeProxyPollResponse: %v", err)
			}
			if got.Offer != tc.resp.Offer {
				t.Errorf("Offer = %q, want %q", got.Offer, tc.resp.Offer)
			}
			if got.NAT != tc.resp.NAT {
				t.Errorf("NAT = %q, want %q", got.NAT, tc.resp.NAT)
			}
			if got.RelayURL != tc.resp.RelayURL {
				t.Errorf("RelayURL = %q, want %q", got.RelayURL, tc.resp.RelayURL)
			}
		})
	}
}

// An unrecognised Status is surfaced to the proxy as an error carrying the
// status text, so operators can see what the broker reported.
func TestDecodeProxyPollResponseRejectsUnknownStatus(t *testing.T) {
	t.Parallel()

	_, err := roundTripProxyPollResponse(t, &ProxyPollResponse{
		Offer:    "fake offer",
		NAT:      "restricted",
		RelayURL: "wss://test/",
		Status:   "test error reason",
	})
	if err == nil {
		t.Fatal("DecodeProxyPollResponse succeeded, want error")
	}
	if !strings.Contains(err.Error(), "test error reason") {
		t.Errorf("err = %q, want it to mention %q", err, "test error reason")
	}
}

func TestDecodeProxyAnswerRequest(t *testing.T) {
	t.Parallel()

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
			if req.Answer != test.answer {
				t.Errorf("Answer = %q, want %q", req.Answer, test.answer)
			}
			if req.Sid != test.sid {
				t.Errorf("Sid = %q, want %q", req.Sid, test.sid)
			}
		}
		checkErrorType(t, err, test.err)
	}

}

func TestEncodeProxyAnswerRequest(t *testing.T) {
	t.Parallel()

	req := &ProxyAnswerRequest{
		Answer: `{"type":"answer","sdp":"fake"}`,
		Sid:    "test sid",
	}
	b, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeProxyAnswerRequest(b)
	if err != nil {
		t.Fatalf("DecodeProxyAnswerRequest: %v", err)
	}
	if got.Answer != req.Answer {
		t.Errorf("Answer = %q, want %q", got.Answer, req.Answer)
	}
	if got.Sid != req.Sid {
		t.Errorf("Sid = %q, want %q", got.Sid, req.Sid)
	}
}

func TestDecodeProxyAnswerResponse(t *testing.T) {
	t.Parallel()

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
		if success != test.success {
			t.Errorf("DecodeAnswerResponse(%s) = %v, want %v", test.data, success, test.success)
		}
		checkErrorType(t, err, test.err)
	}

}

func TestEncodeProxyAnswerResponse(t *testing.T) {
	t.Parallel()

	for _, want := range []bool{true, false} {
		b, err := EncodeAnswerResponse(want)
		if err != nil {
			t.Fatalf("EncodeAnswerResponse(%v): %v", want, err)
		}
		got, err := DecodeAnswerResponse(b)
		if err != nil {
			t.Fatalf("DecodeAnswerResponse(%v): %v", want, err)
		}
		if got != want {
			t.Errorf("round trip of %v = %v", want, got)
		}
	}
}

func TestDecodeClientPollRequest(t *testing.T) {
	t.Parallel()

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
		checkErrorType(t, err, test.err)
		if test.err == nil {
			if req.NAT != test.natType {
				t.Errorf("NAT = %q, want %q", req.NAT, test.natType)
			}
			if req.Offer != test.offer {
				t.Errorf("Offer = %q, want %q", req.Offer, test.offer)
			}
		}
	}

}

func TestEncodeClientPollRequests(t *testing.T) {
	t.Parallel()

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
		if err != nil {
			t.Fatalf("EncodeClientPollRequest: %v", err)
		}
		req2, err := DecodeClientPollRequest(b)
		checkErrorType(t, err, test.err)
		if test.err != nil {
			continue
		}
		if req2.Offer != req1.Offer {
			t.Errorf("Offer = %q, want %q", req2.Offer, req1.Offer)
		}
		if req2.NAT != req1.NAT {
			t.Errorf("NAT = %q, want %q", req2.NAT, req1.NAT)
		}
		// An empty fingerprint is filled in with the default bridge's.
		fingerprint := test.fingerprint
		if i == 0 {
			fingerprint = defaultBridgeFingerprint
		}
		if req2.Fingerprint != fingerprint {
			t.Errorf("Fingerprint = %q, want %q", req2.Fingerprint, fingerprint)
		}
	}
}

func TestDecodeClientPollResponse(t *testing.T) {
	t.Parallel()

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
		if err != nil {
			t.Fatalf("DecodeClientPollResponse(%s): %v", test.data, err)
		}
		if resp.Answer != test.answer {
			t.Errorf("Answer = %q, want %q", resp.Answer, test.answer)
		}
		if resp.Error != test.msg {
			t.Errorf("Error = %q, want %q", resp.Error, test.msg)
		}
	}

}

func TestEncodeClientPollResponse(t *testing.T) {
	t.Parallel()

	for _, want := range []*ClientPollResponse{
		{Answer: "fake answer"},
		{Error: "failed"},
	} {
		b, err := want.EncodePollResponse()
		if err != nil {
			t.Fatalf("EncodePollResponse: %v", err)
		}
		got, err := DecodeClientPollResponse(b)
		if err != nil {
			t.Fatalf("DecodeClientPollResponse: %v", err)
		}
		if *got != *want {
			t.Errorf("round trip = %+v, want %+v", got, want)
		}
	}
}
