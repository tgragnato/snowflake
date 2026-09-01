package main

import (
	"bytes"
	"container/heap"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"tgragnato.it/snowflake/common/amp"
	"tgragnato.it/snowflake/common/messages"
)

func NullLogger() *log.Logger {
	logger := log.New(os.Stdout, "", 0)
	logger.SetOutput(io.Discard)
	return logger
}

var (
	rawOffer  = `{"type":"offer","sdp":"v=0\r\no=- 4358805017720277108 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=group:BUNDLE data\r\na=msid-semantic: WMS\r\nm=application 56688 DTLS/SCTP 5000\r\nc=IN IP4 0.0.0.0\r\na=candidate:3769337065 1 udp 2122260223 129.97.208.23 56688 typ host generation 0 network-id 1 network-cost 50\r\na=candidate:2921887769 1 tcp 1518280447 129.97.208.23 35441 typ host tcptype passive generation 0 network-id 1 network-cost 50\r\na=ice-ufrag:aMAZ\r\na=ice-pwd:jcHb08Jjgrazp2dzjdrvPPvV\r\na=ice-options:trickle\r\na=fingerprint:sha-256 C8:88:EE:B9:E7:02:2E:21:37:ED:7A:D1:EB:2B:A3:15:A2:3B:5B:1C:3D:D4:D5:1F:06:CF:52:40:03:F8:DD:66\r\na=setup:actpass\r\na=mid:data\r\na=sctpmap:5000 webrtc-datachannel 1024\r\n"}`
	rawAnswer = `{"type":"answer","sdp":"v=0\r\no=- 4358805017720277108 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=group:BUNDLE data\r\na=msid-semantic: WMS\r\nm=application 56688 DTLS/SCTP 5000\r\nc=IN IP4 0.0.0.0\r\na=candidate:3769337065 1 udp 2122260223 129.97.208.23 56688 typ host generation 0 network-id 1 network-cost 50\r\na=candidate:2921887769 1 tcp 1518280447 129.97.208.23 35441 typ host tcptype passive generation 0 network-id 1 network-cost 50\r\na=ice-ufrag:aMAZ\r\na=ice-pwd:jcHb08Jjgrazp2dzjdrvPPvV\r\na=ice-options:trickle\r\na=fingerprint:sha-256 C8:88:EE:B9:E7:02:2E:21:37:ED:7A:D1:EB:2B:A3:15:A2:3B:5B:1C:3D:D4:D5:1F:06:CF:52:40:03:F8:DD:66\r\na=setup:actpass\r\na=mid:data\r\na=sctpmap:5000 webrtc-datachannel 1024\r\n"}`
	sid       = "ymbcCMto7KHNGYlp"
)

func createClientOffer(sdp, nat, fingerprint string) (*bytes.Reader, error) {
	clientRequest := &messages.ClientPollRequest{
		Offer:       sdp,
		NAT:         nat,
		Fingerprint: fingerprint,
	}
	encOffer, err := clientRequest.EncodeClientPollRequest()
	if err != nil {
		return nil, err
	}
	offer := bytes.NewReader(encOffer)
	return offer, nil
}

func createProxyAnswer(sdp, sid string) (*bytes.Reader, error) {
	req := messages.ProxyAnswerRequest{
		Sid:    sid,
		Answer: sdp,
	}
	proxyRequest, err := req.Encode()
	if err != nil {
		return nil, err
	}
	answer := bytes.NewReader(proxyRequest)
	return answer, nil
}

func addFakeSnowflake(ctx *BrokerContext) *Snowflake {
	s := NewSnowflake("fake", "", NATUnrestricted, 0)
	pool := ctx.GetPool(&ProxyPoll{natType: NATUnrestricted})
	pool.Push(s)
	ctx.idToSnowflake[s.id] = s
	return s
}

func decodeAMPArmorToString(r io.Reader) (string, error) {
	dec, err := amp.NewArmorDecoder(r)
	if err != nil {
		return "", err
	}
	p, err := io.ReadAll(dec)
	return string(p), err
}

// brokerFixture is the per-test broker state. Every test builds its own so
// that metrics and captured log output never leak between cases.
type brokerFixture struct {
	buf *bytes.Buffer
	ctx *BrokerContext
	ipc *IPC
}

func newBrokerFixture() *brokerFixture {
	buf := new(bytes.Buffer)
	ctx := NewBrokerContext(log.New(buf, "", 0), "snowflake.torproject.net")
	return &brokerFixture{buf: buf, ctx: ctx, ipc: &IPC{ctx}}
}

// checkMetrics dumps the broker metrics and asserts they contain want.
func (f *brokerFixture) checkMetrics(t *testing.T, want string) {
	t.Helper()
	f.ctx.metrics.printMetrics()
	if !strings.Contains(f.buf.String(), want) {
		t.Errorf("metrics output does not contain\n%s\ngot:\n%s", want, f.buf.String())
	}
}

// newClientOfferRequest builds a POST to the client endpoint carrying an offer.
func newClientOfferRequest(t *testing.T, natType string) *http.Request {
	t.Helper()
	data, err := createClientOffer(rawOffer, natType, "")
	if err != nil {
		t.Fatalf("createClientOffer: %v", err)
	}
	r, err := http.NewRequest("POST", "snowflake.broker/client", data)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	return r
}

func checkBody(t *testing.T, w *httptest.ResponseRecorder, wantCode int, wantBody string) {
	t.Helper()
	if w.Code != wantCode {
		t.Errorf("status = %d, want %d", w.Code, wantCode)
	}
	if got := w.Body.String(); got != wantBody {
		t.Errorf("body = %q, want %q", got, wantBody)
	}
}

// checkOfferSDP asserts that the offer forwarded to a proxy is the raw offer.
func checkOfferSDP(t *testing.T, offer *ClientOffer) {
	t.Helper()
	if !bytes.Equal(offer.sdp, []byte(rawOffer)) {
		t.Errorf("offer sdp = %q, want %q", offer.sdp, rawOffer)
	}
}

// Expected metrics output blocks. The trailing spaces on the *-ips lines are
// what the broker actually emits.
const (
	M_HTTP_DENIED = `client-denied-count 8
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-nat-strict-denied-count 0
client-nat-moderate-denied-count 0
client-nat-open-denied-count 0
client-nat-unknown-denied-count 8
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 8
client-http-ips ??=8
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips 
`

	M_HTTP_MATCH = `client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-nat-strict-denied-count 0
client-nat-moderate-denied-count 0
client-nat-open-denied-count 0
client-nat-unknown-denied-count 0
client-snowflake-match-count 8
client-snowflake-timeout-count 0
client-http-count 8
client-http-ips ??=8
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips 
`

	M_LEGACY_DENIED = `client-denied-count 8
client-restricted-denied-count 8
client-unrestricted-denied-count 0
client-nat-strict-denied-count 0
client-nat-moderate-denied-count 0
client-nat-open-denied-count 0
client-nat-unknown-denied-count 0
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 8
client-http-ips ??=8
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips 
`

	M_AMP_DENIED = `client-denied-count 8
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-nat-strict-denied-count 0
client-nat-moderate-denied-count 0
client-nat-open-denied-count 0
client-nat-unknown-denied-count 8
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 0
client-http-ips 
client-ampcache-count 8
client-ampcache-ips ??=8
client-sqs-count 0
client-sqs-ips 
`

	M_AMP_MATCH = `client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-nat-strict-denied-count 0
client-nat-moderate-denied-count 0
client-nat-open-denied-count 0
client-nat-unknown-denied-count 0
client-snowflake-match-count 8
client-snowflake-timeout-count 0
client-http-count 0
client-http-ips 
client-ampcache-count 8
client-ampcache-ips ??=8
client-sqs-count 0
client-sqs-ips 
`

	M_PROXY_POLLS_TAIL = `snowflake-ips-total 4
snowflake-idle-count 8
snowflake-proxy-poll-with-relay-url-count 8
snowflake-proxy-poll-without-relay-url-count 0
snowflake-proxy-rejected-for-relay-url-count 0
client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-nat-strict-denied-count 0
client-nat-moderate-denied-count 0
client-nat-open-denied-count 0
client-nat-unknown-denied-count 0
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 0
client-http-ips 
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips 
snowflake-ips-nat-restricted 0
snowflake-ips-nat-unrestricted 0
snowflake-ips-nat-unknown 4
snowflake-ips-nat-strict 0
snowflake-ips-nat-moderate 0
snowflake-ips-nat-open 0
`

	M_NO_PROXIES = `client-denied-count 8
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-nat-strict-denied-count 0
client-nat-moderate-denied-count 0
client-nat-open-denied-count 0
client-nat-unknown-denied-count 8
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 8
client-http-ips CA=8
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips `

	M_RESET = `snowflake-ips-total 0
snowflake-idle-count 0
snowflake-proxy-poll-with-relay-url-count 0
snowflake-proxy-poll-without-relay-url-count 0
snowflake-proxy-rejected-for-relay-url-count 0
client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-nat-strict-denied-count 0
client-nat-moderate-denied-count 0
client-nat-open-denied-count 0
client-nat-unknown-denied-count 0
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 0
client-http-ips 
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips 
snowflake-ips-nat-restricted 0
snowflake-ips-nat-unrestricted 0
snowflake-ips-nat-unknown 0
snowflake-ips-nat-strict 0
snowflake-ips-nat-moderate 0
snowflake-ips-nat-open 0
`
)

func TestBrokerAddsSnowflake(t *testing.T) {
	t.Parallel()

	f := newBrokerFixture()
	if got := f.ctx.openPool.h.Len(); got != 0 {
		t.Fatalf("pool length = %d, want 0", got)
	}
	if got := len(f.ctx.idToSnowflake); got != 0 {
		t.Fatalf("idToSnowflake length = %d, want 0", got)
	}

	addFakeSnowflake(f.ctx)
	if got := f.ctx.openPool.h.Len(); got != 1 {
		t.Errorf("pool length = %d, want 1", got)
	}
	if got := len(f.ctx.idToSnowflake); got != 1 {
		t.Errorf("idToSnowflake length = %d, want 1", got)
	}
}

func TestBrokerMatchesClientsWithProxies(t *testing.T) {
	t.Parallel()

	f := newBrokerFixture()
	p := &ProxyPoll{
		id:           "test",
		natType:      "unrestricted",
		offerChannel: make(chan *ClientOffer),
	}
	go func() {
		f.ctx.proxyPolls <- p
		close(f.ctx.proxyPolls)
	}()
	f.ctx.Broker()

	if got := f.ctx.openPool.h.Len(); got != 1 {
		t.Fatalf("pool length = %d, want 1", got)
	}
	snowflake := f.ctx.openPool.Pop()
	snowflake.offerChannel <- &ClientOffer{sdp: []byte("test offer")}
	offer := <-p.offerChannel

	if f.ctx.idToSnowflake["test"] == nil {
		t.Error(`idToSnowflake["test"] is nil`)
	}
	if !bytes.Equal(offer.sdp, []byte("test offer")) {
		t.Errorf("offer sdp = %q, want %q", offer.sdp, "test offer")
	}
	if got := f.ctx.openPool.h.Len(); got != 0 {
		t.Errorf("pool length = %d, want 0 after the match", got)
	}
}

func TestBrokerRequestOfferFromHeap(t *testing.T) {
	t.Parallel()

	f := newBrokerFixture()
	done := make(chan *ClientOffer)
	go func() {
		done <- f.ctx.RequestOffer(&ProxyPoll{
			id:      "test",
			natType: NATUnrestricted,
			addr:    "foo",
		})
	}()

	request := <-f.ctx.proxyPolls
	request.offerChannel <- &ClientOffer{sdp: []byte("test offer")}
	if offer := <-done; !bytes.Equal(offer.sdp, []byte("test offer")) {
		t.Errorf("offer sdp = %q, want %q", offer.sdp, "test offer")
	}
}

func TestBrokerHTTPClientOffers(t *testing.T) {
	t.Parallel()

	t.Run("with error when no snowflakes are available", func(t *testing.T) {
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		clientOffers(f.ipc, w, newClientOfferRequest(t, NATUnknown))

		checkBody(t, w, http.StatusOK, `{"error":"no snowflake proxies currently available"}`)
		// Ensure that denial is correctly recorded in metrics
		f.checkMetrics(t, M_HTTP_DENIED)
	})

	t.Run("with a proxy answer if available", func(t *testing.T) {
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		r := newClientOfferRequest(t, NATUnknown)

		// Prepare a fake proxy to respond with.
		snowflake := addFakeSnowflake(f.ctx)
		done := make(chan struct{})
		go func() {
			clientOffers(f.ipc, w, r)
			close(done)
		}()
		checkOfferSDP(t, <-snowflake.offerChannel)
		snowflake.answerChannel <- "test answer"
		<-done

		checkBody(t, w, http.StatusOK, `{"answer":"test answer"}`)
		// Ensure that match is correctly recorded in metrics
		f.checkMetrics(t, M_HTTP_MATCH)
	})

	t.Run("with unrestricted proxy to unrestricted client if there are no restricted proxies", func(t *testing.T) {
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		r := newClientOfferRequest(t, NATUnrestricted)

		snowflake := addFakeSnowflake(f.ctx)
		done := make(chan struct{})
		go func() {
			clientOffers(f.ipc, w, r)
			close(done)
		}()

		select {
		case <-snowflake.offerChannel:
		case <-time.After(250 * time.Millisecond):
			t.Fatal("timed out waiting for the offer to reach the unrestricted proxy")
		}
		snowflake.answerChannel <- "test answer"
		<-done

		checkBody(t, w, http.StatusOK, `{"answer":"test answer"}`)
	})

	t.Run("times out when no proxy responds", func(t *testing.T) {
		if testing.Short() {
			t.Skip("takes a few seconds")
		}
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		r := newClientOfferRequest(t, NATUnknown)

		snowflake := addFakeSnowflake(f.ctx)
		done := make(chan struct{})
		go func() {
			clientOffers(f.ipc, w, r)
			close(done)
		}()
		checkOfferSDP(t, <-snowflake.offerChannel)
		<-done

		checkBody(t, w, http.StatusOK, `{"error":"timed out waiting for answer!"}`)
	})
}

// newLegacyClientOfferRequest builds a pre-poll-protocol client request: the
// body is a bare offer and the NAT type travels in a header.
func newLegacyClientOfferRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest("POST", "snowflake.broker/client", bytes.NewReader([]byte(rawOffer)))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	r.Header.Set("Snowflake-NAT-TYPE", "restricted")
	return r
}

func TestBrokerLegacyHTTPClientOffers(t *testing.T) {
	t.Parallel()

	t.Run("with 503 when no snowflakes are available", func(t *testing.T) {
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		clientOffers(f.ipc, w, newLegacyClientOfferRequest(t))

		checkBody(t, w, http.StatusServiceUnavailable, "")
		// Ensure that denial is correctly recorded in metrics
		f.checkMetrics(t, M_LEGACY_DENIED)
	})

	t.Run("with a proxy answer if available", func(t *testing.T) {
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		r := newLegacyClientOfferRequest(t)

		// Prepare a fake proxy to respond with.
		snowflake := addFakeSnowflake(f.ctx)
		done := make(chan struct{})
		go func() {
			clientOffers(f.ipc, w, r)
			close(done)
		}()
		checkOfferSDP(t, <-snowflake.offerChannel)
		snowflake.answerChannel <- "fake answer"
		<-done

		checkBody(t, w, http.StatusOK, "fake answer")
		// Ensure that match is correctly recorded in metrics
		f.checkMetrics(t, M_HTTP_MATCH)
	})

	t.Run("times out when no proxy responds", func(t *testing.T) {
		if testing.Short() {
			t.Skip("takes a few seconds")
		}
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		r := newLegacyClientOfferRequest(t)

		snowflake := addFakeSnowflake(f.ctx)
		done := make(chan struct{})
		go func() {
			clientOffers(f.ipc, w, r)
			close(done)
		}()
		checkOfferSDP(t, <-snowflake.offerChannel)
		<-done

		if w.Code != http.StatusGatewayTimeout {
			t.Errorf("status = %d, want %d", w.Code, http.StatusGatewayTimeout)
		}
	})
}

// newAMPClientOfferRequest builds a GET to the AMP cache endpoint carrying an
// offer in the URL path.
func newAMPClientOfferRequest(t *testing.T, natType string) *http.Request {
	t.Helper()
	encOffer, err := (&messages.ClientPollRequest{Offer: rawOffer, NAT: natType}).EncodeClientPollRequest()
	if err != nil {
		t.Fatalf("EncodeClientPollRequest: %v", err)
	}
	r, err := http.NewRequest("GET", "/amp/client/"+amp.EncodePath(encOffer), nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	return r
}

func checkAMPBody(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	body, err := decodeAMPArmorToString(w.Body)
	if err != nil {
		t.Fatalf("decodeAMPArmorToString: %v", err)
	}
	if body != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}

func TestBrokerAMPClientOffers(t *testing.T) {
	t.Parallel()

	t.Run("with status 200 when request is badly formatted", func(t *testing.T) {
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		r, err := http.NewRequest("GET", "/amp/client/bad", nil)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		ampClientOffers(f.ipc, w, r)
		checkAMPBody(t, w, `{"error":"cannot decode URL path"}`)
	})

	t.Run("with error when no snowflakes are available", func(t *testing.T) {
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		ampClientOffers(f.ipc, w, newAMPClientOfferRequest(t, "unknown"))

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		checkAMPBody(t, w, `{"error":"no snowflake proxies currently available"}`)
		// Ensure that denial is correctly recorded in metrics
		f.checkMetrics(t, M_AMP_DENIED)
	})

	t.Run("with a proxy answer if available", func(t *testing.T) {
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		r := newAMPClientOfferRequest(t, "unknown")

		// Prepare a fake proxy to respond with.
		snowflake := addFakeSnowflake(f.ctx)
		done := make(chan struct{})
		go func() {
			ampClientOffers(f.ipc, w, r)
			close(done)
		}()
		checkOfferSDP(t, <-snowflake.offerChannel)
		snowflake.answerChannel <- "fake answer"
		<-done

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		checkAMPBody(t, w, `{"answer":"fake answer"}`)
		// Ensure that match is correctly recorded in metrics
		f.checkMetrics(t, M_AMP_MATCH)
	})

	t.Run("times out when no proxy responds", func(t *testing.T) {
		if testing.Short() {
			t.Skip("takes a few seconds")
		}
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		r := newAMPClientOfferRequest(t, "unknown")

		snowflake := addFakeSnowflake(f.ctx)
		done := make(chan struct{})
		go func() {
			ampClientOffers(f.ipc, w, r)
			close(done)
		}()
		checkOfferSDP(t, <-snowflake.offerChannel)
		<-done

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		checkAMPBody(t, w, `{"error":"timed out waiting for answer!"}`)
	})

	t.Run("and correctly geolocates remote addr", func(t *testing.T) {
		f := newBrokerFixture()
		if err := f.ctx.metrics.LoadGeoipDatabases("test_geoip", "test_geoip6"); err != nil {
			t.Fatalf("LoadGeoipDatabases: %v", err)
		}
		w := httptest.NewRecorder()
		ampClientOffers(f.ipc, w, newAMPClientOfferRequest(t, NATUnknown))

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		checkAMPBody(t, w, `{"error":"no snowflake proxies currently available"}`)
		f.checkMetrics(t, M_AMP_DENIED)
	})
}

func newProxyPollRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("POST", "snowflake.broker/proxy", strings.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	return r
}

const proxyPollBody = `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0", "AcceptedRelayPattern": "snowflake.torproject.net"}`

func checkContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("body %q does not contain %q", got, want)
	}
}

func TestBrokerProxyPolls(t *testing.T) {
	t.Parallel()

	defaultBridgeValue, err := hex.DecodeString("2B280B23E1107BB62ABFC40DDCC8824814F80A72")
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	var defaultBridge [20]byte
	copy(defaultBridge[:], defaultBridgeValue)

	t.Run("with a client offer if available", func(t *testing.T) {
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		r := newProxyPollRequest(t, proxyPollBody)

		done := make(chan struct{})
		go func() {
			proxyPolls(f.ipc, w, r)
			close(done)
		}()

		// Pass a fake client offer to this proxy
		p := <-f.ctx.proxyPolls
		if p.id != sid {
			t.Errorf("poll id = %q, want %q", p.id, sid)
		}
		p.offerChannel <- &ClientOffer{sdp: []byte("fake offer"), fingerprint: defaultBridge[:]}
		<-done

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		checkContains(t, w.Body.String(), `"Status":"client match","Offer":"fake offer","NAT":"",`)
		checkContains(t, w.Body.String(), `,"RelayURL":"wss://snowflake.torproject.net/"`)
	})

	t.Run("return empty 200 OK when no client offer is available", func(t *testing.T) {
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		r := newProxyPollRequest(t, proxyPollBody)

		done := make(chan struct{})
		go func() {
			proxyPolls(f.ipc, w, r)
			close(done)
		}()

		p := <-f.ctx.proxyPolls
		if p.id != sid {
			t.Errorf("poll id = %q, want %q", p.id, sid)
		}
		// nil means timeout
		p.offerChannel <- nil
		<-done

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		checkContains(t, w.Body.String(), `{"Status":"no match","Offer":"","NAT":"","NextPoll"`)
		checkContains(t, w.Body.String(), `,"RelayURL":""}`)
	})

	t.Run("with incorrect relay pattern if no AcceptedRelayPattern", func(t *testing.T) {
		f := newBrokerFixture()
		w := httptest.NewRecorder()
		r := newProxyPollRequest(t, `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0"}`)

		go f.ctx.Broker()
		done := make(chan struct{})
		go func() {
			proxyPolls(f.ipc, w, r)
			close(done)
		}()
		<-done

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		// A non-standard status makes the decoder return an error carrying
		// the status text, but it still fills in the response.
		resp, _ := messages.DecodeProxyPollResponse(w.Body.Bytes())
		if resp.Status != "incorrect relay pattern" {
			t.Errorf("status = %q, want %q", resp.Status, "incorrect relay pattern")
		}
	})
}

// newBrokerFixtureWithSnowflake registers a snowflake under the well-known sid,
// so a proxy answer for that sid has somewhere to land.
func newBrokerFixtureWithSnowflake() (*brokerFixture, *Snowflake) {
	f := newBrokerFixture()
	s := NewSnowflake(sid, "", NATUnrestricted, 0)
	f.ctx.GetPool(&ProxyPoll{natType: NATUnrestricted}).Push(s)
	f.ctx.idToSnowflake[s.id] = s
	return f, s
}

func newProxyAnswerRequest(t *testing.T, body io.Reader) *http.Request {
	t.Helper()
	r, err := http.NewRequest("POST", "snowflake.broker/answer", body)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	return r
}

func TestBrokerProxyAnswers(t *testing.T) {
	t.Parallel()

	t.Run("by passing to the client if valid", func(t *testing.T) {
		f, s := newBrokerFixtureWithSnowflake()
		data, err := createProxyAnswer(rawAnswer, sid)
		if err != nil {
			t.Fatalf("createProxyAnswer: %v", err)
		}
		w := httptest.NewRecorder()
		r := newProxyAnswerRequest(t, data)

		done := make(chan struct{})
		go func() {
			proxyAnswers(f.ipc, w, r)
			close(done)
		}()
		answer := <-s.answerChannel
		<-done

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		if answer != rawAnswer {
			t.Errorf("answer = %q, want %q", answer, rawAnswer)
		}
	})

	t.Run("with client gone status if the proxy ID is not recognized", func(t *testing.T) {
		f, _ := newBrokerFixtureWithSnowflake()
		data, err := createProxyAnswer(rawAnswer, "invalid")
		if err != nil {
			t.Fatalf("createProxyAnswer: %v", err)
		}
		w := httptest.NewRecorder()
		proxyAnswers(f.ipc, w, newProxyAnswerRequest(t, data))

		checkBody(t, w, http.StatusOK, `{"Status":"client gone"}`)
	})

	t.Run("with error if the proxy gives invalid answer", func(t *testing.T) {
		f, _ := newBrokerFixtureWithSnowflake()
		w := httptest.NewRecorder()
		proxyAnswers(f.ipc, w, newProxyAnswerRequest(t, bytes.NewReader(nil)))

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("with error if the proxy writes too much data", func(t *testing.T) {
		f, _ := newBrokerFixtureWithSnowflake()
		w := httptest.NewRecorder()
		proxyAnswers(f.ipc, w, newProxyAnswerRequest(t, bytes.NewReader(make([]byte, 100001))))

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

// newE2EFixture builds a broker with a NullLogger for the end-to-end cases,
// which assert on HTTP responses rather than on metrics output.
func newE2EFixture() *brokerFixture {
	ctx := NewBrokerContext(NullLogger(), "snowflake.torproject.net")
	return &brokerFixture{buf: new(bytes.Buffer), ctx: ctx, ipc: &IPC{ctx}}
}

const e2eProxyPollBody = `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0","AcceptedRelayPattern":"snowflake.torproject.net"}`

func TestEndToEndClientProxyDataRace(t *testing.T) {
	t.Parallel()

	f := newE2EFixture()
	go f.ctx.Broker()

	proxyDone := make(chan struct{})
	clientDone := make(chan struct{})

	// Make proxy poll
	wp := httptest.NewRecorder()
	rp := newProxyPollRequest(t, e2eProxyPollBody)
	go func() {
		proxyPolls(f.ipc, wp, rp)
		close(proxyDone)
	}()

	// Client offer
	wc := httptest.NewRecorder()
	rc := newClientOfferRequest(t, NATUnknown)
	go func() {
		clientOffers(f.ipc, wc, rc)
		close(clientDone)
	}()

	<-proxyDone
	if wp.Code != http.StatusOK {
		t.Errorf("proxy poll status = %d, want %d", wp.Code, http.StatusOK)
	}

	// Proxy answers
	wa := httptest.NewRecorder()
	datap, err := createProxyAnswer(rawAnswer, sid)
	if err != nil {
		t.Fatalf("createProxyAnswer: %v", err)
	}
	answerDone := make(chan struct{})
	ra := newProxyAnswerRequest(t, datap)
	go func() {
		proxyAnswers(f.ipc, wa, ra)
		close(answerDone)
	}()

	<-answerDone
	<-clientDone
}

func TestEndToEndProxyPollIntervalAndRateLimiting(t *testing.T) {
	t.Parallel()

	f := newE2EFixture()
	go f.ctx.Broker()

	proxyDone := make(chan struct{})
	clientDone := make(chan struct{})

	// Make proxy poll
	wp := httptest.NewRecorder()
	rp := newProxyPollRequest(t, e2eProxyPollBody)
	rp.RemoteAddr = "foo"
	go func() {
		proxyPolls(f.ipc, wp, rp)
		close(proxyDone)
	}()

	// Client offer
	wc := httptest.NewRecorder()
	rc := newClientOfferRequest(t, NATUnknown)
	go func() {
		clientOffers(f.ipc, wc, rc)
		close(clientDone)
	}()

	<-proxyDone
	if wp.Code != http.StatusOK {
		t.Errorf("proxy poll status = %d, want %d", wp.Code, http.StatusOK)
	}
	resp, err := messages.DecodeProxyPollResponse(wp.Body.Bytes())
	if err != nil {
		t.Fatalf("DecodeProxyPollResponse: %v", err)
	}
	if resp.NextPoll <= 0 {
		t.Errorf("NextPoll = %d, want > 0", resp.NextPoll)
	}

	// Proxy answers
	wa := httptest.NewRecorder()
	datap, err := createProxyAnswer(rawAnswer, sid)
	if err != nil {
		t.Fatalf("createProxyAnswer: %v", err)
	}
	answerDone := make(chan struct{})
	ra := newProxyAnswerRequest(t, datap)
	go func() {
		proxyAnswers(f.ipc, wa, ra)
		close(answerDone)
	}()
	<-answerDone
	<-clientDone

	// A different proxy polling from the same address too soon is rate limited.
	wp = httptest.NewRecorder()
	rp = newProxyPollRequest(t, `{"Sid":"ymbcCMto7KHNGYlp2","Version":"1.0","AcceptedRelayPattern":"snowflake.torproject.net"}`)
	rp.RemoteAddr = "foo"
	proxyPolls(f.ipc, wp, rp)

	if wp.Code != http.StatusOK {
		t.Errorf("proxy poll status = %d, want %d", wp.Code, http.StatusOK)
	}
	resp, err = messages.DecodeProxyPollResponse(wp.Body.Bytes())
	if err != nil {
		t.Fatalf("DecodeProxyPollResponse: %v", err)
	}
	if resp.Status != "polled too soon" {
		t.Errorf("status = %q, want %q", resp.Status, "polled too soon")
	}
	if resp.NextPoll <= 0 {
		t.Errorf("NextPoll = %d, want > 0", resp.NextPoll)
	}
}

func TestEndToEndSnowflakeBrokering(t *testing.T) {
	t.Parallel()

	f := newE2EFixture()

	// Proxy polls with its ID first...
	wP := httptest.NewRecorder()
	rP := newProxyPollRequest(t, e2eProxyPollBody)
	polled := make(chan struct{})
	go func() {
		proxyPolls(f.ipc, wP, rP)
		close(polled)
	}()

	// Manually do the Broker goroutine action here for full control.
	p := <-f.ctx.proxyPolls
	if p.id != sid {
		t.Fatalf("poll id = %q, want %q", p.id, sid)
	}
	s := NewSnowflake(p.id, "", NATUnrestricted, 0)
	f.ctx.GetPool(&ProxyPoll{natType: NATUnrestricted}).Push(s)
	f.ctx.idToSnowflake[s.id] = s
	go func() {
		p.offerChannel <- <-s.offerChannel
	}()
	if f.ctx.idToSnowflake[sid] == nil {
		t.Fatalf("idToSnowflake[%q] is nil", sid)
	}

	// Client request blocks until proxy answer arrives.
	wC := httptest.NewRecorder()
	rC := newClientOfferRequest(t, NATUnknown)
	done := make(chan struct{})
	go func() {
		clientOffers(f.ipc, wC, rC)
		close(done)
	}()

	<-polled
	if wP.Code != http.StatusOK {
		t.Errorf("proxy poll status = %d, want %d", wP.Code, http.StatusOK)
	}
	checkContains(t, wP.Body.String(), `{"Status":"client match","Offer":`)
	checkContains(t, wP.Body.String(), `"RelayURL":"wss://snowflake.torproject.net/"}`)
	respP, err := messages.DecodeProxyPollResponse(wP.Body.Bytes())
	if err != nil {
		t.Fatalf("DecodeProxyPollResponse: %v", err)
	}
	if respP.Offer != rawOffer {
		t.Errorf("offer = %q, want %q", respP.Offer, rawOffer)
	}

	// Follow up with the answer request afterwards
	wA := httptest.NewRecorder()
	dataA, err := createProxyAnswer(rawAnswer, sid)
	if err != nil {
		t.Fatalf("createProxyAnswer: %v", err)
	}
	proxyAnswers(f.ipc, wA, newProxyAnswerRequest(t, dataA))
	if wA.Code != http.StatusOK {
		t.Errorf("proxy answer status = %d, want %d", wA.Code, http.StatusOK)
	}

	<-done
	if wC.Code != http.StatusOK {
		t.Errorf("client status = %d, want %d", wC.Code, http.StatusOK)
	}
	respC, err := messages.DecodeClientPollResponse(wC.Body.Bytes())
	if err != nil {
		t.Fatalf("DecodeClientPollResponse: %v", err)
	}
	if respC.Answer != rawAnswer {
		t.Errorf("answer = %q, want %q", respC.Answer, rawAnswer)
	}
}

func TestSnowflakeHeap(t *testing.T) {
	t.Parallel()

	h := new(SnowflakeHeap)
	heap.Init(h)
	if got := h.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}

	// The heap is ordered by client count, smallest first.
	for i, clients := range []uint64{4, 5, 3, 1} {
		s := new(Snowflake)
		s.clients = clients
		heap.Push(h, s)
		if got := h.Len(); got != i+1 {
			t.Errorf("Len() = %d, want %d", got, i+1)
		}
	}

	// Removing index 0 drops the least-loaded snowflake (1 client).
	heap.Remove(h, 0)
	if got := h.Len(); got != 3 {
		t.Fatalf("Len() = %d, want 3", got)
	}

	for i, wantClients := range []uint64{3, 4, 5} {
		r := heap.Pop(h).(*Snowflake)
		if got, want := h.Len(), 2-i; got != want {
			t.Errorf("Len() = %d, want %d", got, want)
		}
		if r.clients != wantClients {
			t.Errorf("popped snowflake has %d clients, want %d", r.clients, wantClients)
		}
		if r.index != -1 {
			t.Errorf("popped snowflake index = %d, want -1", r.index)
		}
	}
}

func TestInvalidGeoipFile(t *testing.T) {
	t.Parallel()

	// Make sure things behave properly if geoip file fails to load
	ctx := NewBrokerContext(NullLogger(), "")
	if err := ctx.metrics.LoadGeoipDatabases("invalid_filename", "invalid_filename6"); err != nil {
		log.Printf("loading geo ip databases returned error: %v", err)
	}
	ctx.metrics.UpdateProxyStats("127.0.0.1", "", NATUnrestricted)
	if ctx.metrics.geoipdb != nil {
		t.Error("geoipdb is non-nil after loading invalid database files")
	}
}

// newMetricsFixture builds a broker with geoip loaded and a short poll
// interval, so rate-limit expiry is testable.
func newMetricsFixture(t *testing.T) *brokerFixture {
	t.Helper()
	f := newBrokerFixture()
	f.ctx.strictPool.pollInterval = time.Second
	f.ctx.moderatePool.pollInterval = time.Second
	f.ctx.openPool.pollInterval = time.Second
	if err := f.ctx.metrics.LoadGeoipDatabases("test_geoip", "test_geoip6"); err != nil {
		t.Fatalf("LoadGeoipDatabases: %v", err)
	}
	return f
}

// pollProxyOnce runs one proxy poll to completion, unblocking it with a nil
// offer (which the broker treats as a timeout).
func pollProxyOnce(t *testing.T, f *brokerFixture, body, remoteAddr string) {
	t.Helper()
	w := httptest.NewRecorder()
	r := newProxyPollRequest(t, body)
	r.RemoteAddr = remoteAddr

	done := make(chan struct{})
	go func() {
		proxyPolls(f.ipc, w, r)
		close(done)
	}()
	p := <-f.ctx.proxyPolls // manually unblock poll
	p.offerChannel <- nil
	<-done
}

func proxyPollBodyOfType(proxyType string) string {
	if proxyType == "" {
		return `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0","AcceptedRelayPattern":"snowflake.torproject.net"}`
	}
	return `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0","Type":"` + proxyType + `","AcceptedRelayPattern":"snowflake.torproject.net"}`
}

func TestMetricsForProxyPolls(t *testing.T) {
	t.Parallel()

	f := newMetricsFixture(t)
	// Four distinct CA addresses, one per proxy type.
	for i, proxyType := range []string{"", "standalone", "badge", "webext"} {
		pollProxyOnce(t, f, proxyPollBodyOfType(proxyType), fmt.Sprintf("129.97.208.%d", 23+i))
	}
	f.ctx.metrics.printMetrics()

	metricsStr := f.buf.String()
	wantPrefix := "snowflake-stats-end " + time.Now().UTC().Format("2006-01-02 15:04:05") + " (86400 s)\nsnowflake-ips CA=4\n"
	if !strings.HasPrefix(metricsStr, wantPrefix) {
		t.Errorf("metrics do not start with %q; got:\n%s", wantPrefix, metricsStr)
	}
	for _, want := range []string{
		"\nsnowflake-ips-standalone 1\n",
		"\nsnowflake-ips-badge 1\n",
		"\nsnowflake-ips-webext 1\n",
		"\nsnowflake-ips-iptproxy 0\n",
		"\nsnowflake-ips-bloco 0\n",
	} {
		checkContains(t, metricsStr, want)
	}
	if strings.Contains(metricsStr, "snowflake-ips-unknown") {
		t.Errorf("metrics unexpectedly contain snowflake-ips-unknown:\n%s", metricsStr)
	}
	if !strings.HasSuffix(metricsStr, M_PROXY_POLLS_TAIL) {
		t.Errorf("metrics do not end with\n%s\ngot:\n%s", M_PROXY_POLLS_TAIL, metricsStr)
	}
}

func TestMetricsForNoProxiesAvailable(t *testing.T) {
	t.Parallel()

	f := newMetricsFixture(t)
	w := httptest.NewRecorder()
	r := newClientOfferRequest(t, NATUnknown)
	r.RemoteAddr = "129.97.208.23:8888" // CA geoip
	clientOffers(f.ipc, w, r)

	f.checkMetrics(t, M_NO_PROXIES)

	// Test reset
	f.buf.Reset()
	f.ctx.metrics.printMetrics()
	for _, want := range []string{
		"\nsnowflake-ips \n",
		"\nsnowflake-ips-standalone 0\n",
		"\nsnowflake-ips-badge 0\n",
		"\nsnowflake-ips-webext 0\n",
		"\nsnowflake-ips-iptproxy 0\n",
		"\nsnowflake-ips-bloco 0\n",
		M_RESET,
	} {
		checkContains(t, f.buf.String(), want)
	}
	if strings.Contains(f.buf.String(), "snowflake-ips-unknown") {
		t.Errorf("metrics unexpectedly contain snowflake-ips-unknown:\n%s", f.buf.String())
	}
}

func TestMetricsForClientProxyMatch(t *testing.T) {
	t.Parallel()

	f := newMetricsFixture(t)
	w := httptest.NewRecorder()
	r := newClientOfferRequest(t, NATUnknown)

	// Prepare a fake proxy to respond with.
	snowflake := addFakeSnowflake(f.ctx)
	done := make(chan struct{})
	go func() {
		clientOffers(f.ipc, w, r)
		close(done)
	}()
	checkOfferSDP(t, <-snowflake.offerChannel)
	snowflake.answerChannel <- "fake answer"
	<-done

	f.checkMetrics(t, "client-denied-count 0\nclient-restricted-denied-count 0\nclient-unrestricted-denied-count 0\nclient-nat-strict-denied-count 0\nclient-nat-moderate-denied-count 0\nclient-nat-open-denied-count 0\nclient-nat-unknown-denied-count 0\nclient-snowflake-match-count 8")
}

// Counts are reported binned to multiples of 8, so 9 denials round up to 16.
func TestMetricsBinningBoundary(t *testing.T) {
	t.Parallel()

	f := newMetricsFixture(t)
	for i := 0; i < 9; i++ {
		clientOffers(f.ipc, httptest.NewRecorder(), newClientOfferRequest(t, NATRestricted))
	}

	f.buf.Reset()
	f.checkMetrics(t, "client-denied-count 16\nclient-restricted-denied-count 16\nclient-unrestricted-denied-count 0\nclient-nat-strict-denied-count 0\nclient-nat-moderate-denied-count 0\nclient-nat-open-denied-count 0\nclient-nat-unknown-denied-count 0\n")
}

func TestMetricsProxyCountsByUniqueIP(t *testing.T) {
	t.Parallel()

	f := newMetricsFixture(t)
	body := proxyPollBodyOfType("")
	pollProxyOnce(t, f, body, "129.97.208.23:8080") // CA geoip
	<-time.After(2 * time.Second)                   // wait for rate limit to expire
	pollProxyOnce(t, f, body, "129.97.208.23:8080") // same IP, so still one proxy

	f.ctx.metrics.printMetrics()
	checkContains(t, f.buf.String(), "snowflake-ips CA=1\n")
	checkContains(t, f.buf.String(), "snowflake-ips-total 1\n")
}

func TestMetricsProxyCountsByNATType(t *testing.T) {
	t.Parallel()

	f := newMetricsFixture(t)
	for i, natType := range []string{"restricted", "unrestricted"} {
		body := `{"Sid":"ymbcCMto7KHNGYlp","Version":"1.2","Type":"unknown","NAT":"` + natType + `","AcceptedRelayPattern":"snowflake.torproject.net"}`
		pollProxyOnce(t, f, body, fmt.Sprintf("129.97.208.%d:8888", 23+i)) // CA geoip
	}

	f.checkMetrics(t, "snowflake-ips-nat-restricted 1\nsnowflake-ips-nat-unrestricted 1\nsnowflake-ips-nat-unknown 0\nsnowflake-ips-nat-strict 0\nsnowflake-ips-nat-moderate 0\nsnowflake-ips-nat-open 0")
}

func TestMetricsClientFailuresByNATType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		natType string
		want    string
	}{
		{NATRestricted, "client-denied-count 8\nclient-restricted-denied-count 8\nclient-unrestricted-denied-count 0\nclient-nat-strict-denied-count 0\nclient-nat-moderate-denied-count 0\nclient-nat-open-denied-count 0\nclient-nat-unknown-denied-count 0\nclient-snowflake-match-count 0"},
		{NATUnrestricted, "client-denied-count 8\nclient-restricted-denied-count 0\nclient-unrestricted-denied-count 8\nclient-nat-strict-denied-count 0\nclient-nat-moderate-denied-count 0\nclient-nat-open-denied-count 0\nclient-nat-unknown-denied-count 0\nclient-snowflake-match-count 0"},
		{NATUnknown, "client-denied-count 8\nclient-restricted-denied-count 0\nclient-unrestricted-denied-count 0\nclient-nat-strict-denied-count 0\nclient-nat-moderate-denied-count 0\nclient-nat-open-denied-count 0\nclient-nat-unknown-denied-count 8\nclient-snowflake-match-count 0"},
	} {
		t.Run(tc.natType, func(t *testing.T) {
			f := newMetricsFixture(t)
			clientOffers(f.ipc, httptest.NewRecorder(), newClientOfferRequest(t, tc.natType))
			f.checkMetrics(t, tc.want)
		})
	}
}

// The set of IPs seen is per reporting interval: printing must clear it, so a
// different proxy in the next interval is still counted as one.
func TestMetricsSeenIPsClearedAfterPrint(t *testing.T) {
	t.Parallel()

	f := newMetricsFixture(t)
	body := proxyPollBodyOfType("")
	for _, addr := range []string{"129.97.208.23", "129.97.208.24"} {
		pollProxyOnce(t, f, body, addr) // CA geoip
		f.ctx.metrics.printMetrics()
		checkContains(t, f.buf.String(), "snowflake-ips CA=1")
		checkContains(t, f.buf.String(), "snowflake-ips-total 1")
		f.buf.Reset()
	}
}

func TestConcurrency(t *testing.T) {
	ctx := NewBrokerContext(NullLogger(), "snowflake.torproject.net")
	i := &IPC{ctx}
	go ctx.Broker()

	var wg sync.WaitGroup

	const numProxies = 1000
	// Multiple proxy polls
	for x := 0; x < numProxies; x++ {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		id := strings.TrimRight(base64.StdEncoding.EncodeToString(buf), "=")

		wp := httptest.NewRecorder()
		datap := bytes.NewReader(fmt.Appendf(nil, `{"Sid": "%s","Version":"1.0","AcceptedRelayPattern":"snowflake.torproject.net"}`, id))
		rp, err := http.NewRequest("POST", "snowflake.broker/proxy", datap)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		rp.RemoteAddr = fmt.Sprintf("1.1.%d.%d", x/256, x%256)

		go func() {
			proxyPolls(i, wp, rp)
			if wp.Code != http.StatusOK {
				t.Errorf("proxy poll status = %d, want %d", wp.Code, http.StatusOK)
			}

			// Proxy answers
			wa := httptest.NewRecorder()
			dataa, err := createProxyAnswer(rawAnswer, id)
			if err != nil {
				t.Errorf("createProxyAnswer: %v", err)
				return
			}
			ra, err := http.NewRequest("POST", "snowflake.broker/answer", dataa)
			if err != nil {
				t.Errorf("http.NewRequest: %v", err)
				return
			}
			go proxyAnswers(i, wa, ra)
		}()
	}
	// Wait for all proxies to be registered by the broker goroutine before
	// sending client offers: a client that arrives before its proxy has been
	// pushed onto a pool is answered with "no snowflake proxies available".
	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx.snowflakeLock.Lock()
		registered := len(ctx.idToSnowflake)
		ctx.snowflakeLock.Unlock()
		if registered == numProxies {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d proxies registered", registered, numProxies)
		}
		time.Sleep(time.Millisecond)
	}

	// Multiple client offers
	for x := 0; x < 500; x++ {
		wg.Add(1)
		wc := httptest.NewRecorder()
		datac, err := createClientOffer(rawOffer, NATUnrestricted, "")
		if err != nil {
			t.Fatalf("createClientOffer: %v", err)
		}
		rc, err := http.NewRequest("POST", "snowflake.broker/client", datac)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}

		go func() {
			defer wg.Done()
			clientOffers(i, wc, rc)
			if wc.Code != http.StatusOK {
				t.Errorf("client status = %d, want %d", wc.Code, http.StatusOK)
			}
			respC, _ := messages.DecodeClientPollResponse(wc.Body.Bytes())
			if !strings.Contains(respC.Answer, "129.97.208.23") {
				t.Errorf("answer %q does not contain %q", respC.Answer, "129.97.208.23")
			}
		}()
	}
	wg.Wait()
}
