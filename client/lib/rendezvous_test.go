package snowflake_client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/pion/webrtc/v4"
	"tgragnato.it/snowflake/common/amp"
	"tgragnato.it/snowflake/common/messages"
	"tgragnato.it/snowflake/common/nat"
	"tgragnato.it/snowflake/common/sqsclient"
	"tgragnato.it/snowflake/common/util"
)

// mockTransport's RoundTrip method returns a response with a fake status and
// body.
type mockTransport struct {
	statusCode int
	body       []byte
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", t.statusCode, http.StatusText(t.statusCode)),
		StatusCode: t.statusCode,
		Body:       io.NopCloser(bytes.NewReader(t.body)),
	}, nil
}

// errorTransport's RoundTrip method returns an error.
type errorTransport struct {
	err error
}

func (t errorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, t.err
}

// makeEncPollReq returns an encoded client poll request containing a given
// offer.
func makeEncPollReq(offer string) []byte {
	encPollReq, err := (&messages.ClientPollRequest{
		Offer: offer,
		NAT:   nat.NATUnknown,
	}).EncodeClientPollRequest()
	if err != nil {
		panic(err)
	}
	return encPollReq
}

// makeEncPollResp returns an encoded client poll response with given answer and
// error strings.
func makeEncPollResp(answer, errorStr string) []byte {
	encPollResp, err := (&messages.ClientPollResponse{
		Answer: answer,
		Error:  errorStr,
	}).EncodePollResponse()
	if err != nil {
		panic(err)
	}
	return encPollResp
}

var fakeEncPollReq = makeEncPollReq(`{"type":"offer","sdp":"test"}`)

func TestHTTPRendezvousConstruction(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		fronts     []string
		wantFronts []string
	}{
		{"no front domain", []string{}, []string{}},
		{"with front domain", []string{"front"}, []string{"front"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &mockTransport{http.StatusOK, []byte{}}
			rend, err := newHTTPRendezvous("http://test.broker", tc.fronts, transport)
			if err != nil {
				t.Fatalf("newHTTPRendezvous: %v", err)
			}
			if rend.brokerURL == nil {
				t.Fatal("brokerURL is nil")
			}
			if got := rend.brokerURL.Host; got != "test.broker" {
				t.Errorf("brokerURL.Host = %q, want %q", got, "test.broker")
			}
			if !slices.Equal(rend.fronts, tc.wantFronts) {
				t.Errorf("fronts = %v, want %v", rend.fronts, tc.wantFronts)
			}
			if rend.transport != transport {
				t.Error("transport was not retained")
			}
		})
	}
}

func TestHTTPRendezvousExchange(t *testing.T) {
	t.Parallel()

	t.Run("responds with answer", func(t *testing.T) {
		fakeEncPollResp := makeEncPollResp(
			`{"answer": "{\"type\":\"answer\",\"sdp\":\"fake\"}" }`,
			"",
		)
		rend, err := newHTTPRendezvous("http://test.broker", []string{},
			&mockTransport{http.StatusOK, fakeEncPollResp})
		if err != nil {
			t.Fatalf("newHTTPRendezvous: %v", err)
		}
		answer, err := rend.Exchange(fakeEncPollReq)
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		if !bytes.Equal(answer, fakeEncPollResp) {
			t.Errorf("answer = %q, want %q", answer, fakeEncPollResp)
		}
	})

	t.Run("responds with no answer", func(t *testing.T) {
		fakeEncPollResp := makeEncPollResp(
			"",
			`{"error": "no snowflake proxies currently available"}`,
		)
		rend, err := newHTTPRendezvous("http://test.broker", []string{},
			&mockTransport{http.StatusOK, fakeEncPollResp})
		if err != nil {
			t.Fatalf("newHTTPRendezvous: %v", err)
		}
		answer, err := rend.Exchange(fakeEncPollReq)
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		if !bytes.Equal(answer, fakeEncPollResp) {
			t.Errorf("answer = %q, want %q", answer, fakeEncPollResp)
		}
	})

	t.Run("fails with unexpected HTTP status code", func(t *testing.T) {
		rend, err := newHTTPRendezvous("http://test.broker", []string{},
			&mockTransport{http.StatusInternalServerError, []byte{}})
		if err != nil {
			t.Fatalf("newHTTPRendezvous: %v", err)
		}
		answer, err := rend.Exchange(fakeEncPollReq)
		if answer != nil {
			t.Errorf("answer = %q, want nil", answer)
		}
		if err == nil {
			t.Fatal("Exchange succeeded, want error")
		}
		if got := err.Error(); got != brokerErrorUnexpected {
			t.Errorf("err = %q, want %q", got, brokerErrorUnexpected)
		}
	})

	t.Run("fails with error", func(t *testing.T) {
		transportErr := errors.New("error")
		rend, err := newHTTPRendezvous("http://test.broker", []string{},
			&errorTransport{err: transportErr})
		if err != nil {
			t.Fatalf("newHTTPRendezvous: %v", err)
		}
		answer, err := rend.Exchange(fakeEncPollReq)
		if !errors.Is(err, transportErr) {
			t.Errorf("err = %v, want %v", err, transportErr)
		}
		if answer != nil {
			t.Errorf("answer = %q, want nil", answer)
		}
	})

	t.Run("fails with large read", func(t *testing.T) {
		rend, err := newHTTPRendezvous("http://test.broker", []string{},
			&mockTransport{http.StatusOK, make([]byte, readLimit+1)})
		if err != nil {
			t.Fatalf("newHTTPRendezvous: %v", err)
		}
		if _, err = rend.Exchange(fakeEncPollReq); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("err = %v, want %v", err, io.ErrUnexpectedEOF)
		}
	})
}

func ampArmorEncode(p []byte) []byte {
	var buf bytes.Buffer
	enc, err := amp.NewArmorEncoder(&buf)
	if err != nil {
		panic(err)
	}
	_, err = enc.Write(p)
	if err != nil {
		panic(err)
	}
	err = enc.Close()
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func TestAMPCacheRendezvousConstruction(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		cache        string
		fronts       []string
		wantCacheURL string
	}{
		{"no cache and no front domain", "", []string{}, ""},
		{"cache and no front domain", "https://amp.cache/", []string{}, "https://amp.cache/"},
		{"no cache and front domain", "", []string{"front"}, ""},
		{"cache and front domain", "https://amp.cache/", []string{"front"}, "https://amp.cache/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &mockTransport{http.StatusOK, []byte{}}
			rend, err := newAMPCacheRendezvous("http://test.broker", tc.cache, tc.fronts, transport)
			if err != nil {
				t.Fatalf("newAMPCacheRendezvous: %v", err)
			}
			if rend.brokerURL == nil {
				t.Fatal("brokerURL is nil")
			}
			if got := rend.brokerURL.String(); got != "http://test.broker" {
				t.Errorf("brokerURL = %q, want %q", got, "http://test.broker")
			}
			switch {
			case tc.wantCacheURL == "":
				if rend.cacheURL != nil {
					t.Errorf("cacheURL = %v, want nil", rend.cacheURL)
				}
			case rend.cacheURL == nil:
				t.Errorf("cacheURL = nil, want %q", tc.wantCacheURL)
			default:
				if got := rend.cacheURL.String(); got != tc.wantCacheURL {
					t.Errorf("cacheURL = %q, want %q", got, tc.wantCacheURL)
				}
			}
			if !slices.Equal(rend.fronts, tc.fronts) {
				t.Errorf("fronts = %v, want %v", rend.fronts, tc.fronts)
			}
			if rend.transport != transport {
				t.Error("transport was not retained")
			}
		})
	}
}

func TestAMPCacheRendezvousExchange(t *testing.T) {
	t.Parallel()

	t.Run("responds with answer", func(t *testing.T) {
		fakeEncPollResp := makeEncPollResp(
			`{"answer": "{\"type\":\"answer\",\"sdp\":\"fake\"}" }`,
			"",
		)
		rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{},
			&mockTransport{http.StatusOK, ampArmorEncode(fakeEncPollResp)})
		if err != nil {
			t.Fatalf("newAMPCacheRendezvous: %v", err)
		}
		answer, err := rend.Exchange(fakeEncPollReq)
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		if !bytes.Equal(answer, fakeEncPollResp) {
			t.Errorf("answer = %q, want %q", answer, fakeEncPollResp)
		}
	})

	t.Run("responds with no answer", func(t *testing.T) {
		fakeEncPollResp := makeEncPollResp(
			"",
			`{"error": "no snowflake proxies currently available"}`,
		)
		rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{},
			&mockTransport{http.StatusOK, ampArmorEncode(fakeEncPollResp)})
		if err != nil {
			t.Fatalf("newAMPCacheRendezvous: %v", err)
		}
		answer, err := rend.Exchange(fakeEncPollReq)
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		if !bytes.Equal(answer, fakeEncPollResp) {
			t.Errorf("answer = %q, want %q", answer, fakeEncPollResp)
		}
	})

	t.Run("fails with unexpected HTTP status code", func(t *testing.T) {
		rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{},
			&mockTransport{http.StatusInternalServerError, []byte{}})
		if err != nil {
			t.Fatalf("newAMPCacheRendezvous: %v", err)
		}
		answer, err := rend.Exchange(fakeEncPollReq)
		if answer != nil {
			t.Errorf("answer = %q, want nil", answer)
		}
		if err == nil {
			t.Fatal("Exchange succeeded, want error")
		}
		if got := err.Error(); got != brokerErrorUnexpected {
			t.Errorf("err = %q, want %q", got, brokerErrorUnexpected)
		}
	})

	t.Run("fails with error", func(t *testing.T) {
		transportErr := errors.New("error")
		rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{},
			&errorTransport{err: transportErr})
		if err != nil {
			t.Fatalf("newAMPCacheRendezvous: %v", err)
		}
		answer, err := rend.Exchange(fakeEncPollReq)
		if !errors.Is(err, transportErr) {
			t.Errorf("err = %v, want %v", err, transportErr)
		}
		if answer != nil {
			t.Errorf("answer = %q, want nil", answer)
		}
	})

	t.Run("fails with large read", func(t *testing.T) {
		// readLimit should apply to the raw HTTP body, not the encoded bytes.
		// Encode readLimit bytes—the encoded size will be larger—and try to
		// read the body. It should fail.
		rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{},
			&mockTransport{http.StatusOK, ampArmorEncode(make([]byte, readLimit))})
		if err != nil {
			t.Fatalf("newAMPCacheRendezvous: %v", err)
		}
		// We may get io.ErrUnexpectedEOF here, or something like
		// "missing </pre> tag".
		if _, err = rend.Exchange(fakeEncPollReq); err == nil {
			t.Error("Exchange succeeded, want error")
		}
	})
}

func TestSQSRendezvousConstruction(t *testing.T) {
	t.Parallel()

	transport := &mockTransport{http.StatusOK, []byte{}}
	rend, err := newSQSRendezvous(
		"https://sqs.us-east-1.amazonaws.com",
		"eyJhd3MtYWNjZXNzLWtleS1pZCI6InRlc3QtYWNjZXNzLWtleSIsImF3cy1zZWNyZXQta2V5IjoidGVzdC1zZWNyZXQta2V5In0=",
		transport,
	)
	if err != nil {
		t.Fatalf("newSQSRendezvous: %v", err)
	}
	if rend.sqsClient == nil {
		t.Error("sqsClient is nil")
	}
	if rend.sqsURL == nil {
		t.Fatal("sqsURL is nil")
	}
	if got := rend.sqsURL.String(); got != "https://sqs.us-east-1.amazonaws.com" {
		t.Errorf("sqsURL = %q, want %q", got, "https://sqs.us-east-1.amazonaws.com")
	}
}

const sqsRendezvousResponseQueueURL = "https://sqs.us-east-1.amazonaws.com/testing"

// fakeSQSClient is a test double for sqsclient.SQSClient. Embedding the
// interface satisfies the methods the rendezvous never calls; invoking one of
// those panics, which is what we want from an unexpected call. Each method
// records a call count that tests can read back with calls.
type fakeSQSClient struct {
	sqsclient.SQSClient

	sendMessage    func(context.Context, *sqs.SendMessageInput) (*sqs.SendMessageOutput, error)
	getQueueUrl    func(context.Context, *sqs.GetQueueUrlInput) (*sqs.GetQueueUrlOutput, error)
	receiveMessage func(context.Context, *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error)

	mu     sync.Mutex
	counts map[string]int
}

func (f *fakeSQSClient) calls(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[method]
}

func (f *fakeSQSClient) record(method string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.counts == nil {
		f.counts = make(map[string]int)
	}
	f.counts[method]++
}

func (f *fakeSQSClient) SendMessage(ctx context.Context, input *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	f.record("SendMessage")
	return f.sendMessage(ctx, input)
}

func (f *fakeSQSClient) GetQueueUrl(ctx context.Context, input *sqs.GetQueueUrlInput, _ ...func(*sqs.Options)) (*sqs.GetQueueUrlOutput, error) {
	f.record("GetQueueUrl")
	return f.getQueueUrl(ctx, input)
}

func (f *fakeSQSClient) ReceiveMessage(ctx context.Context, input *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	f.record("ReceiveMessage")
	return f.receiveMessage(ctx, input)
}

// newSQSRendezvousFixture builds a sqsRendezvous backed by a fake SQS client.
func newSQSRendezvousFixture(t *testing.T) (*fakeSQSClient, sqsRendezvous, *url.URL) {
	t.Helper()
	client := &fakeSQSClient{}
	sqsURL, err := url.Parse("https://sqs.us-east-1.amazonaws.com/broker")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	return client, sqsRendezvous{
		transport:  &mockTransport{http.StatusOK, []byte{}},
		sqsClient:  client,
		sqsURL:     sqsURL,
		timeout:    0,
		numRetries: 5,
	}, sqsURL
}

// checkSendMessage validates the poll request the rendezvous publishes and
// returns the client ID it generated, so later calls can be checked against it.
func checkSendMessage(t *testing.T, sqsURL *url.URL, want []byte, clientID *string) func(context.Context, *sqs.SendMessageInput) (*sqs.SendMessageOutput, error) {
	t.Helper()
	return func(_ context.Context, input *sqs.SendMessageInput) (*sqs.SendMessageOutput, error) {
		if got := *input.MessageBody; got != string(want) {
			t.Errorf("MessageBody = %q, want %q", got, want)
		}
		if got := *input.QueueUrl; got != sqsURL.String() {
			t.Errorf("QueueUrl = %q, want %q", got, sqsURL.String())
		}
		*clientID = *input.MessageAttributes["ClientID"].StringValue
		return &sqs.SendMessageOutput{}, nil
	}
}

func checkReceiveMessageInput(t *testing.T, got *sqs.ReceiveMessageInput) {
	t.Helper()
	if *got.QueueUrl != sqsRendezvousResponseQueueURL ||
		got.MaxNumberOfMessages != 1 ||
		got.WaitTimeSeconds != 20 {
		t.Errorf("ReceiveMessage input = %+v", got)
	}
}

func TestSQSRendezvousExchangeRespondsWithAnswer(t *testing.T) {
	t.Parallel()

	client, rend, sqsURL := newSQSRendezvousFixture(t)
	fakeEncPollResp := makeEncPollResp(
		`{"answer": "{\"type\":\"answer\",\"sdp\":\"fake\"}" }`,
		"",
	)

	var clientID string
	client.sendMessage = checkSendMessage(t, sqsURL, fakeEncPollResp, &clientID)
	client.getQueueUrl = func(_ context.Context, input *sqs.GetQueueUrlInput) (*sqs.GetQueueUrlOutput, error) {
		if got, want := *input.QueueName, "snowflake-client-"+clientID; got != want {
			t.Errorf("QueueName = %q, want %q", got, want)
		}
		return &sqs.GetQueueUrlOutput{QueueUrl: aws.String(sqsRendezvousResponseQueueURL)}, nil
	}
	client.receiveMessage = func(_ context.Context, input *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error) {
		checkReceiveMessageInput(t, input)
		return &sqs.ReceiveMessageOutput{
			Messages: []types.Message{{Body: aws.String("answer")}},
		}, nil
	}

	answer, err := rend.Exchange(fakeEncPollResp)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !bytes.Equal(answer, []byte("answer")) {
		t.Errorf("answer = %q, want %q", answer, "answer")
	}
}

func TestSQSRendezvousExchangeCannotGetQueueURL(t *testing.T) {
	t.Parallel()

	client, rend, sqsURL := newSQSRendezvousFixture(t)
	fakeEncPollResp := makeEncPollResp(
		`{"answer": "{\"type\":\"answer\",\"sdp\":\"fake\"}" }`,
		"",
	)

	var clientID string
	client.sendMessage = checkSendMessage(t, sqsURL, fakeEncPollResp, &clientID)
	client.getQueueUrl = func(_ context.Context, input *sqs.GetQueueUrlInput) (*sqs.GetQueueUrlOutput, error) {
		if got, want := *input.QueueName, "snowflake-client-"+clientID; got != want {
			t.Errorf("QueueName = %q, want %q", got, want)
		}
		return nil, errors.New("test error")
	}

	answer, err := rend.Exchange(fakeEncPollResp)
	if answer != nil {
		t.Errorf("answer = %q, want nil", answer)
	}
	if err == nil {
		t.Fatal("Exchange succeeded, want error")
	}
	if got := err.Error(); got != "test error" {
		t.Errorf("err = %q, want %q", got, "test error")
	}
	// The rendezvous should give up only after exhausting its retries.
	if got := client.calls("GetQueueUrl"); got != rend.numRetries {
		t.Errorf("GetQueueUrl calls = %d, want %d", got, rend.numRetries)
	}
}

func TestSQSRendezvousExchangeDoesNotReceiveAnswer(t *testing.T) {
	t.Parallel()

	client, rend, sqsURL := newSQSRendezvousFixture(t)
	fakeEncPollResp := makeEncPollResp(
		`{"answer": "{\"type\":\"answer\",\"sdp\":\"fake\"}" }`,
		"",
	)

	var clientID string
	client.sendMessage = checkSendMessage(t, sqsURL, fakeEncPollResp, &clientID)
	client.getQueueUrl = func(_ context.Context, input *sqs.GetQueueUrlInput) (*sqs.GetQueueUrlOutput, error) {
		if got, want := *input.QueueName, "snowflake-client-"+clientID; got != want {
			t.Errorf("QueueName = %q, want %q", got, want)
		}
		return &sqs.GetQueueUrlOutput{QueueUrl: aws.String(sqsRendezvousResponseQueueURL)}, nil
	}
	client.receiveMessage = func(_ context.Context, input *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error) {
		checkReceiveMessageInput(t, input)
		return &sqs.ReceiveMessageOutput{Messages: []types.Message{}}, nil
	}

	answer, err := rend.Exchange(fakeEncPollResp)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if answer == nil || len(answer) != 0 {
		t.Errorf("answer = %v, want an empty non-nil slice", answer)
	}
	if got := client.calls("ReceiveMessage"); got != rend.numRetries {
		t.Errorf("ReceiveMessage calls = %d, want %d", got, rend.numRetries)
	}
}

func TestBrokerChannel(t *testing.T) {
	t.Parallel()

	answerSdp := &webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  "test",
	}
	answerSdpStr, err := util.SerializeSessionDescription(answerSdp)
	if err != nil {
		t.Fatalf("SerializeSessionDescription: %v", err)
	}
	serverResponse, err := (&messages.ClientPollResponse{Answer: answerSdpStr}).EncodePollResponse()
	if err != nil {
		t.Fatalf("EncodePollResponse: %v", err)
	}

	offerSdp := &webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  "test",
	}

	requestBodyChan := make(chan []byte)
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		go func() {
			requestBodyChan <- body
		}()
		w.Write(serverResponse)
	}))
	defer mockServer.Close()

	brokerChannel, err := newBrokerChannelFromConfig(ClientConfig{
		BrokerURL:         mockServer.URL,
		BridgeFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})
	if err != nil {
		t.Fatalf("newBrokerChannelFromConfig: %v", err)
	}
	brokerChannel.SetNATType(nat.NATRestricted)

	answerSdpReturned, err := brokerChannel.Negotiate(offerSdp, brokerChannel.GetNATType())
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	if *answerSdpReturned != *answerSdp {
		t.Errorf("answer = %+v, want %+v", answerSdpReturned, answerSdp)
	}

	body := <-requestBodyChan
	pollReq, err := messages.DecodeClientPollRequest(body)
	if err != nil {
		t.Fatalf("DecodeClientPollRequest: %v", err)
	}
	if got, want := pollReq.Fingerprint, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; got != want {
		t.Errorf("Fingerprint = %q, want %q", got, want)
	}
	if got := pollReq.NAT; got != nat.NATRestricted {
		t.Errorf("NAT = %q, want %q", got, nat.NATRestricted)
	}
	requestSdp, err := util.DeserializeSessionDescription(pollReq.Offer)
	if err != nil {
		t.Fatalf("DeserializeSessionDescription: %v", err)
	}
	if *requestSdp != *offerSdp {
		t.Errorf("offer = %+v, want %+v", requestSdp, offerSdp)
	}
}
