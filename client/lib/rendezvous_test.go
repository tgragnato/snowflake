package snowflake_client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/tgragnato/snowflake/common/amp"
	"github.com/tgragnato/snowflake/common/messages"
	"github.com/tgragnato/snowflake/common/nat"
	"github.com/tgragnato/snowflake/common/sqsclient"
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

func TestHTTPRendezvous(t *testing.T) {
	Convey("HTTP rendezvous", t, func() {
		Convey("Construct httpRendezvous with no front domain", func() {
			transport := &mockTransport{http.StatusOK, []byte{}}
			rend, err := newHTTPRendezvous("http://test.broker", []string{}, transport)
			So(err, ShouldBeNil)
			So(rend.brokerURL, ShouldNotBeNil)
			So(rend.brokerURL.Host, ShouldResemble, "test.broker")
			So(rend.fronts, ShouldEqual, []string{})
			So(rend.transport, ShouldEqual, transport)
		})

		Convey("Construct httpRendezvous *with* front domain", func() {
			transport := &mockTransport{http.StatusOK, []byte{}}
			rend, err := newHTTPRendezvous("http://test.broker", []string{"front"}, transport)
			So(err, ShouldBeNil)
			So(rend.brokerURL, ShouldNotBeNil)
			So(rend.brokerURL.Host, ShouldResemble, "test.broker")
			So(rend.fronts, ShouldContain, "front")
			So(rend.transport, ShouldEqual, transport)
		})

		Convey("httpRendezvous.Exchange responds with answer", func() {
			fakeEncPollResp := makeEncPollResp(
				`{"answer": "{\"type\":\"answer\",\"sdp\":\"fake\"}" }`,
				"",
			)
			rend, err := newHTTPRendezvous("http://test.broker", []string{},
				&mockTransport{http.StatusOK, fakeEncPollResp})
			So(err, ShouldBeNil)
			answer, err := rend.Exchange(fakeEncPollReq)
			So(err, ShouldBeNil)
			So(answer, ShouldResemble, fakeEncPollResp)
		})

		Convey("httpRendezvous.Exchange responds with no answer", func() {
			fakeEncPollResp := makeEncPollResp(
				"",
				`{"error": "no snowflake proxies currently available"}`,
			)
			rend, err := newHTTPRendezvous("http://test.broker", []string{},
				&mockTransport{http.StatusOK, fakeEncPollResp})
			So(err, ShouldBeNil)
			answer, err := rend.Exchange(fakeEncPollReq)
			So(err, ShouldBeNil)
			So(answer, ShouldResemble, fakeEncPollResp)
		})

		Convey("httpRendezvous.Exchange fails with unexpected HTTP status code", func() {
			rend, err := newHTTPRendezvous("http://test.broker", []string{},
				&mockTransport{http.StatusInternalServerError, []byte{}})
			So(err, ShouldBeNil)
			answer, err := rend.Exchange(fakeEncPollReq)
			So(err, ShouldNotBeNil)
			So(answer, ShouldBeNil)
			So(err.Error(), ShouldResemble, brokerErrorUnexpected)
		})

		Convey("httpRendezvous.Exchange fails with error", func() {
			transportErr := errors.New("error")
			rend, err := newHTTPRendezvous("http://test.broker", []string{},
				&errorTransport{err: transportErr})
			So(err, ShouldBeNil)
			answer, err := rend.Exchange(fakeEncPollReq)
			So(err, ShouldEqual, transportErr)
			So(answer, ShouldBeNil)
		})

		Convey("httpRendezvous.Exchange fails with large read", func() {
			rend, err := newHTTPRendezvous("http://test.broker", []string{},
				&mockTransport{http.StatusOK, make([]byte, readLimit+1)})
			So(err, ShouldBeNil)
			_, err = rend.Exchange(fakeEncPollReq)
			So(err, ShouldEqual, io.ErrUnexpectedEOF)
		})
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

func TestAMPCacheRendezvous(t *testing.T) {
	Convey("AMP cache rendezvous", t, func() {
		Convey("Construct ampCacheRendezvous with no cache and no front domain", func() {
			transport := &mockTransport{http.StatusOK, []byte{}}
			rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{}, transport)
			So(err, ShouldBeNil)
			So(rend.brokerURL, ShouldNotBeNil)
			So(rend.brokerURL.String(), ShouldResemble, "http://test.broker")
			So(rend.cacheURL, ShouldBeNil)
			So(rend.fronts, ShouldResemble, []string{})
			So(rend.transport, ShouldEqual, transport)
		})

		Convey("Construct ampCacheRendezvous with cache and no front domain", func() {
			transport := &mockTransport{http.StatusOK, []byte{}}
			rend, err := newAMPCacheRendezvous("http://test.broker", "https://amp.cache/", []string{}, transport)
			So(err, ShouldBeNil)
			So(rend.brokerURL, ShouldNotBeNil)
			So(rend.brokerURL.String(), ShouldResemble, "http://test.broker")
			So(rend.cacheURL, ShouldNotBeNil)
			So(rend.cacheURL.String(), ShouldResemble, "https://amp.cache/")
			So(rend.fronts, ShouldResemble, []string{})
			So(rend.transport, ShouldEqual, transport)
		})

		Convey("Construct ampCacheRendezvous with no cache and front domain", func() {
			transport := &mockTransport{http.StatusOK, []byte{}}
			rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{"front"}, transport)
			So(err, ShouldBeNil)
			So(rend.brokerURL, ShouldNotBeNil)
			So(rend.brokerURL.String(), ShouldResemble, "http://test.broker")
			So(rend.cacheURL, ShouldBeNil)
			So(rend.fronts, ShouldContain, "front")
			So(rend.transport, ShouldEqual, transport)
		})

		Convey("Construct ampCacheRendezvous with cache and front domain", func() {
			transport := &mockTransport{http.StatusOK, []byte{}}
			rend, err := newAMPCacheRendezvous("http://test.broker", "https://amp.cache/", []string{"front"}, transport)
			So(err, ShouldBeNil)
			So(rend.brokerURL, ShouldNotBeNil)
			So(rend.brokerURL.String(), ShouldResemble, "http://test.broker")
			So(rend.cacheURL, ShouldNotBeNil)
			So(rend.cacheURL.String(), ShouldResemble, "https://amp.cache/")
			So(rend.fronts, ShouldContain, "front")
			So(rend.transport, ShouldEqual, transport)
		})

		Convey("ampCacheRendezvous.Exchange responds with answer", func() {
			fakeEncPollResp := makeEncPollResp(
				`{"answer": "{\"type\":\"answer\",\"sdp\":\"fake\"}" }`,
				"",
			)
			rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{},
				&mockTransport{http.StatusOK, ampArmorEncode(fakeEncPollResp)})
			So(err, ShouldBeNil)
			answer, err := rend.Exchange(fakeEncPollReq)
			So(err, ShouldBeNil)
			So(answer, ShouldResemble, fakeEncPollResp)
		})

		Convey("ampCacheRendezvous.Exchange responds with no answer", func() {
			fakeEncPollResp := makeEncPollResp(
				"",
				`{"error": "no snowflake proxies currently available"}`,
			)
			rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{},
				&mockTransport{http.StatusOK, ampArmorEncode(fakeEncPollResp)})
			So(err, ShouldBeNil)
			answer, err := rend.Exchange(fakeEncPollReq)
			So(err, ShouldBeNil)
			So(answer, ShouldResemble, fakeEncPollResp)
		})

		Convey("ampCacheRendezvous.Exchange fails with unexpected HTTP status code", func() {
			rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{},
				&mockTransport{http.StatusInternalServerError, []byte{}})
			So(err, ShouldBeNil)
			answer, err := rend.Exchange(fakeEncPollReq)
			So(err, ShouldNotBeNil)
			So(answer, ShouldBeNil)
			So(err.Error(), ShouldResemble, brokerErrorUnexpected)
		})

		Convey("ampCacheRendezvous.Exchange fails with error", func() {
			transportErr := errors.New("error")
			rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{},
				&errorTransport{err: transportErr})
			So(err, ShouldBeNil)
			answer, err := rend.Exchange(fakeEncPollReq)
			So(err, ShouldEqual, transportErr)
			So(answer, ShouldBeNil)
		})

		Convey("ampCacheRendezvous.Exchange fails with large read", func() {
			// readLimit should apply to the raw HTTP body, not the
			// encoded bytes. Encode readLimit bytes—the encoded
			// size will be larger—and try to read the body. It
			// should fail.
			rend, err := newAMPCacheRendezvous("http://test.broker", "", []string{},
				&mockTransport{http.StatusOK, ampArmorEncode(make([]byte, readLimit))})
			So(err, ShouldBeNil)
			_, err = rend.Exchange(fakeEncPollReq)
			// We may get io.ErrUnexpectedEOF here, or something
			// like "missing </pre> tag".
			So(err, ShouldNotBeNil)
		})
	})
}

func TestSQSRendezvous(t *testing.T) {
	Convey("SQS Rendezvous", t, func() {

		Convey("Construct SQS queue rendezvous", func() {
			transport := &mockTransport{http.StatusOK, []byte{}}
			rend, err := newSQSRendezvous("https://sqs.us-east-1.amazonaws.com", "some-access-key-id", "some-secret-key", transport)

			So(err, ShouldBeNil)
			So(rend.sqsClientID, ShouldNotBeNil)
			So(rend.sqsClient, ShouldNotBeNil)
			So(rend.sqsURL, ShouldNotBeNil)
			So(rend.sqsURL.String(), ShouldResemble, "https://sqs.us-east-1.amazonaws.com")
		})

		ctrl := gomock.NewController(t)
		mockSqsClient := sqsclient.NewMockSQSClient(ctrl)
		responseQueueURL := "https://sqs.us-east-1.amazonaws.com/testing"
		sqsClientID := "test123"
		sqsUrl, _ := url.Parse("https://sqs.us-east-1.amazonaws.com/broker")
		fakeEncPollResp := makeEncPollResp(
			`{"answer": "{\"type\":\"answer\",\"sdp\":\"fake\"}" }`,
			"",
		)
		sqsRendezvous := sqsRendezvous{
			transport:   &mockTransport{http.StatusOK, []byte{}},
			sqsClientID: sqsClientID,
			sqsClient:   mockSqsClient,
			sqsURL:      sqsUrl,
			timeout:     0,
			numRetries:  5,
		}

		Convey("sqsRendezvous.Exchange responds with answer", func() {
			mockSqsClient.EXPECT().SendMessage(gomock.Any(), &sqs.SendMessageInput{
				MessageAttributes: map[string]types.MessageAttributeValue{
					"ClientID": {
						DataType:    aws.String("String"),
						StringValue: aws.String(sqsClientID),
					},
				},
				MessageBody: aws.String(string(fakeEncPollResp)),
				QueueUrl:    aws.String(sqsUrl.String()),
			})
			mockSqsClient.EXPECT().GetQueueUrl(gomock.Any(), &sqs.GetQueueUrlInput{
				QueueName: aws.String("snowflake-client-" + sqsClientID),
			}).Return(&sqs.GetQueueUrlOutput{
				QueueUrl: aws.String(responseQueueURL),
			}, nil)
			mockSqsClient.EXPECT().ReceiveMessage(gomock.Any(), gomock.Eq(&sqs.ReceiveMessageInput{
				QueueUrl:            &responseQueueURL,
				MaxNumberOfMessages: 1,
				WaitTimeSeconds:     20,
			})).Return(&sqs.ReceiveMessageOutput{
				Messages: []types.Message{{Body: aws.String("answer")}},
			}, nil)

			answer, err := sqsRendezvous.Exchange(fakeEncPollResp)

			So(answer, ShouldEqual, []byte("answer"))
			So(err, ShouldBeNil)
		})

		Convey("sqsRendezvous.Exchange cannot get queue url", func() {
			mockSqsClient.EXPECT().SendMessage(gomock.Any(), &sqs.SendMessageInput{
				MessageAttributes: map[string]types.MessageAttributeValue{
					"ClientID": {
						DataType:    aws.String("String"),
						StringValue: aws.String(sqsClientID),
					},
				},
				MessageBody: aws.String(string(fakeEncPollResp)),
				QueueUrl:    aws.String(sqsUrl.String()),
			})
			for i := 0; i < sqsRendezvous.numRetries; i++ {
				mockSqsClient.EXPECT().GetQueueUrl(gomock.Any(), &sqs.GetQueueUrlInput{
					QueueName: aws.String("snowflake-client-" + sqsClientID),
				}).Return(nil, errors.New("test error"))
			}

			answer, err := sqsRendezvous.Exchange(fakeEncPollResp)

			So(answer, ShouldBeNil)
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, errors.New("test error"))
		})

		Convey("sqsRendezvous.Exchange does not receive answer", func() {
			mockSqsClient.EXPECT().SendMessage(gomock.Any(), &sqs.SendMessageInput{
				MessageAttributes: map[string]types.MessageAttributeValue{
					"ClientID": {
						DataType:    aws.String("String"),
						StringValue: aws.String(sqsClientID),
					},
				},
				MessageBody: aws.String(string(fakeEncPollResp)),
				QueueUrl:    aws.String(sqsUrl.String()),
			})
			mockSqsClient.EXPECT().GetQueueUrl(gomock.Any(), &sqs.GetQueueUrlInput{
				QueueName: aws.String("snowflake-client-" + sqsClientID),
			}).Return(&sqs.GetQueueUrlOutput{
				QueueUrl: aws.String(responseQueueURL),
			}, nil)
			for i := 0; i < sqsRendezvous.numRetries; i++ {
				mockSqsClient.EXPECT().ReceiveMessage(gomock.Any(), gomock.Eq(&sqs.ReceiveMessageInput{
					QueueUrl:            &responseQueueURL,
					MaxNumberOfMessages: 1,
					WaitTimeSeconds:     20,
				})).Return(&sqs.ReceiveMessageOutput{
					Messages: []types.Message{},
				}, nil)
			}

			answer, err := sqsRendezvous.Exchange(fakeEncPollResp)

			So(answer, ShouldEqual, []byte{})
			So(err, ShouldBeNil)
		})
	})
}
