package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"tgragnato.it/snowflake/common/messages"
	"tgragnato.it/snowflake/common/sqsclient"
)

const (
	brokerSQSQueueName  = "example-name"
	sqsResponseQueueURL = "https://sqs.us-east-1.amazonaws.com/testing"
)

// fakeSQSClient is a test double for sqsclient.SQSClient. Embedding the
// interface satisfies GetQueueUrl, which the broker never calls; invoking it
// panics, which is what we want from an unexpected call. Each method records a
// call count that tests can read back with calls.
//
// Methods with no hook set return a zero-valued output and a nil error, so a
// test only has to stub what it actually exercises.
type fakeSQSClient struct {
	sqsclient.SQSClient

	createQueue        func(context.Context, *sqs.CreateQueueInput) (*sqs.CreateQueueOutput, error)
	deleteMessage      func(context.Context, *sqs.DeleteMessageInput) (*sqs.DeleteMessageOutput, error)
	deleteQueue        func(context.Context, *sqs.DeleteQueueInput) (*sqs.DeleteQueueOutput, error)
	getQueueAttributes func(context.Context, *sqs.GetQueueAttributesInput) (*sqs.GetQueueAttributesOutput, error)
	listQueues         func(context.Context, *sqs.ListQueuesInput) (*sqs.ListQueuesOutput, error)
	receiveMessage     func(context.Context, *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error)
	sendMessage        func(context.Context, *sqs.SendMessageInput) (*sqs.SendMessageOutput, error)

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

func (f *fakeSQSClient) CreateQueue(ctx context.Context, input *sqs.CreateQueueInput, _ ...func(*sqs.Options)) (*sqs.CreateQueueOutput, error) {
	f.record("CreateQueue")
	if f.createQueue == nil {
		return &sqs.CreateQueueOutput{}, nil
	}
	return f.createQueue(ctx, input)
}

func (f *fakeSQSClient) DeleteMessage(ctx context.Context, input *sqs.DeleteMessageInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error) {
	f.record("DeleteMessage")
	if f.deleteMessage == nil {
		return &sqs.DeleteMessageOutput{}, nil
	}
	return f.deleteMessage(ctx, input)
}

func (f *fakeSQSClient) DeleteQueue(ctx context.Context, input *sqs.DeleteQueueInput, _ ...func(*sqs.Options)) (*sqs.DeleteQueueOutput, error) {
	f.record("DeleteQueue")
	if f.deleteQueue == nil {
		return &sqs.DeleteQueueOutput{}, nil
	}
	return f.deleteQueue(ctx, input)
}

func (f *fakeSQSClient) GetQueueAttributes(ctx context.Context, input *sqs.GetQueueAttributesInput, _ ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	f.record("GetQueueAttributes")
	if f.getQueueAttributes == nil {
		return &sqs.GetQueueAttributesOutput{}, nil
	}
	return f.getQueueAttributes(ctx, input)
}

func (f *fakeSQSClient) ListQueues(ctx context.Context, input *sqs.ListQueuesInput, _ ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	f.record("ListQueues")
	if f.listQueues == nil {
		return &sqs.ListQueuesOutput{}, nil
	}
	return f.listQueues(ctx, input)
}

func (f *fakeSQSClient) ReceiveMessage(ctx context.Context, input *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	f.record("ReceiveMessage")
	if f.receiveMessage == nil {
		return &sqs.ReceiveMessageOutput{}, nil
	}
	return f.receiveMessage(ctx, input)
}

func (f *fakeSQSClient) SendMessage(ctx context.Context, input *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	f.record("SendMessage")
	if f.sendMessage == nil {
		return &sqs.SendMessageOutput{}, nil
	}
	return f.sendMessage(ctx, input)
}

// sqsFixture is the per-subtest state. Each subtest builds a fresh one so that
// broker metrics and the captured log output never leak between cases.
type sqsFixture struct {
	buf    *bytes.Buffer
	ipcCtx *BrokerContext
	ipc    *IPC
	client *fakeSQSClient
}

func newSQSFixture() *sqsFixture {
	buf := new(bytes.Buffer)
	ipcCtx := NewBrokerContext(log.New(buf, "", 0), "")
	return &sqsFixture{
		buf:    buf,
		ipcCtx: ipcCtx,
		ipc:    &IPC{ipcCtx},
		client: &fakeSQSClient{},
	}
}

// brokerQueueCreated is the CreateQueue hook covering the queue that
// newSQSHandler always creates for the broker itself.
func brokerQueueCreated(t *testing.T) func(context.Context, *sqs.CreateQueueInput) (*sqs.CreateQueueOutput, error) {
	t.Helper()
	return func(_ context.Context, input *sqs.CreateQueueInput) (*sqs.CreateQueueOutput, error) {
		if got, want := *input.QueueName, brokerSQSQueueName; got != want {
			t.Errorf("CreateQueue name = %q, want %q", got, want)
		}
		want := strconv.FormatInt(int64((5 * time.Minute).Seconds()), 10)
		if got := input.Attributes["MessageRetentionPeriod"]; got != want {
			t.Errorf("MessageRetentionPeriod = %q, want %q", got, want)
		}
		return &sqs.CreateQueueOutput{QueueUrl: aws.String(sqsResponseQueueURL)}, nil
	}
}

// startSQSHandler wires the fake into a handler and starts polling.
func (f *sqsFixture) startSQSHandler(t *testing.T, ctx context.Context) *sqsHandler {
	t.Helper()
	h, err := newSQSHandler(ctx, f.client, brokerSQSQueueName, f.ipc)
	if err != nil {
		t.Fatalf("newSQSHandler: %v", err)
	}
	go h.PollAndHandleMessages(ctx)
	return h
}

func expectedReceiveMessageInput() *sqs.ReceiveMessageInput {
	return &sqs.ReceiveMessageInput{
		QueueUrl:              aws.String(sqsResponseQueueURL),
		MaxNumberOfMessages:   10,
		WaitTimeSeconds:       15,
		MessageAttributeNames: []string{string(types.QueueAttributeNameAll)},
	}
}

func checkReceiveMessageInput(t *testing.T, got *sqs.ReceiveMessageInput) {
	t.Helper()
	want := expectedReceiveMessageInput()
	if *got.QueueUrl != *want.QueueUrl ||
		got.MaxNumberOfMessages != want.MaxNumberOfMessages ||
		got.WaitTimeSeconds != want.WaitTimeSeconds ||
		len(got.MessageAttributeNames) != 1 ||
		got.MessageAttributeNames[0] != want.MessageAttributeNames[0] {
		t.Errorf("ReceiveMessage input = %+v, want %+v", got, want)
	}
}

// encodedClientOffer is the body of the SQS message a client would send.
func encodedClientOffer(t *testing.T) *string {
	t.Helper()
	encOffer, err := (&messages.ClientPollRequest{Offer: rawOffer, NAT: "unknown"}).EncodeClientPollRequest()
	if err != nil {
		t.Fatalf("EncodeClientPollRequest: %v", err)
	}
	return aws.String(string(encOffer))
}

func TestSQSHandlerIgnoresOfferWithoutClientID(t *testing.T) {
	t.Parallel()

	f := newSQSFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	messageBody := encodedClientOffer(t)
	receiptHandle := "fake-receipt-handle"

	f.client.createQueue = brokerQueueCreated(t)
	f.client.receiveMessage = func(_ context.Context, input *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error) {
		checkReceiveMessageInput(t, input)
		return &sqs.ReceiveMessageOutput{
			Messages: []types.Message{{Body: messageBody, ReceiptHandle: &receiptHandle}},
		}, nil
	}
	f.client.deleteMessage = func(_ context.Context, input *sqs.DeleteMessageInput) (*sqs.DeleteMessageOutput, error) {
		if *input.QueueUrl != sqsResponseQueueURL || *input.ReceiptHandle != receiptHandle {
			t.Errorf("DeleteMessage input = %+v", input)
		}
		cancel()
		return &sqs.DeleteMessageOutput{}, nil
	}

	f.startSQSHandler(t, ctx)
	<-ctx.Done()

	// The only queue created must be the broker's own: a message without a
	// ClientID must not cause an answer queue to be provisioned.
	if got := f.client.calls("CreateQueue"); got != 1 {
		t.Errorf("CreateQueue calls = %d, want 1 (broker queue only)", got)
	}
}

func TestSQSHandlerIgnoresReceiveError(t *testing.T) {
	t.Parallel()

	f := newSQSFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f.client.createQueue = brokerQueueCreated(t)
	f.client.receiveMessage = func(_ context.Context, input *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error) {
		checkReceiveMessageInput(t, input)
		cancel()
		return nil, errors.New("error")
	}

	f.startSQSHandler(t, ctx)
	<-ctx.Done()

	if got := f.client.calls("CreateQueue"); got != 1 {
		t.Errorf("CreateQueue calls = %d, want 1 (broker queue only)", got)
	}
	if got := f.client.calls("DeleteMessage"); got != 0 {
		t.Errorf("DeleteMessage calls = %d, want 0", got)
	}
}

// validClientMessage carries a ClientID, so the handler will try to create an
// answer queue for it.
func validClientMessage(t *testing.T, clientID, receiptHandle string) *sqs.ReceiveMessageOutput {
	t.Helper()
	return &sqs.ReceiveMessageOutput{
		Messages: []types.Message{{
			Body:              encodedClientOffer(t),
			MessageAttributes: map[string]types.MessageAttributeValue{"ClientID": {StringValue: &clientID}},
			ReceiptHandle:     &receiptHandle,
		}},
	}
}

func TestSQSHandlerSkipsSendWhenQueueCreationFails(t *testing.T) {
	t.Parallel()

	f := newSQSFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const clientID = "fake-id"
	brokerQueue := brokerQueueCreated(t)
	f.client.createQueue = func(ctx context.Context, input *sqs.CreateQueueInput) (*sqs.CreateQueueOutput, error) {
		if *input.QueueName == "snowflake-client-"+clientID {
			return nil, errors.New("error")
		}
		return brokerQueue(ctx, input)
	}
	f.client.receiveMessage = func(_ context.Context, input *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error) {
		checkReceiveMessageInput(t, input)
		cancel()
		return validClientMessage(t, clientID, "fake-receipt-handle"), nil
	}

	f.startSQSHandler(t, ctx)
	<-ctx.Done()

	// Give the message-handling goroutine a chance to reach a SendMessage it
	// should never make.
	time.Sleep(100 * time.Millisecond)
	if got := f.client.calls("SendMessage"); got != 0 {
		t.Errorf("SendMessage calls = %d, want 0 when answer queue creation fails", got)
	}
}

func TestSQSHandlerRespondsWithProxyAnswer(t *testing.T) {
	t.Parallel()

	f := newSQSFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const clientID = "fake-id"
	brokerQueue := brokerQueueCreated(t)
	f.client.createQueue = func(ctx context.Context, input *sqs.CreateQueueInput) (*sqs.CreateQueueOutput, error) {
		if *input.QueueName == "snowflake-client-"+clientID {
			return &sqs.CreateQueueOutput{QueueUrl: aws.String(sqsResponseQueueURL)}, nil
		}
		return brokerQueue(ctx, input)
	}

	// Deliver the offer exactly once, then keep failing so the poll loop spins
	// without producing more work.
	var numTimes atomic.Uint32
	f.client.receiveMessage = func(_ context.Context, input *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error) {
		checkReceiveMessageInput(t, input)
		if numTimes.Add(1) != 1 {
			return nil, errors.New("error")
		}
		snowflake := NewSnowflake("fake", "", NATUnrestricted, 0)
		f.ipcCtx.GetPool(&ProxyPoll{natType: NATUnrestricted}).Push(snowflake)
		go func() {
			<-snowflake.offerChannel
			snowflake.answerChannel <- "fake answer"
		}()
		return validClientMessage(t, clientID, "fake-receipt-handle"), nil
	}

	f.client.sendMessage = func(_ context.Context, input *sqs.SendMessageInput) (*sqs.SendMessageOutput, error) {
		if got, want := *input.MessageBody, `{"answer":"fake answer"}`; got != want {
			t.Errorf("MessageBody = %q, want %q", got, want)
		}
		// Ensure that the match is correctly recorded in metrics.
		f.ipcCtx.metrics.printMetrics()
		const wantMetrics = `client-denied-count 0
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
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 8
client-sqs-ips ??=8
`
		if !strings.Contains(f.buf.String(), wantMetrics) {
			t.Errorf("metrics output does not contain expected block; got:\n%s", f.buf.String())
		}
		cancel()
		return &sqs.SendMessageOutput{}, nil
	}

	f.startSQSHandler(t, ctx)
	<-ctx.Done()

	if got := f.client.calls("SendMessage"); got != 1 {
		t.Errorf("SendMessage calls = %d, want 1", got)
	}
}

// startCleanupSQSHandler starts a handler whose cleanup loop fires immediately.
func (f *sqsFixture) startCleanupSQSHandler(t *testing.T, ctx context.Context) {
	t.Helper()
	f.client.createQueue = brokerQueueCreated(t)
	if f.client.receiveMessage == nil {
		f.client.receiveMessage = func(context.Context, *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error) {
			return &sqs.ReceiveMessageOutput{Messages: []types.Message{}}, nil
		}
	}
	h, err := newSQSHandler(ctx, f.client, brokerSQSQueueName, f.ipc)
	if err != nil {
		t.Fatalf("newSQSHandler: %v", err)
	}
	// Set the cleanup interval to 1 ns so we can immediately test the cleanup logic.
	h.cleanupInterval = time.Nanosecond
	go h.PollAndHandleMessages(ctx)
}

func checkListQueuesInput(t *testing.T, got *sqs.ListQueuesInput) {
	t.Helper()
	if *got.QueueNamePrefix != "snowflake-client-" || *got.MaxResults != 1000 || got.NextToken != nil {
		t.Errorf("ListQueues input = %+v", got)
	}
}

func TestSQSCleanupWithNoOpenQueues(t *testing.T) {
	t.Parallel()

	f := newSQSFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	f.client.listQueues = func(_ context.Context, input *sqs.ListQueuesInput) (*sqs.ListQueuesOutput, error) {
		checkListQueuesInput(t, input)
		wg.Done()
		// Cancel the handler context since we are only interested in testing
		// one iteration of the cleanup.
		cancel()
		return &sqs.ListQueuesOutput{QueueUrls: []string{}}, nil
	}

	f.startCleanupSQSHandler(t, ctx)
	wg.Wait()

	if got := f.client.calls("DeleteQueue"); got != 0 {
		t.Errorf("DeleteQueue calls = %d, want 0", got)
	}
}

func TestSQSCleanupDeletesStaleQueues(t *testing.T) {
	t.Parallel()

	f := newSQSFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientQueueUrl1 := "https://sqs.us-east-1.amazonaws.com/snowflake-client-1"
	clientQueueUrl2 := "https://sqs.us-east-1.amazonaws.com/snowflake-client-2"

	var wg sync.WaitGroup
	wg.Add(1)
	var listCalls atomic.Uint32
	f.client.listQueues = func(_ context.Context, input *sqs.ListQueuesInput) (*sqs.ListQueuesOutput, error) {
		checkListQueuesInput(t, input)
		if listCalls.Add(1) == 1 {
			return &sqs.ListQueuesOutput{QueueUrls: []string{clientQueueUrl1, clientQueueUrl2}}, nil
		}
		// Executed on the second iteration of the cleanupClientQueues loop.
		// One full iteration has completed, so we can verify its results.
		wg.Done()
		cancel()
		return &sqs.ListQueuesOutput{QueueUrls: []string{}}, nil
	}

	// A zero timestamp is far enough in the past to be past the cleanup cutoff.
	f.client.getQueueAttributes = func(_ context.Context, input *sqs.GetQueueAttributesInput) (*sqs.GetQueueAttributesOutput, error) {
		if len(input.AttributeNames) != 1 || input.AttributeNames[0] != types.QueueAttributeNameLastModifiedTimestamp {
			t.Errorf("GetQueueAttributes AttributeNames = %v", input.AttributeNames)
		}
		return &sqs.GetQueueAttributesOutput{
			Attributes: map[string]string{
				string(types.QueueAttributeNameLastModifiedTimestamp): "0",
			},
		}, nil
	}

	var mu sync.Mutex
	var deleted []string
	f.client.deleteQueue = func(_ context.Context, input *sqs.DeleteQueueInput) (*sqs.DeleteQueueOutput, error) {
		mu.Lock()
		deleted = append(deleted, *input.QueueUrl)
		mu.Unlock()
		return &sqs.DeleteQueueOutput{}, nil
	}

	f.startCleanupSQSHandler(t, ctx)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	want := []string{clientQueueUrl1, clientQueueUrl2}
	if len(deleted) != len(want) {
		t.Fatalf("deleted queues = %v, want %v", deleted, want)
	}
	for i := range want {
		if deleted[i] != want[i] {
			t.Errorf("deleted[%d] = %q, want %q", i, deleted[i], want[i])
		}
	}
}
