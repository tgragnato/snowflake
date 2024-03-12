package snowflake_client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/sqsclient"
	sqscreds "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/sqscreds/lib"
)

type sqsRendezvous struct {
	transport  http.RoundTripper
	sqsClient  sqsclient.SQSClient
	sqsURL     *url.URL
	timeout    time.Duration
	numRetries int
}

func newSQSRendezvous(sqsQueue string, sqsCredsStr string, transport http.RoundTripper) (*sqsRendezvous, error) {
	sqsURL, err := url.Parse(sqsQueue)
	if err != nil {
		return nil, err
	}

	sqsCreds, err := sqscreds.AwsCredsFromBase64(sqsCredsStr)
	if err != nil {
		return nil, err
	}

	queueURL := sqsURL.String()
	hostName := sqsURL.Hostname()

	regionRegex, _ := regexp.Compile(`^sqs\.([\w-]+)\.amazonaws\.com$`)
	res := regionRegex.FindStringSubmatch(hostName)
	if len(res) < 2 {
		log.Fatal("Could not extract AWS region from SQS URL. Ensure that the SQS Queue URL provided is valid.")
	}
	region := res[1]
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(sqsCreds.AwsAccessKeyId, sqsCreds.AwsSecretKey, ""),
		),
		config.WithRegion(region),
	)
	if err != nil {
		log.Fatal(err)
	}
	client := sqs.NewFromConfig(cfg)

	log.Println("Queue URL: ", queueURL)

	return &sqsRendezvous{
		transport:  transport,
		sqsClient:  client,
		sqsURL:     sqsURL,
		timeout:    time.Second,
		numRetries: 5,
	}, nil
}

func (r *sqsRendezvous) Exchange(encPollReq []byte) ([]byte, error) {
	log.Println("Negotiating via SQS Queue rendezvous...")

	var id [8]byte
	_, err := rand.Read(id[:])
	if err != nil {
		return nil, err
	}
	sqsClientID := hex.EncodeToString(id[:])
	log.Println("SQS Client ID for rendezvous: " + sqsClientID)

	_, err = r.sqsClient.SendMessage(context.TODO(), &sqs.SendMessageInput{
		MessageAttributes: map[string]types.MessageAttributeValue{
			"ClientID": {
				DataType:    aws.String("String"),
				StringValue: aws.String(sqsClientID),
			},
		},
		MessageBody: aws.String(string(encPollReq)),
		QueueUrl:    aws.String(r.sqsURL.String()),
	})
	if err != nil {
		return nil, err
	}

	time.Sleep(r.timeout) // wait for client queue to be created by the broker

	var responseQueueURL *string
	for i := 0; i < r.numRetries; i++ {
		// The SQS queue corresponding to the client where the SDP Answer will be placed
		// may not be created yet. We will retry up to 5 times before we error out.
		var res *sqs.GetQueueUrlOutput
		res, err = r.sqsClient.GetQueueUrl(context.TODO(), &sqs.GetQueueUrlInput{
			QueueName: aws.String("snowflake-client-" + sqsClientID),
		})
		if err != nil {
			log.Println(err)
			log.Printf("Attempt %d of %d to retrieve URL of response SQS queue failed.\n", i+1, r.numRetries)
			time.Sleep(r.timeout)
		} else {
			responseQueueURL = res.QueueUrl
			break
		}
	}
	if err != nil {
		return nil, err
	}

	var answer string
	for i := 0; i < r.numRetries; i++ {
		// Waiting for SDP Answer from proxy to be placed in SQS queue.
		// We will retry upt to 5 times before we error out.
		res, err := r.sqsClient.ReceiveMessage(context.TODO(), &sqs.ReceiveMessageInput{
			QueueUrl:            responseQueueURL,
			MaxNumberOfMessages: 1,
			WaitTimeSeconds:     20,
		})
		if err != nil {
			return nil, err
		}
		if len(res.Messages) == 0 {
			log.Printf("Attempt %d of %d to receive message from response SQS queue failed. No message found in queue.\n", i+1, r.numRetries)
			delay := float64(i)/2.0 + 1
			time.Sleep(time.Duration(delay*1000) * (r.timeout / 1000))
		} else {
			answer = *res.Messages[0].Body
			break
		}
	}

	return []byte(answer), nil
}
