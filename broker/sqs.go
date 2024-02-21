package main

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/messages"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/sqsclient"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/util"
)

const (
	cleanupThreshold = -2 * time.Minute
)

type sqsHandler struct {
	SQSClient       sqsclient.SQSClient
	SQSQueueURL     *string
	IPC             *IPC
	cleanupInterval time.Duration
}

func (r *sqsHandler) pollMessages(ctx context.Context, chn chan<- *types.Message) {
	for {
		select {
		case <-ctx.Done():
			// if context is cancelled
			return
		default:
			res, err := r.SQSClient.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
				QueueUrl:            r.SQSQueueURL,
				MaxNumberOfMessages: 10,
				WaitTimeSeconds:     15,
				MessageAttributeNames: []string{
					string(types.QueueAttributeNameAll),
				},
			})

			if err != nil {
				log.Printf("SQSHandler: encountered error while polling for messages: %v\n", err)
				continue
			}

			for _, message := range res.Messages {
				chn <- &message
			}
		}
	}
}

func (r *sqsHandler) cleanupClientQueues(ctx context.Context) {
	for range time.NewTicker(r.cleanupInterval).C {
		// Runs at fixed intervals to clean up any client queues that were last changed more than 2 minutes ago
		select {
		case <-ctx.Done():
			// if context is cancelled
			return
		default:
			queueURLsList := []string{}
			var nextToken *string
			for {
				res, err := r.SQSClient.ListQueues(ctx, &sqs.ListQueuesInput{
					QueueNamePrefix: aws.String("snowflake-client-"),
					MaxResults:      aws.Int32(1000),
					NextToken:       nextToken,
				})
				if err != nil {
					log.Printf("SQSHandler: encountered error while retrieving client queues to clean up: %v\n", err)
					// client queues will be cleaned up the next time the cleanup operation is triggered automatically
					break
				}
				queueURLsList = append(queueURLsList, res.QueueUrls...)
				if res.NextToken == nil {
					break
				} else {
					nextToken = res.NextToken
				}
			}

			numDeleted := 0
			cleanupCutoff := time.Now().Add(cleanupThreshold)
			for _, queueURL := range queueURLsList {
				if !strings.Contains(queueURL, "snowflake-client-") {
					continue
				}
				res, err := r.SQSClient.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
					QueueUrl:       aws.String(queueURL),
					AttributeNames: []types.QueueAttributeName{types.QueueAttributeNameLastModifiedTimestamp},
				})
				if err != nil {
					// According to the AWS SQS docs, the deletion process for a queue can take up to 60 seconds. So the queue
					// can be in the process of being deleted, but will still be returned by the ListQueues operation, but
					// fail when we try to GetQueueAttributes for the queue
					log.Printf("SQSHandler: encountered error while getting attribute of client queue %s. queue may already be deleted.\n", queueURL)
					continue
				}
				lastModifiedInt64, err := strconv.ParseInt(res.Attributes[string(types.QueueAttributeNameLastModifiedTimestamp)], 10, 64)
				if err != nil {
					log.Printf("SQSHandler: encountered invalid lastModifiedTimetamp value from client queue %s: %v\n", queueURL, err)
					continue
				}
				lastModified := time.Unix(lastModifiedInt64, 0)
				if lastModified.Before(cleanupCutoff) {
					_, err := r.SQSClient.DeleteQueue(ctx, &sqs.DeleteQueueInput{
						QueueUrl: aws.String(queueURL),
					})
					if err != nil {
						log.Printf("SQSHandler: encountered error when deleting client queue %s: %v\n", queueURL, err)
						continue
					} else {
						numDeleted += 1
					}

				}
			}
			log.Printf("SQSHandler: finished running iteration of client queue cleanup. found and deleted %d client queues.\n", numDeleted)
		}
	}
}

func (r *sqsHandler) handleMessage(context context.Context, message *types.Message) {
	var encPollReq []byte
	var response []byte
	var err error

	clientID := message.MessageAttributes["ClientID"].StringValue
	if clientID == nil {
		log.Println("SQSHandler: got SDP offer in SQS message with no client ID. ignoring this message.")
		return
	}

	res, err := r.SQSClient.CreateQueue(context, &sqs.CreateQueueInput{
		QueueName: aws.String("snowflake-client-" + *clientID),
	})
	if err != nil {
		log.Printf("SQSHandler: error encountered when creating answer queue for client %s: %v\n", *clientID, err)
		return
	}
	answerSQSURL := res.QueueUrl

	encPollReq = []byte(*message.Body)

	// Get best guess Client IP for geolocating
	remoteAddr := ""
	req, err := messages.DecodeClientPollRequest(encPollReq)
	if err != nil {
		log.Printf("SQSHandler: error encounted when decoding client poll request %s: %v\n", *clientID, err)
	} else {
		sdp, err := util.DeserializeSessionDescription(req.Offer)
		if err != nil {
			log.Printf("SQSHandler: error encounted when deserializing session desc %s: %v\n", *clientID, err)
		} else {
			candidateAddrs := util.GetCandidateAddrs(sdp.SDP)
			if len(candidateAddrs) > 0 {
				remoteAddr = candidateAddrs[0].String()
			}
		}
	}

	arg := messages.Arg{
		Body:             encPollReq,
		RemoteAddr:       remoteAddr,
		RendezvousMethod: messages.RendezvousSqs,
	}
	err = r.IPC.ClientOffers(arg, &response)

	if err != nil {
		log.Printf("SQSHandler: error encountered when handling message: %v\n", err)
		return
	}

	r.SQSClient.SendMessage(context, &sqs.SendMessageInput{
		QueueUrl:    answerSQSURL,
		MessageBody: aws.String(string(response)),
	})
}

func (r *sqsHandler) deleteMessage(context context.Context, message *types.Message) {
	r.SQSClient.DeleteMessage(context, &sqs.DeleteMessageInput{
		QueueUrl:      r.SQSQueueURL,
		ReceiptHandle: message.ReceiptHandle,
	})
}

func newSQSHandler(context context.Context, client sqsclient.SQSClient, sqsQueueName string, region string, i *IPC) (*sqsHandler, error) {
	// Creates the queue if a queue with the same name doesn't exist. If a queue with the same name and attributes
	// already exists, then nothing will happen. If a queue with the same name, but different attributes exists, then
	// an error will be returned
	res, err := client.CreateQueue(context, &sqs.CreateQueueInput{
		QueueName: aws.String(sqsQueueName),
		Attributes: map[string]string{
			"MessageRetentionPeriod": strconv.FormatInt(int64((5 * time.Minute).Seconds()), 10),
		},
	})

	if err != nil {
		return nil, err
	}

	return &sqsHandler{
		SQSClient:       client,
		SQSQueueURL:     res.QueueUrl,
		IPC:             i,
		cleanupInterval: time.Second * 30,
	}, nil
}

func (r *sqsHandler) PollAndHandleMessages(ctx context.Context) {
	log.Println("SQSHandler: Starting to poll for messages at: " + *r.SQSQueueURL)
	messagesChn := make(chan *types.Message, 2)
	go r.pollMessages(ctx, messagesChn)
	go r.cleanupClientQueues(ctx)

	for message := range messagesChn {
		select {
		case <-ctx.Done():
			// if context is cancelled
			return
		default:
			r.handleMessage(ctx, message)
			r.deleteMessage(ctx, message)
		}
	}
}
