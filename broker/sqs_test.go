package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/sqsclient"
)

func TestSQS(t *testing.T) {

	Convey("Context", t, func() {
		buf := new(bytes.Buffer)
		ipcCtx := NewBrokerContext(log.New(buf, "", 0), "", "")
		i := &IPC{ipcCtx}

		var logBuffer bytes.Buffer
		log.SetOutput(&logBuffer)

		Convey("Responds to SQS client offers...", func() {
			ctrl := gomock.NewController(t)
			mockSQSClient := sqsclient.NewMockSQSClient(ctrl)

			brokerSQSQueueName := "example-name"
			responseQueueURL := aws.String("https://sqs.us-east-1.amazonaws.com/testing")

			runSQSHandler := func(sqsHandlerContext context.Context) {
				mockSQSClient.EXPECT().CreateQueue(sqsHandlerContext, &sqs.CreateQueueInput{
					QueueName: aws.String(brokerSQSQueueName),
					Attributes: map[string]string{
						"MessageRetentionPeriod": strconv.FormatInt(int64((5 * time.Minute).Seconds()), 10),
					},
				}).Return(&sqs.CreateQueueOutput{
					QueueUrl: responseQueueURL,
				}, nil).Times(1)
				sqsHandler, err := newSQSHandler(sqsHandlerContext, mockSQSClient, brokerSQSQueueName, "example-region", i)
				So(err, ShouldBeNil)
				go sqsHandler.PollAndHandleMessages(sqsHandlerContext)
			}

			messageBody := aws.String("1.0\n{\"offer\": \"fake\", \"nat\": \"unknown\"}")
			receiptHandle := "fake-receipt-handle"
			sqsReceiveMessageInput := sqs.ReceiveMessageInput{
				QueueUrl:            responseQueueURL,
				MaxNumberOfMessages: 10,
				WaitTimeSeconds:     15,
				MessageAttributeNames: []string{
					string(types.QueueAttributeNameAll),
				},
			}
			sqsDeleteMessageInput := sqs.DeleteMessageInput{
				QueueUrl:      responseQueueURL,
				ReceiptHandle: &receiptHandle,
			}

			Convey("by ignoring it if no client id specified", func(c C) {
				var wg sync.WaitGroup
				wg.Add(1)

				sqsHandlerContext, sqsCancelFunc := context.WithCancel(context.Background())
				defer sqsCancelFunc()
				defer wg.Wait()
				mockSQSClient.EXPECT().ReceiveMessage(sqsHandlerContext, &sqsReceiveMessageInput).MinTimes(1).DoAndReturn(
					func(ctx context.Context, input *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
						return &sqs.ReceiveMessageOutput{
							Messages: []types.Message{
								{
									Body:          messageBody,
									ReceiptHandle: &receiptHandle,
								},
							},
						}, nil
					},
				)
				mockSQSClient.EXPECT().DeleteMessage(sqsHandlerContext, &sqsDeleteMessageInput).Times(1).Do(
					func(ctx context.Context, input *sqs.DeleteMessageInput, optFns ...func(*sqs.Options)) {
						defer wg.Done()
						c.So(logBuffer.String(), ShouldContainSubstring, "SQSHandler: got SDP offer in SQS message with no client ID. ignoring this message.")
						mockSQSClient.EXPECT().DeleteMessage(sqsHandlerContext, &sqsDeleteMessageInput).AnyTimes()
					},
				)
				runSQSHandler(sqsHandlerContext)
			})

			Convey("by doing nothing if an error occurs upon receipt of the message", func(c C) {
				var wg sync.WaitGroup
				wg.Add(2)

				sqsHandlerContext, sqsCancelFunc := context.WithCancel(context.Background())
				defer sqsCancelFunc()
				defer wg.Wait()

				numTimes := 0
				// When ReceiveMessage is called for the first time, the error has not had a chance to be logged yet.
				// Therefore, we opt to wait for the second call because we are guaranteed that the error was logged
				// by then.
				mockSQSClient.EXPECT().ReceiveMessage(sqsHandlerContext, &sqsReceiveMessageInput).MinTimes(2).DoAndReturn(
					func(ctx context.Context, input *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
						numTimes += 1
						if numTimes <= 2 {
							wg.Done()
							if numTimes == 2 {
								c.So(logBuffer.String(), ShouldContainSubstring, "SQSHandler: encountered error while polling for messages: error")
							}
						}
						return nil, errors.New("error")
					},
				)
				runSQSHandler(sqsHandlerContext)
			})

			Convey("by attempting to create a new sqs queue...", func() {
				clientId := "fake-id"
				sqsCreateQueueInput := sqs.CreateQueueInput{
					QueueName: aws.String("snowflake-client-fake-id"),
				}

				expectReceiveMessageReturnsValidMessage := func(sqsHandlerContext context.Context) {
					mockSQSClient.EXPECT().ReceiveMessage(sqsHandlerContext, &sqsReceiveMessageInput).AnyTimes().DoAndReturn(
						func(ctx context.Context, input *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
							return &sqs.ReceiveMessageOutput{
								Messages: []types.Message{
									{
										Body: messageBody,
										MessageAttributes: map[string]types.MessageAttributeValue{
											"ClientID": {StringValue: &clientId},
										},
										ReceiptHandle: &receiptHandle,
									},
								},
							}, nil
						},
					)
				}

				Convey("and does not attempt to send a message via SQS if queue creation fails.", func(c C) {
					var wg sync.WaitGroup
					wg.Add(2)

					sqsHandlerContext, sqsCancelFunc := context.WithCancel(context.Background())
					defer sqsCancelFunc()
					defer wg.Wait()

					expectReceiveMessageReturnsValidMessage(sqsHandlerContext)
					mockSQSClient.EXPECT().CreateQueue(sqsHandlerContext, &sqsCreateQueueInput).Return(nil, errors.New("error")).AnyTimes()
					numTimes := 0
					mockSQSClient.EXPECT().DeleteMessage(sqsHandlerContext, &sqsDeleteMessageInput).MinTimes(2).Do(
						func(ctx context.Context, input *sqs.DeleteMessageInput, optFns ...func(*sqs.Options)) {
							numTimes += 1
							if numTimes <= 2 {
								wg.Done()
								if numTimes == 2 {
									c.So(logBuffer.String(), ShouldContainSubstring, "SQSHandler: error encountered when creating answer queue for client fake-id: error")
								}
							}
						},
					)
					runSQSHandler(sqsHandlerContext)
				})

				Convey("and responds with a proxy answer if available.", func(c C) {
					var wg sync.WaitGroup
					wg.Add(1)

					sqsHandlerContext, sqsCancelFunc := context.WithCancel(context.Background())
					defer sqsCancelFunc()
					defer wg.Wait()

					expectReceiveMessageReturnsValidMessage(sqsHandlerContext)
					mockSQSClient.EXPECT().CreateQueue(sqsHandlerContext, &sqsCreateQueueInput).Return(&sqs.CreateQueueOutput{
						QueueUrl: responseQueueURL,
					}, nil).AnyTimes()
					mockSQSClient.EXPECT().DeleteMessage(sqsHandlerContext, &sqsDeleteMessageInput).AnyTimes()
					numTimes := 0
					mockSQSClient.EXPECT().SendMessage(sqsHandlerContext, gomock.Any()).MinTimes(1).DoAndReturn(
						func(ctx context.Context, input *sqs.SendMessageInput, optFns ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
							numTimes += 1
							if numTimes == 1 {
								c.So(input.MessageBody, ShouldEqual, aws.String("{\"answer\":\"fake answer\"}"))
								// Ensure that match is correctly recorded in metrics
								ipcCtx.metrics.printMetrics()
								c.So(buf.String(), ShouldContainSubstring, `client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-snowflake-match-count 8
client-http-count 0
client-http-ips 
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 8
client-sqs-ips ??=8
`)
								wg.Done()
							}
							return &sqs.SendMessageOutput{}, nil
						},
					)
					runSQSHandler(sqsHandlerContext)

					snowflake := ipcCtx.AddSnowflake("fake", "", NATUnrestricted, 0)

					offer := <-snowflake.offerChannel
					So(offer.sdp, ShouldResemble, []byte("fake"))

					snowflake.answerChannel <- "fake answer"
				})
			})
		})

		Convey("Cleans up SQS client queues...", func() {
			brokerSQSQueueName := "example-name"
			responseQueueURL := aws.String("https://sqs.us-east-1.amazonaws.com/testing")

			ctrl := gomock.NewController(t)
			mockSQSClient := sqsclient.NewMockSQSClient(ctrl)

			runSQSHandler := func(sqsHandlerContext context.Context) {

				mockSQSClient.EXPECT().CreateQueue(sqsHandlerContext, &sqs.CreateQueueInput{
					QueueName: aws.String(brokerSQSQueueName),
					Attributes: map[string]string{
						"MessageRetentionPeriod": strconv.FormatInt(int64((5 * time.Minute).Seconds()), 10),
					},
				}).Return(&sqs.CreateQueueOutput{
					QueueUrl: responseQueueURL,
				}, nil).Times(1)

				mockSQSClient.EXPECT().ReceiveMessage(sqsHandlerContext, gomock.Any()).AnyTimes().Return(
					&sqs.ReceiveMessageOutput{
						Messages: []types.Message{},
					}, nil,
				)

				sqsHandler, err := newSQSHandler(sqsHandlerContext, mockSQSClient, brokerSQSQueueName, "example-region", i)
				So(err, ShouldBeNil)
				// Set the cleanup interval to 1 ns so we can immediately test the cleanup logic
				sqsHandler.cleanupInterval = time.Nanosecond

				go sqsHandler.PollAndHandleMessages(sqsHandlerContext)
			}

			Convey("does nothing if there are no open queues.", func() {
				var wg sync.WaitGroup
				wg.Add(1)
				sqsHandlerContext, sqsCancelFunc := context.WithCancel(context.Background())
				defer wg.Wait()

				mockSQSClient.EXPECT().ListQueues(sqsHandlerContext, &sqs.ListQueuesInput{
					QueueNamePrefix: aws.String("snowflake-client-"),
					MaxResults:      aws.Int32(1000),
					NextToken:       nil,
				}).DoAndReturn(func(ctx context.Context, input *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
					wg.Done()
					// Cancel the handler context since we are only interested in testing one iteration of the cleanup
					sqsCancelFunc()
					return &sqs.ListQueuesOutput{
						QueueUrls: []string{},
					}, nil
				})

				runSQSHandler(sqsHandlerContext)
			})

			Convey("deletes open queue when there is one open queue.", func(c C) {
				var wg sync.WaitGroup
				wg.Add(1)
				sqsHandlerContext, sqsCancelFunc := context.WithCancel(context.Background())

				clientQueueUrl1 := "https://sqs.us-east-1.amazonaws.com/snowflake-client-1"
				clientQueueUrl2 := "https://sqs.us-east-1.amazonaws.com/snowflake-client-2"

				gomock.InOrder(
					mockSQSClient.EXPECT().ListQueues(sqsHandlerContext, &sqs.ListQueuesInput{
						QueueNamePrefix: aws.String("snowflake-client-"),
						MaxResults:      aws.Int32(1000),
						NextToken:       nil,
					}).Times(1).Return(&sqs.ListQueuesOutput{
						QueueUrls: []string{
							clientQueueUrl1,
							clientQueueUrl2,
						},
					}, nil),
					mockSQSClient.EXPECT().ListQueues(sqsHandlerContext, &sqs.ListQueuesInput{
						QueueNamePrefix: aws.String("snowflake-client-"),
						MaxResults:      aws.Int32(1000),
						NextToken:       nil,
					}).Times(1).DoAndReturn(func(ctx context.Context, input *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
						// Executed on second iteration of cleanupClientQueues loop. This means that one full iteration has completed and we can verify the results of that iteration
						wg.Done()
						sqsCancelFunc()
						c.So(logBuffer.String(), ShouldContainSubstring, "SQSHandler: finished running iteration of client queue cleanup. found and deleted 2 client queues.")
						return &sqs.ListQueuesOutput{
							QueueUrls: []string{},
						}, nil
					}),
				)

				gomock.InOrder(
					mockSQSClient.EXPECT().GetQueueAttributes(sqsHandlerContext, &sqs.GetQueueAttributesInput{
						QueueUrl:       aws.String(clientQueueUrl1),
						AttributeNames: []types.QueueAttributeName{types.QueueAttributeNameLastModifiedTimestamp},
					}).Times(1).Return(&sqs.GetQueueAttributesOutput{
						Attributes: map[string]string{
							string(types.QueueAttributeNameLastModifiedTimestamp): "0",
						}}, nil),

					mockSQSClient.EXPECT().GetQueueAttributes(sqsHandlerContext, &sqs.GetQueueAttributesInput{
						QueueUrl:       aws.String(clientQueueUrl2),
						AttributeNames: []types.QueueAttributeName{types.QueueAttributeNameLastModifiedTimestamp},
					}).Times(1).Return(&sqs.GetQueueAttributesOutput{
						Attributes: map[string]string{
							string(types.QueueAttributeNameLastModifiedTimestamp): "0",
						}}, nil),
				)

				gomock.InOrder(
					mockSQSClient.EXPECT().DeleteQueue(sqsHandlerContext, &sqs.DeleteQueueInput{
						QueueUrl: aws.String(clientQueueUrl1),
					}).Return(&sqs.DeleteQueueOutput{}, nil),
					mockSQSClient.EXPECT().DeleteQueue(sqsHandlerContext, &sqs.DeleteQueueInput{
						QueueUrl: aws.String(clientQueueUrl2),
					}).Return(&sqs.DeleteQueueOutput{}, nil),
				)

				runSQSHandler(sqsHandlerContext)
				wg.Wait()
			})
		})
	})
}
