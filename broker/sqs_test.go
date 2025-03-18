package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
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
		ipcCtx := NewBrokerContext(log.New(buf, "", 0), "")
		i := &IPC{ipcCtx}

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
				sqsHandlerContext, sqsCancelFunc := context.WithCancel(context.Background())
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
				mockSQSClient.EXPECT().DeleteMessage(sqsHandlerContext, &sqsDeleteMessageInput).MinTimes(1).Do(
					func(ctx context.Context, input *sqs.DeleteMessageInput, optFns ...func(*sqs.Options)) {
						sqsCancelFunc()
					},
				)
				// We expect no queues to be created
				mockSQSClient.EXPECT().CreateQueue(gomock.Any(), gomock.Any()).Times(0)
				runSQSHandler(sqsHandlerContext)
				<-sqsHandlerContext.Done()
			})

			Convey("by doing nothing if an error occurs upon receipt of the message", func(c C) {

				sqsHandlerContext, sqsCancelFunc := context.WithCancel(context.Background())

				mockSQSClient.EXPECT().ReceiveMessage(sqsHandlerContext, &sqsReceiveMessageInput).MinTimes(1).DoAndReturn(
					func(ctx context.Context, input *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
						sqsCancelFunc()
						return nil, errors.New("error")
					},
				)
				// We expect no queues to be created or deleted
				mockSQSClient.EXPECT().CreateQueue(gomock.Any(), gomock.Any()).Times(0)
				mockSQSClient.EXPECT().DeleteMessage(gomock.Any(), gomock.Any()).Times(0)
				runSQSHandler(sqsHandlerContext)
				<-sqsHandlerContext.Done()
			})

			Convey("by attempting to create a new sqs queue...", func() {
				clientId := "fake-id"
				sqsCreateQueueInput := sqs.CreateQueueInput{
					QueueName: aws.String("snowflake-client-fake-id"),
				}
				validMessage := &sqs.ReceiveMessageOutput{
					Messages: []types.Message{
						{
							Body: messageBody,
							MessageAttributes: map[string]types.MessageAttributeValue{
								"ClientID": {StringValue: &clientId},
							},
							ReceiptHandle: &receiptHandle,
						},
					},
				}
				Convey("and does not attempt to send a message via SQS if queue creation fails.", func(c C) {
					sqsHandlerContext, sqsCancelFunc := context.WithCancel(context.Background())

					mockSQSClient.EXPECT().ReceiveMessage(sqsHandlerContext, &sqsReceiveMessageInput).AnyTimes().DoAndReturn(
						func(ctx context.Context, input *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
							sqsCancelFunc()
							return validMessage, nil
						})
					mockSQSClient.EXPECT().CreateQueue(sqsHandlerContext, &sqsCreateQueueInput).Return(nil, errors.New("error")).AnyTimes()
					mockSQSClient.EXPECT().DeleteMessage(sqsHandlerContext, &sqsDeleteMessageInput).AnyTimes()
					runSQSHandler(sqsHandlerContext)
					<-sqsHandlerContext.Done()
				})

				Convey("and responds with a proxy answer if available.", func(c C) {
					sqsHandlerContext, sqsCancelFunc := context.WithCancel(context.Background())
					var numTimes atomic.Uint32

					mockSQSClient.EXPECT().ReceiveMessage(gomock.Any(), &sqsReceiveMessageInput).AnyTimes().DoAndReturn(
						func(ctx context.Context, input *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {

							n := numTimes.Add(1)
							if n == 1 {
								snowflake := ipcCtx.AddSnowflake("fake", "", NATUnrestricted, 0)
								go func(c C) {
									<-snowflake.offerChannel
									snowflake.answerChannel <- "fake answer"
								}(c)
								return validMessage, nil
							}
							return nil, errors.New("error")

						})
					mockSQSClient.EXPECT().CreateQueue(gomock.Any(), &sqsCreateQueueInput).Return(&sqs.CreateQueueOutput{
						QueueUrl: responseQueueURL,
					}, nil).AnyTimes()
					mockSQSClient.EXPECT().DeleteMessage(gomock.Any(), gomock.Any()).AnyTimes()
					mockSQSClient.EXPECT().SendMessage(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(
						func(ctx context.Context, input *sqs.SendMessageInput, optFns ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
							c.So(input.MessageBody, ShouldEqual, aws.String("{\"answer\":\"fake answer\"}"))
							// Ensure that match is correctly recorded in metrics
							ipcCtx.metrics.printMetrics()
							c.So(buf.String(), ShouldContainSubstring, `client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-snowflake-match-count 8
client-snowflake-timeout-count 0
client-http-count 0
client-http-ips 
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 8
client-sqs-ips ??=8
`)
							sqsCancelFunc()
							return &sqs.SendMessageOutput{}, nil
						},
					)
					runSQSHandler(sqsHandlerContext)

					<-sqsHandlerContext.Done()
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
