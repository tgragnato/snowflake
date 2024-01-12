package snowflake_client

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/sqsclient"
)

func TestExample(t *testing.T) {
	Convey("Test Example 1", t, func() {
		ctrl := gomock.NewController(t)
		mockSqsClient := sqsclient.NewMockSQSClient(ctrl)
		mockSqsClient.EXPECT().GetQueueUrl(gomock.Any(), gomock.Any()).Return(&sqs.GetQueueUrlOutput{
			QueueUrl: aws.String("https://wwww.google.com"),
		}, nil)

		output, err := mockSqsClient.GetQueueUrl(context.TODO(), &sqs.GetQueueUrlInput{
			QueueName: aws.String("testing"),
		})
		ShouldBeNil(err)
		ShouldEqual(output, sqs.GetQueueUrlOutput{
			QueueUrl: aws.String("https://wwww.google.com"),
		})
	})
}
