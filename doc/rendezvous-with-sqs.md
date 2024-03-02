# Rendezvous with Amazon SQS
This is a new experimental rendezvous method (in addition to the existing HTTPs and AMP cache methods).
It leverages the Amazon SQS Queue service for a client to communicate with the broker server.

## Broker
To run the broker with this rendezvous method, use the following CLI flags (they are both required):
- `broker-sqs-name` - name of the broker SQS queue to listen for incoming messages
- `broker-sqs-region` - name of AWS region of the SQS queue

These two parameters determine the SQS queue URL that the client needs to be run with as a CLI flag in order to communicate with the broker. For example, the following values can be used:

`-broker-sqs-name snowflake-broker -broker-sqs-region us-east-1`

The machine on which the broker is being run must be equiped with the correct AWS configs and credentials that would allow the broker program to create, read from, and write to the SQS queue. These are typically stored at `~/.aws/config` and `~/.aws/credentials`. However, enviornment variables may also be used as described in the [AWS Docs](https://docs.aws.amazon.com/sdkref/latest/guide/creds-config-files.html)

## Client
To run the client with this rendezvous method, use the following CLI flags (they are all required):
- `sqsqueue` - URL of the SQS queue to use as a proxy for signalling
- `sqscreds` - Encoded credentials for accessing the SQS queue

`sqsqueue` should correspond to the URL of the SQS queue that the broker is listening on. 
For the example above, the following value can be used:

`-sqsqueue https://sqs.us-east-1.amazonaws.com/893902434899/snowflake-broker -sqscreds some-encoded-sqs-creds`

*Public access to SQS queues is not allowed, so there needs to be some form of authentication to be able to access the queue. Limited permission credentials will be provided by the Snowflake team to access the corresponding SQS queue.*

## Implementation Details
```
╭――――――――――――――――――╮     ╭――――――――――――――――――╮     ╭――――――――――――――――――╮     ╭―――――――――――――――――-―╮
│      Client      │ <=> │    Amazon SQS    │ <=> │      Broker      │ <=> │  Snowflake Proxy  │
╰――――――――――――――――――╯     ╰――――――――――――――――――╯     ╰――――――――――――――――――╯     ╰――――――――――――――――――-╯
```

1. On startup, the **broker** ensures that an SQS queue with the name of the `broker-sqs-name` parameter exists. It will create such a queue if it doesn’t exist. Afterwards, it will enter a loop of continuously:
    - polling for new messages
    - cleaning up client queues
2. **Client** sends SDP Offer to the SQS queue at the URL provided by the `sqsqueue` parameter using a message with a unique ID (clientID) corresponding to the client along with the contents of the SDP Offer. The client will randomly generate a new ClientID to use each rendezvous attempt.
3. The **broker** will receive this message during its polling and process it.
    -  A client SQS queue with the name `"snowflake-client" + clientID` will be created for the broker to send messages to the client. This is needed because if a queue shared between all clients was used for outgoing messages from the server, then clients would have to pick off the top message, check if it is addressed to them, and then process the message if it is. This means clients would possibly have to check many messages before they find the one addressed to them.
    - When the broker has a response for the client, it will send a message to the client queue with the details of the SDP answer.
    - The SDP offer message from the client is then deleted from the broker queue.
4. The **client** will continuously poll its client queue and eventually receive the message with the SDP answer from the broker.
5. The broker server will periodically clean up the unique SQS queues it has created for each client once the queues are no longer needed (it will delete queues that were last modified before a certain amount of time ago)