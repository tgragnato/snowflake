# Rendezvous with Amazon SQS

**Table of Contents**

- [Broker](#broker)
- [Client](#client)
- [Credentials](#credentials)
- [Implementation details](#implementation-details)

This is an experimental rendezvous method, alongside the existing HTTPS and AMP cache
methods. It uses an Amazon SQS queue as the channel through which a client
communicates with the broker.

## Broker

Running the broker with this rendezvous method requires both of the following flags:

- `-broker-sqs-name` — name of the broker SQS queue to listen on for incoming messages.
- `-broker-sqs-region` — AWS region of that queue.

Together they determine the SQS queue URL that clients must be configured with. For
example:

```bash
-broker-sqs-name snowflake-broker -broker-sqs-region us-east-1
```

The machine running the broker must be configured with AWS credentials that allow it
to create, read from, write to and delete SQS queues. These are usually stored in
`~/.aws/config` and `~/.aws/credentials`, but environment variables work as well; see
the [AWS documentation](https://docs.aws.amazon.com/sdkref/latest/guide/creds-config-files.html).

## Client

Running the client with this rendezvous method requires both of the following flags:

- `-sqsqueue` — URL of the SQS queue used as a proxy for signaling.
- `-sqscreds` — encoded credentials for accessing that queue.

`-sqsqueue` must match the URL of the queue the broker listens on. For the example
above:

```bash
-sqsqueue https://sqs.us-east-1.amazonaws.com/893902434899/snowflake-broker -sqscreds some-encoded-sqs-creds
```

## Credentials

SQS queues cannot be made publicly accessible, so the client has to authenticate in
order to reach the queue. `-sqscreds` carries a base64 encoding of a JSON object of
the form:

```json
{"aws-access-key-id": "...", "aws-secret-key": "..."}
```

The credentials are issued from an identity restricted to the queues involved, with no
permissions beyond creating, sending, receiving and deleting the messages this
rendezvous method needs.

## Implementation details

```text
+--------+     +------------+     +--------+     +-----------------+
| Client | <=> | Amazon SQS | <=> | Broker | <=> | Snowflake proxy |
+--------+     +------------+     +--------+     +-----------------+
```

1. On startup the **broker** ensures that a queue named by `-broker-sqs-name` exists,
   creating it if it does not. It then loops continuously, polling for new messages
   and cleaning up client queues.
2. The **client** sends its SDP offer to the queue at the URL given by `-sqsqueue`, in
   a message carrying a unique client ID along with the contents of the offer. The
   client generates a fresh random client ID for each rendezvous attempt.
3. The **broker** receives that message while polling, and processes it:
   - It creates a client queue named `"snowflake-client" + clientID` to send messages
     back to the client. A single queue shared by all clients would force each client
     to take the top message, check whether it is addressed to itself, and process it
     only then, so a client could have to inspect many messages before finding its own.
   - Once it has a response, it sends the SDP answer to that client queue.
   - It then deletes the client's offer message from the broker queue.
4. The **client** polls its client queue until it receives the message carrying the
   broker's SDP answer.
5. The **broker** periodically cleans up the client queues it created, deleting those
   that have not been modified for long enough to be considered no longer needed.
