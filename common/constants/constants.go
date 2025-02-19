package constants

const (
	// If the broker does not receive the proxy answer within this many seconds
	// after the broker received the client offer,
	// the broker will respond with an error to the client.
	//
	// this is calibrated to match the timeout of the CDNs we use for rendezvous
	BrokerClientTimeout = 5
)
