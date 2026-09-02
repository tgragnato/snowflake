**Table of Contents**

- [Client library](#client-library)
  - [Using your own rendezvous method](#using-your-own-rendezvous-method)
- [Server library](#server-library)
- [Running your own Snowflake infrastructure](#running-your-own-snowflake-infrastructure)

Snowflake is available as a general-purpose pluggable transports library and adheres
to the [pluggable transports v2.1 Go API](https://github.com/Pluggable-Transports/Pluggable-Transports-spec/blob/master/releases/PTSpecV2.1/Pluggable%20Transport%20Specification%20v2.1%20-%20Go%20Transport%20API.pdf).
The client library gives you a `net.Conn` whose traffic is carried through volunteer
Snowflake proxies; the server library gives you the matching listener.

### Client library

The Snowflake client library contains functions for running a Snowflake client.

Example usage:

```go
package main

import (
	"log"

	sf "tgragnato.it/snowflake/client/lib"
)

func main() {
	config := sf.ClientConfig{
		BrokerURL:    "https://snowflake-broker.example.com",
		FrontDomains: []string{"friendlyfrontdomain.net"},
		ICEAddresses: []string{
			"stun:stun.tgragnato.it:3478",
		},
		Max: 1,
	}

	transport, err := sf.NewSnowflakeClient(config)
	if err != nil {
		log.Fatal("Failed to start snowflake transport: ", err)
	}

	// transport implements the ClientFactory interface and returns a net.Conn
	conn, err := transport.Dial()
	if err != nil {
		log.Printf("dial error: %s", err)
		return
	}
	defer conn.Close()

	// ...
}
```

`FrontDomains` takes bare domain names, not URLs, and one of them is chosen at random
for each broker request. The singular `FrontDomain` field is kept for backward
compatibility only; prefer `FrontDomains` in new code.

#### Using your own rendezvous method

You can define and use your own rendezvous method to communicate with a Snowflake
broker by implementing the `RendezvousMethod` interface.

```go
package main

import (
	"log"

	sf "tgragnato.it/snowflake/client/lib"
)

type StubMethod struct{}

func (m *StubMethod) Exchange(pollReq []byte) ([]byte, error) {
	var brokerResponse []byte
	var err error

	// Implement the logic you need to communicate with the Snowflake broker here.

	return brokerResponse, err
}

func main() {
	config := sf.ClientConfig{
		ICEAddresses: []string{
			"stun:stun.tgragnato.it:3478",
		},
	}

	transport, err := sf.NewSnowflakeClient(config)
	if err != nil {
		log.Fatal("Failed to start snowflake transport: ", err)
	}

	// custom rendezvous methods can be set with `SetRendezvousMethod`
	rendezvous := &StubMethod{}
	transport.SetRendezvousMethod(rendezvous)

	// transport implements the ClientFactory interface and returns a net.Conn
	conn, err := transport.Dial()
	if err != nil {
		log.Printf("dial error: %s", err)
		return
	}
	defer conn.Close()

	// ...
}
```

### Server library

The Snowflake server library contains functions for running a Snowflake server.

Example usage:

```go
package main

import (
	"log"
	"net"

	"golang.org/x/crypto/acme/autocert"
	sf "tgragnato.it/snowflake/server/lib"
)

func main() {
	// The snowflake server runs a websocket server. To run this securely, you will
	// need a valid certificate.
	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("snowflake.yourdomain.com"),
		Email:      "you@yourdomain.com",
	}

	transport := sf.NewSnowflakeServer(certManager.GetCertificate)

	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:443")
	if err != nil {
		log.Fatalf("error resolving bind address: %s", err)
	}

	numKCPInstances := 1
	ln, err := transport.Listen(addr, numKCPInstances)
	if err != nil {
		log.Fatalf("error opening listener: %s", err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// net.Error.Temporary is deprecated, so treat any accept error as
			// fatal unless your application knows how to recover from it.
			log.Printf("Snowflake accept error: %s", err)
			break
		}

		go func() {
			defer conn.Close()

			// ...
		}()
	}

	// ...
}
```

### Running your own Snowflake infrastructure

At the moment we do not have the ability to share Snowflake infrastructure between
different types of applications. If you are planning on using Snowflake as a transport
for your application, you will need to:

- Run a Snowflake broker. See the [broker documentation](broker.md) and the
  [installation guide](https://gitlab.torproject.org/tpo/anti-censorship/team/-/wikis/Survival-Guides/Snowflake-Broker-Installation-Guide)
  for more information.
- Run Snowflake proxies. These can be [standalone Go proxies](proxy.md) or
  [browser-based proxies](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake-webext).
