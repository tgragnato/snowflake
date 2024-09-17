# Snowflake

[![Go](https://github.com/tgragnato/snowflake/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/tgragnato/snowflake/actions/workflows/go.yml)
[![CodeQL](https://github.com/tgragnato/snowflake/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/tgragnato/snowflake/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/tgragnato/snowflake)](https://goreportcard.com/report/github.com/tgragnato/snowflake)
[![codecov](https://codecov.io/gh/tgragnato/snowflake/branch/main/graph/badge.svg)](https://codecov.io/gh/tgragnato/snowflake)

Pluggable Transport using WebRTC, inspired by Flashproxy.

### Custom fork

![Schematic](/schematic.png)

- golang 1.22+ & bumped dependencies
- custom transport for broker negotiation (TLS 1.3 with selected ciphersuites & groups, MultiPath TCP)
- custom DTLS fingerprint, different from any popular WebRTC implementation
- use the Setting Engine to reduce MulticastDNS noise
- use a context aware io.Reader that closes on errors in copyLoop
- extremely simple token handling
- client padding to evade TLS in DTLS detection
- introduction of a proxy option to force the NAT type as unrestricted
- coder/websocket in place of gorilla/websocket

**Table of Contents**

- [Structure of this Repository](#structure-of-this-repository)
- [Usage](#usage)
  - [Using Snowflake with Tor](#using-snowflake-with-tor)
  - [Running a Snowflake Proxy](#running-a-snowflake-proxy)
  - [Using the Snowflake Library with Other Applications](#using-the-snowflake-library-with-other-applications)
- [Test Environment](#test-environment)
- [FAQ](#faq)
- [More info and links](#more-info-and-links)

### Structure of this Repository

- `broker/` contains code for the Snowflake broker
- `doc/` contains Snowflake documentation and manpages
- `client/` contains the Tor pluggable transport client and client library code
- `common/` contains generic libraries used by multiple pieces of Snowflake
- `proxy/` contains code for the Go standalone Snowflake proxy
- `probetest/` contains code for a NAT probetesting service
- `server/` contains the Tor pluggable transport server and server library code

### Usage

Snowflake is currently deployed as a pluggable transport for Tor.

#### Using Snowflake with Tor

To use the Snowflake client with Tor, you will need to add the appropriate `Bridge` and `ClientTransportPlugin` lines to your [torrc](https://2019.www.torproject.org/docs/tor-manual.html.en) file. See the [client README](client) for more information on building and running the Snowflake client.

#### Running a Snowflake Proxy

You can contribute to Snowflake by running a Snowflake proxy. We have the option to run a proxy in your browser or as a standalone Go program. See our [community documentation](https://community.torproject.org/relay/setup/snowflake/) for more details. 

#### Using the Snowflake Library with Other Applications

Snowflake can be used as a Go API, and adheres to the [v2.1 pluggable transports specification](). For more information on using the Snowflake Go library, see the [Snowflake library documentation](doc/using-the-snowflake-library.md).

### FAQ

**Q: How does it work?**

In the Tor use-case:

1. Volunteers visit websites which host the "snowflake" proxy. (just
like flashproxy)
2. Tor clients automatically find available browser proxies via the Broker
(the domain fronted signaling channel).
3. Tor client and browser proxy establish a WebRTC peer connection.
4. Proxy connects to some relay.
5. Tor occurs.

More detailed information about how clients, snowflake proxies, and the Broker
fit together on the way...

**Q: What are the benefits of this PT compared with other PTs?**

Snowflake combines the advantages of flashproxy and meek. Primarily:

- It has the convenience of Meek, but can support magnitudes more
users with negligible CDN costs. (Domain fronting is only used for brief
signalling / NAT-piercing to setup the P2P WebRTC DataChannels which handle
the actual traffic.)

- Arbitrarily high numbers of volunteer proxies are possible like in
flashproxy, but NATs are no longer a usability barrier - no need for
manual port forwarding!

**Q: Why is this called Snowflake?**

It utilizes the "ICE" negotiation via WebRTC, and also involves a great
abundance of ephemeral and short-lived (and special!) volunteer proxies...

### More info and links

We have more documentation in the [Snowflake wiki](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/wikis/home) and at https://snowflake.torproject.org/.

##### uTLS Settings

Snowflake communicate with broker that serves as signaling server with TLS based domain fronting connection, which may be identified by its usage of Go language TLS stack.

uTLS is a software library designed to initiate the TLS Client Hello fingerprint of browsers or other popular software's TLS stack to evade censorship based on TLS client hello fingerprint with `-utls-imitate` . You can use `-version` to see a list of supported values.

Depending on client and server configuration, it may not always work as expected as not all extensions are correctly implemented.

You can also remove SNI (Server Name Indication) from client hello to evade censorship with `-utls-nosni`, not all servers supports this.
