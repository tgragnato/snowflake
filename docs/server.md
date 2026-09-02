**Table of Contents**

- [Setup](#setup)
- [TLS](#tls)
- [Multiple KCP state machines](#multiple-kcp-state-machines)
- [Controlling source addresses](#controlling-source-addresses)

This is the server transport plugin for Snowflake. The transport protocol it speaks is
[WebSocket](https://tools.ietf.org/html/rfc6455): the client connects to a proxy over
WebRTC, and the proxy connects to this program over WebSocket.

### Setup

Here is a short example of configuring your `torrc` file to run the Snowflake server
under Tor:

```ini
SocksPort 0
ORPort 9001
ExtORPort auto
BridgeRelay 1

ServerTransportListenAddr snowflake 0.0.0.0:443
ServerTransportPlugin snowflake exec ./server --acme-hostnames snowflake.example --acme-email admin@snowflake.example --log /var/log/tor/snowflake-server.log
```

Every domain name given to the `-acme-hostnames` option must resolve to the IP address
of the server. You can give more than one, separated by commas.

The server accepts the flags `-acme-hostnames`, `-acme-email`, `-disable-tls`, `-log`,
`-unsafe-logging` and `-version`. Use `-unsafe-logging` only for local debugging: it
keeps IP addresses and other identifying data in the logs.

### TLS

The server uses TLS WebSockets by default, `wss://` rather than `ws://`. There is a
`-disable-tls` option for testing, but you should use TLS in production.

Certificates are fetched from [Let's Encrypt](https://letsencrypt.org/) automatically.
Use `-acme-hostnames` to tell the server which hostnames it may request certificates
for, and optionally `-acme-email` to give Let's Encrypt a contact address so it can
report any problems. Certificate data is cached in the directory
`pt_state/snowflake-certificate-cache` inside the Tor state directory.

The ACME protocol requires the server to listen on port 80, in addition to whatever
ports serve WebSocket connections, and the program exits if it cannot bind it. On
Linux, the `setcap` program, part of libcap2, lets the server bind low-numbered ports
without running as root:

```bash
setcap 'cap_net_bind_service=+ep' /usr/local/bin/snowflake-server
```

### Multiple KCP state machines

The server uses a network protocol called KCP internally to manage and persist client
sessions. Each KCP scheduler runs in a single goroutine, so with many simultaneous
users — thousands — a single scheduler becomes a bottleneck. The `num-turbotunnel`
pluggable transport option controls how many KCP instances run, which helps with CPU
scaling
([snowflake#40200](https://bugs.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/40200)):

```ini
ServerTransportOptions snowflake num-turbotunnel=2
```

There is currently no way to set this option automatically; you have to tune it by
hand.

### Controlling source addresses

Use the `orport-srcaddr` pluggable transport option to control the source addresses
used when connecting to the upstream Tor ExtORPort or ORPort. The value may be a
single IP address, for example `127.0.0.2`, or a CIDR range, for example
`127.0.2.0/24`. Given a range, an address from it is chosen at random for each new
connection.

Set the option with `ServerTransportOptions` in `torrc`:

```ini
ServerTransportOptions snowflake orport-srcaddr=127.0.2.0/24
```

It can be combined with the other options:

```ini
ServerTransportOptions snowflake num-turbotunnel=2 orport-srcaddr=127.0.2.0/24
```

Using a source address range other than the default `127.0.0.1` helps conserve
localhost ephemeral ports on servers that receive a lot of connections
([snowflake#40198](https://bugs.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/40198)).
