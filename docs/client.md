**Table of Contents**

- [Dependencies](#dependencies)
- [Building the Snowflake client](#building-the-snowflake-client)
- [Running the Snowflake client with Tor](#running-the-snowflake-client-with-tor)
  - [Testing against a local broker](#testing-against-a-local-broker)
- [Bridge line options](#bridge-line-options)
- [Rendezvous methods](#rendezvous-methods)
  - [Domain-fronted HTTPS](#domain-fronted-https)
  - [AMP cache](#amp-cache)
  - [Amazon SQS](#amazon-sqs)
  - [Direct access](#direct-access)

This is the Tor client component of Snowflake. It is built on
[goptlib](https://gitweb.torproject.org/pluggable-transports/goptlib.git/), the Tor
pluggable transports library for Go.

### Dependencies

- Go 1.26 or later. See [development.md](development.md) for the toolchain and lint
  requirements that apply to the whole repository.
- [pion/webrtc](https://github.com/pion/webrtc), used for the WebRTC connection to
  Snowflake proxies. It is declared in `go.mod` and downloaded automatically by
  `go build`; no separate step is required.

### Building the Snowflake client

From the `client/` directory:

```bash
go build
```

### Running the Snowflake client with Tor

The client is configured through SOCKS options, set in your `torrc` file. The
following configuration is recommended as a starting point:

```ini
UseBridges 1
DataDirectory datadir
SocksPort auto

ClientTransportPlugin snowflake exec ./client -log snowflake.log

# CDN77
Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.tgragnato.it:3478,stun:stun.nextcloud.com:443,stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn
Bridge snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.tgragnato.it:3478,stun:stun.nextcloud.com:443,stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn
```

Rendezvous through an AMP cache instead, with the broker's own domain in `url=`:

```ini
Bridge snowflake 192.0.2.5:443 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net/ ampcache=https://cdn.ampproject.org/ front=www.google.com ice=stun:stun.tgragnato.it:3478,stun:stun.nextcloud.com:443,stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn
Bridge snowflake 192.0.2.6:443 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://snowflake-broker.torproject.net/ ampcache=https://cdn.ampproject.org/ front=www.google.com ice=stun:stun.tgragnato.it:3478,stun:stun.nextcloud.com:443,stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn
```

Or through an Amazon SQS queue, which replaces `url=` and the fronting options
entirely:

```ini
Bridge snowflake 192.0.2.5:443 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 sqsqueue=https://sqs.us-east-1.amazonaws.com/893902434899/snowflake-broker sqscreds=eyJhd3MtYWNjZXNzLWtleS1pZCI6IkFLSUE1QUlGNFdKSlhTN1lIRUczIiwiYXdzLXNlY3JldC1rZXkiOiI3U0RNc0pBNHM1RitXZWJ1L3pMOHZrMFFXV0lsa1c2Y1dOZlVsQ0tRIn0= ice=stun:stun.tgragnato.it:3478,stun:stun.nextcloud.com:443,stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn
Bridge snowflake 192.0.2.6:443 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA sqsqueue=https://sqs.us-east-1.amazonaws.com/893902434899/snowflake-broker sqscreds=eyJhd3MtYWNjZXNzLWtleS1pZCI6IkFLSUE1QUlGNFdKSlhTN1lIRUczIiwiYXdzLXNlY3JldC1rZXkiOiI3U0RNc0pBNHM1RitXZWJ1L3pMOHZrMFFXV0lsa1c2Y1dOZlVsQ0tRIn0= ice=stun:stun.tgragnato.it:3478,stun:stun.nextcloud.com:443,stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn
```

To bootstrap Tor, run:

```bash
tor -f torrc
```

This starts the client plugin, which bootstraps to 100% over WebRTC.

#### Testing against a local broker

To exercise the client against a broker running on the same machine, keep the local
LAN candidates and point `url=` at it:

```ini
UseBridges 1
DataDirectory datadir

ClientTransportPlugin snowflake exec ./client -keep-local-addresses

Bridge snowflake 192.0.2.3:1 url=http://localhost:8080/
```

### Bridge line options

| Option | Meaning |
| --- | --- |
| `fingerprint=` | Fingerprint of the bridge the client ultimately connects to. |
| `url=` | URL of a broker instance. To try Snowflake against your own broker, put its URL here. |
| `fronts=` | Optional comma-separated list of front domains for the broker request; one is chosen at random per request. `front=` is the older single-value form and is still accepted. |
| `ampcache=` | URL of the AMP cache used for rendezvous. See [AMP cache](#amp-cache). |
| `sqsqueue=`, `sqscreds=` | SQS queue URL and encoded credentials. See [Amazon SQS](#amazon-sqs). |
| `ice=` | Comma-separated list of ICE servers. Only STUN over UDP is supported. Prefer servers that implement NAT discovery; see the wiki page on [NAT traversal](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/wikis/NAT-matching). |
| `utls-imitate=` | ClientHello fingerprint to imitate when rendezvousing with the broker, for fingerprinting resistance. Run the client with `-version` to list the supported values. |
| `utls-nosni=` | Set to `true` to omit the SNI extension from the ClientHello. Not every server accepts connections without it. |
| `max=` | Maximum number of proxies to use simultaneously. |

The value of `ice=` is split on commas and each entry is parsed on its own, so every
entry needs its own `stun:` scheme, as in
`ice=stun:stun.example.com:3478,stun:stun.example.org:3478`. An entry whose scheme is
not `stun` is skipped with a warning rather than rejected outright, so a missing prefix
silently costs you that server.

The client also accepts the command-line flags `-log`, `-log-to-state-dir`,
`-keep-local-addresses`, `-unsafe-logging` and `-version`. Do not use
`-unsafe-logging` outside local debugging: it keeps IP addresses and other identifying
data in the logs.

### Rendezvous methods

The Snowflake client supports several ways of reaching the broker to find a proxy.
This first step is called rendezvous.

#### Domain-fronted HTTPS

For domain-fronted rendezvous, use the `-url` and `-front` (or `-fronts`) options
together. [Domain fronting](https://www.bamsoftware.com/papers/fronting/) hides the
externally visible domain name from an observer, making it appear that the Snowflake
client is communicating with some server other than the Snowflake broker.

- `-url` is the HTTPS URL of a forwarder to the broker, on a service that supports
  domain fronting, such as a CDN.
- `-front` is the domain name shown externally. It must be another domain on the same
  service. `-fronts` takes a comma-separated list and picks one at random per request.

Example:

```
-url https://snowflake-broker.torproject.net.global.prod.fastly.net/ \
-front cdn.sstatic.net
```

#### AMP cache

For AMP cache rendezvous, use the `-url`, `-ampcache` and `-front` options together.
[AMP](https://amp.dev/documentation/) is a standard for web pages on mobile devices,
and an
[AMP cache](https://amp.dev/documentation/guides-and-tutorials/learn/amp-caches-and-cors/how_amp_pages_are_cached/)
is a cache and proxy specialized for AMP pages. The broker can make its client
registration responses look like AMP pages, so that they can be served through an AMP
cache. To an observer, the client then appears to be accessing an AMP cache, or another
domain operated by the same organization.

`-front` is still required, because the
[format of AMP cache URLs](https://amp.dev/documentation/guides-and-tutorials/learn/amp-caches-and-cors/amp-cache-urls/)
would otherwise reveal the domain name of the broker.

Only one AMP cache works with this option: the Google AMP cache at
https://cdn.ampproject.org/.

- `-url` is the HTTPS URL of the broker.
- `-ampcache` is `https://cdn.ampproject.org/`.
- `-front` is any Google domain, such as `www.google.com`.

Example:

```
-url https://snowflake-broker.torproject.net/ \
-ampcache https://cdn.ampproject.org/ \
-front www.google.com
```

#### Amazon SQS

For SQS rendezvous, use the `-sqsqueue` and `-sqscreds` options together. The client
exchanges messages with the broker through an Amazon SQS queue instead of an HTTPS
request. This method is experimental; see
[rendezvous-with-sqs.md](rendezvous-with-sqs.md) for the message flow and for how the
broker side is configured.

#### Direct access

The broker can also be reached directly over HTTPS, without domain fronting, by
passing `-url` on its own:

```
-url https://snowflake-broker.torproject.net/
```

This is meant for testing only. It is not suitable for circumvention, because the
broker is easily blocked by its address.
