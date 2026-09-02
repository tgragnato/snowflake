**Table of Contents**

- [Overview](#overview)
- [Running your own](#running-your-own)
  - [TLS](#tls)
  - [Other options](#other-options)
  - [Pointing a client at your broker](#pointing-a-client-at-your-broker)

This is the broker component of Snowflake.

### Overview

The broker performs the rendezvous: it matches Snowflake clients with proxies and
passes along their WebRTC session descriptions, the step usually called signaling.
Once that exchange completes, the client and the proxy establish a peer connection
directly.

It plays the role of Flashproxy's facilitator, but bidirectionally and behind domain
fronting.

The broker expects:

- Clients to send their SDP offer in a POST request, which then blocks until the
  broker responds with the answer from the matched proxy.
- Proxies to announce themselves with a POST request, to which the broker responds
  with some client's SDP offer. The proxy then sends a second POST request soon after,
  containing its SDP answer, which the broker passes back to the same client.

The wire format of these messages is specified in [broker-spec.txt](broker-spec.txt).

### Running your own

#### TLS

The broker uses TLS by default. There is a `-disable-tls` option for testing, but you
should use TLS in production.

Certificates are fetched from [Let's Encrypt](https://letsencrypt.org/) automatically.
Use `-acme-hostnames` to tell the broker which hostnames it may request certificates
for, and optionally `-acme-email` to give Let's Encrypt a contact address so it can
report any problems. Certificates are cached in the directory named by
`-acme-cert-cache` (default `acme-cert-cache`).

To answer ACME challenges, the broker opens an additional HTTP listener on port 80. On
Linux, the `setcap` program, part of libcap2, lets it bind low-numbered ports without
running as root:

```bash
setcap 'cap_net_bind_service=+ep' /usr/local/bin/broker
```

To use certificates you manage yourself instead of ACME, pass `-cert` and `-key`.

#### Other options

| Flag | Purpose |
| --- | --- |
| `-addr` | Address to listen on (default `:443`). |
| `-geoipdb`, `-geoip6db` | GeoIP databases used to attribute polls to countries. |
| `-disable-geoip` | Collect statistics without country attribution. |
| `-metrics-log` | Path to the metrics logging output; see [broker-spec.txt](broker-spec.txt). |
| `-ip-count-prefix`, `-ip-count-interval` | Path prefix and interval for IP count logging. |
| `-allowed-relay-pattern` | Rejects proxies whose `AcceptedRelayPattern` is more restrictive than this. |
| `-bridge-list-path` | File listing the bridges clients may be matched to. |
| `-poll-interval-filepath` | File holding the poll interval recommended to proxies. |
| `-trusted-hops` | Number of trusted reverse-proxy hops in front of the broker, used to determine proxy IP addresses (default `1`). |
| `-broker-sqs-name`, `-broker-sqs-region`, `-sqs-profiles` | Enable the SQS rendezvous method; see [rendezvous-with-sqs.md](rendezvous-with-sqs.md). |
| `-unsafe-logging` | Keep IP addresses and other identifying data in the logs. Debugging only. |

#### Pointing a client at your broker

Give the URL of your broker to the client plugin with the `-url $URL` flag, or set
`url=` in the bridge line. See [client.md](client.md).
