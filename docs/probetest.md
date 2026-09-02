**Table of Contents**

- [Overview](#overview)
- [Building](#building)
- [Running your own](#running-your-own)

This is the server side of Snowflake's NAT probe service.

### Overview

A Snowflake proxy contacts this service to discover its own NAT type, also called its
interactive connectivity type, which determines the clients the broker can match it
with. The service attempts WebRTC sessions with the proxy while varying the ICE
candidates offered in the offer and the answer, and while relaying the connection
through a SOCKS5 proxy that constrains connectivity in a controlled way. From the
results it classifies the requesting proxy as `strict` (restricted), `moderate` or
`open` (unrestricted).

These are the same NAT type values the broker reports in its metrics; see
[broker-spec.txt](broker-spec.txt). On the proxy side the service is selected with the
`-nat-probe-server` flag; see [proxy.md](proxy.md).

### Building

From the `probetest/` directory:

```bash
go build
```

Or build the container image from the repository root:

```bash
cd "$(git rev-parse --show-toplevel)"
docker build -t snowflake-probetest -f probetest/Dockerfile .
```

### Running your own

The service uses TLS by default. There is a `-disable-tls` option for testing, but you
should use TLS in production. Certificates come either from Let's Encrypt, through
`-acme-hostnames` and `-acme-email`, or from files given with `-cert` and `-key`.

| Flag | Purpose |
| --- | --- |
| `-addr` | Address to listen on (default `:8443`). |
| `-stun` | Comma-separated STUN servers used for NAT traversal. |
| `-acme-hostnames`, `-acme-email`, `-acme-cert-cache` | ACME certificate settings. |
| `-cert`, `-key` | Use manually managed certificates instead of ACME. |
| `-disable-tls` | Serve over plain HTTP. Testing only. |
| `-unsafe-logging` | Keep IP addresses and other identifying data in the logs. Debugging only. |

A complete deployment additionally requires:

- UDP-capable SOCKS5 proxies that constrain interactivity as needed, one simulating
  strict connectivity and one simulating moderate connectivity. Their addresses are
  passed through the two SOCKS5 proxy flags; run the binary with `-h` for their exact
  names and defaults.
- Single-stack STUN servers, so that the address observed during a probe is not
  influenced by dual-stack behavior.

Without these, the service cannot tell the connectivity classes apart and its
classifications are not meaningful.
