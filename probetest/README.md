<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Overview](#overview)
- [Running your own](#running-your-own)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

This is code for a server-side component of Snowflake's interactive connectivity type testing system.

### Overview

This is a test server that allows a Snowflake proxy to probe the server and attempt
WebRTC sessions to determine its _interactive connectivity type_ and what kind of
Snowflake clients it can connect to. It works by adjusting the interactive connection
candidates sent in the WebRTC offer and answer, as well as relaying the connection through
a specialized proxy that limits the interactive connectivity of the probe's connection.
By design, this probe system can classify the client's interactive connectivity type as
"strict"(restricted), "moderate", "open"(unrestricted).

### Running your own

The server uses TLS by default.
There is a `--disable-tls` option for testing purposes,
but you should use TLS in production.

To build the probe server, run
```go build```

Or alternatively:

```
cd .. # switch to the repo root directory or $(git rev-parse --show-toplevel)
docker build -t snowflake-probetest -f probetest/Dockerfile .
```

The deployment of this probe requires running UDP enabled socks5 proxies that can limit
the interactivity according to need, and single stack STUN servers.
