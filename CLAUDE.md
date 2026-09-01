# Snowflake — Claude Instructions

Read the following files before suggesting or generating any code:

1. [`README.md`](README.md) — project overview, how this fork deviates from upstream Snowflake, repository layout, uTLS settings.
2. [`docs/broker-spec.txt`](docs/broker-spec.txt) — normative broker protocol: `/metrics` reporting format and the client/proxy rendezvous message formats.
3. [`docs/broker.md`](docs/broker.md) — the broker (rendezvous/signaling server): what it matches, and how to run your own.
4. [`docs/client.md`](docs/client.md) — the Tor client transport plugin: build, `torrc` bridge lines, and the available rendezvous methods.
5. [`docs/probetest.md`](docs/probetest.md) — the NAT/interactive-connectivity probe service used by proxies to classify themselves.
6. [`docs/proxy.md`](docs/proxy.md) — the standalone Go proxy: build steps and the full command-line flag reference.
7. [`docs/rendezvous-with-sqs.md`](docs/rendezvous-with-sqs.md) — the experimental Amazon SQS rendezvous method and its message flow.
8. [`docs/server.md`](docs/server.md) — the WebSocket server transport plugin: `torrc` setup, TLS/ACME, KCP and source-address options.
9. [`docs/using-the-snowflake-library.md`](docs/using-the-snowflake-library.md) — using Snowflake as a Go library under the PT v2.1 API.
10. [`docs/development.md`](docs/development.md) — build, test, lint and commit conventions, plus the invariants (privacy, fingerprinting, wire compatibility) any change must preserve.
