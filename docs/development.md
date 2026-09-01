**Table of Contents**

- [Repository layout](#repository-layout)
- [Build, test, lint](#build-test-lint)
- [Commit conventions](#commit-conventions)
- [Invariants](#invariants)
- [Keeping the docs in sync](#keeping-the-docs-in-sync)

This document collects the conventions and invariants that apply to every change in this
repository. It is meant to be read alongside the component documentation.

The Go module path is `tgragnato.it/snowflake` and the minimum Go version is 1.26.

### Repository layout

- `broker/` — the broker (rendezvous / signaling server), including the SQS rendezvous method.
- `client/` — the Tor pluggable-transport client (`client/snowflake.go`, where the
  command-line flags and per-bridge `torrc` args are parsed) and the client library
  (`client/lib/`). The example `torrc` and `torrc.localhost` live here.
- `common/` — libraries shared by several components: turbotunnel/KCP session persistence,
  SDP encapsulation, NAT type handling, event logging, bridge fingerprints, safe logging.
- `proxy/` — the standalone Go proxy: `proxy/main.go` for the flags, `proxy/lib/` for the logic.
- `server/` — the Tor pluggable-transport server (`server/server.go`) and server library
  (`server/lib/`).
- `probetest/` — the NAT / interactive-connectivity probe-testing service.
- `dtls/` — the forked DTLS stack that carries this fork's custom handshake fingerprint.
- `distinctcounter/` — cardinality counting used for broker metrics.
- `docs/` — documentation, manpages (`snowflake-client.1`, `snowflake-proxy.1`), the systemd
  unit, the OpenBSD rc script, and `schematic.png`.

### Build, test, lint

```
go build -v ./...
CGO_ENABLED=1 go test -race ./...
golangci-lint run
```

CI ([`.github/workflows/go.yml`](../.github/workflows/go.yml)) builds and runs the race
detector on Go 1.26 and 1.27, collects coverage and runs `golangci-lint` on 1.27, and on
pushes to `main` builds and pushes the proxy container image from the root
[`Dockerfile`](../Dockerfile) (linux/amd64 and linux/arm64, with SBOM and provenance).
[`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) runs CodeQL.

Linting is configured by [`.golangci.yml`](../.golangci.yml), which carries a small set of
targeted per-path exclusions. Prefer fixing the code over widening those exclusions.

Tests use the standard library `testing` package only. GoConvey and gomock were deliberately
removed; do not reintroduce assertion or mocking frameworks. Tests that exercise concurrent
rendezvous must synchronise explicitly (wait for the expected registrations) rather than
sleeping, otherwise they are flaky under `-race`.

Do not add dependencies, in production or test code. Every dependency is code that ships in a
circumvention tool without having been reviewed here, so the precautionary choice is to keep
the surface small: less code means fewer bugs and fewer ways to be compromised. Prefer the
standard library and in-module packages, and treat any change to `go.mod` or `go.sum` as
something to justify rather than a side effect.

When you change code, check the coverage of the package you touched and write the tests
needed to bring it to at least 80%:

```
go test -cover ./path/to/package
go test -coverprofile=coverage.out ./path/to/package && go tool cover -func=coverage.out
```

`go tool cover -func` points at the specific uncovered functions, and
`go tool cover -html=coverage.out` at the uncovered lines. If 80% is not reachable — the
remaining paths need real network peers, or are error branches that cannot be provoked
without unreasonable scaffolding — say so explicitly in the change rather than leaving the
gap unexplained.

### Commit conventions

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) and are
linted in CI by [`.github/workflows/pr.yml`](../.github/workflows/pr.yml), which also derives
the next version number from them. Use `type(scope): summary`, for example
`fix(proxy): ...`, `test: ...`, `docs: ...`, `build(deps): ...`. Dependency bumps arrive via
Dependabot and are auto-approved.

### Invariants

These properties are part of correctness for a circumvention tool, not stylistic preferences.

**Privacy.** Client IP addresses and other identifying data must remain scrubbed unless
`-unsafe-logging` is passed. Never add a log line that prints a peer address by default, and
never widen what the broker's `/metrics` endpoint exposes beyond what
[`broker-spec.txt`](broker-spec.txt) documents — that endpoint is a public, aggregated
statistics interface.

**Fingerprinting resistance.** The point of this fork is that its TLS, DTLS and WebRTC
fingerprints differ from popular implementations: a custom broker transport (TLS 1.3 with a
selected cipher suite and group list, MultiPath TCP), a custom DTLS fingerprint, reduced
MulticastDNS noise via pion's `SettingEngine`, and client padding to defeat TLS-in-DTLS
detection. Any change to handshake parameters, cipher suite or curve lists, extension order,
padding, or ICE/`SettingEngine` behaviour changes the distinguisher surface. Call such changes
out explicitly; never make them incidentally while doing something else.

**Wire compatibility.** Client, proxy, broker and server are deployed independently and run at
different versions simultaneously. Changes to the broker HTTP API, the SDP encapsulation, or
turbotunnel framing must either stay backward compatible or be explicitly versioned, and
`broker-spec.txt` must be updated in the same change.

**NAT semantics.** A proxy's NAT type determines which clients it can serve. `-stun`,
`-ephemeral-ports-range`, `-nat-probe-server` and `-nat-type-force-unrestricted` all feed into
that classification; changing how it is computed changes which clients get matched, so treat
it as a behavioural change to the matching logic in the broker.

### Keeping the docs in sync

- The flag reference in [`proxy.md`](proxy.md) is produced by running `go run . --help` from
  the `proxy/` directory. Regenerate that block in the same change that touches the flags.
- The `torrc` snippets in [`client.md`](client.md) and [`server.md`](server.md) must stay
  consistent with the args actually parsed in `client/snowflake.go` and `server/server.go`.
- The tables of contents in these docs are maintained by hand. If you add or rename a
  section, update the list at the top of the file in the same change.
