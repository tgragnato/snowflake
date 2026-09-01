**Table of Contents**

- [Overview](#overview)
- [Working with the module](#working-with-the-module)
- [What the fork removes](#what-the-fork-removes)
- [What the fork keeps, and why](#what-the-fork-keeps-and-why)
- [The supported surface](#the-supported-surface)
- [Invariants](#invariants)
- [Testing this module](#testing-this-module)
- [Known gaps](#known-gaps)

`dtls/` is this fork's DTLS stack. It carries the custom handshake fingerprint that the
[README](../README.md) lists among the deviations from upstream Snowflake, and it removes
cryptographic algorithms considered too weak rather than merely deprioritising them.

### Overview

The directory is a **nested Go module**, `github.com/pion/dtls/v3`, wired into the main module
through a `replace` directive in the root [`go.mod`](../go.mod):

```
replace github.com/pion/dtls/v3 v3.1.5 => ./dtls
```

The practical consequence is that commands run from the repository root do not reach it:
`./...` expands within the main module only. To build, test, vet or format this code, run the
command from inside `dtls/`. The two modules also declare their own `go` directives
independently, so a language-version difference between them is possible.

DTLS is the transport for the WebRTC data channel between a Snowflake client and a proxy, so
changes here are visible to every peer, including the browser-based proxies of
[snowflake-webext](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake-webext),
which run a different DTLS implementation entirely.

### Working with the module

```
cd dtls
go build ./...
CGO_ENABLED=1 go test -race $(go list ./... | grep -v "/e2e")
go vet ./...
gofmt -l .
```

The `e2e` package is excluded above because it drives an external OpenSSL with DTLS support and
hangs without it. Exclude it rather than making its tests pass by lowering what they check.

### What the fork removes

The removals are implemented in the code, not left to configuration, so an operator cannot
re-enable them by mistake:

- **RSA signing.** [`config.go`](../dtls/config.go) accepts only `ed25519` and `*ecdsa`
  private keys; anything else is rejected with `ErrInvalidPrivateKey`. `isCompatible` in
  [`signaturehash.go`](../dtls/pkg/crypto/signaturehash/signaturehash.go) refuses to select any
  scheme for an RSA key, so this side never produces an RSA signature.
- **RSA PKCS#1 v1.5.** Not verified at all. An RSA certificate presented alongside a non-PSS
  signature algorithm fails closed with `ErrKeySignatureVerifyUnimplemented` instead of falling
  back to the weaker padding. `rsa_pkcs1_*` schemes are not in `signature.Algorithms()`, so
  they are rejected while parsing a peer's list.
- **CBC and CCM cipher suites**, in favour of AEAD/GCM.
- **The weaker member of a pair**, where both are otherwise equivalent:
  `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` is gone and only the SHA-384/AES-256 variant
  remains.
- **P-256 keypair generation.** `P256` remains a recognised curve identifier, but `toECDH` in
  [`elliptic.go`](../dtls/pkg/crypto/elliptic/elliptic.go) produces keypairs only for X25519
  and P-384. Being a declared constant is not the same as being usable.

### What the fork keeps, and why

**RSA-PSS signature schemes stay, including the SHA-256 variants.** RFC 8446 §9.1 makes
`rsa_pss_rsae_sha256` (0x0804) and `ecdsa_secp256r1_sha256` (0x0403) mandatory to implement, so
the SHA-256 variants are precisely the ones that cannot be dropped — the opposite of what
"prefer the stronger hash" would suggest. Note that this implementation encodes signature
algorithms as TLS 1.2 style `{hash, signature}` pairs, so `{hash.SHA256, signature.ECDSA}`
serialises to 0x0403: removing it would remove a mandatory scheme and would break peers whose
certificates are ECDSA P-256, which is what most WebRTC implementations generate, this one
included ([`selfsign.go`](../dtls/pkg/crypto/selfsign/selfsign.go) uses P-256).

**RSA-PSS verification stays.** Advertising `rsa_pss_rsae_*` means a peer may authenticate with
an RSA certificate, and we have to be able to verify it. "We never sign with RSA" and "we never
verify RSA" are different statements; only the first is true here.

**Do not reorder the offered lists casually.** The order in `Algorithms()` and `Algorithms13()`
determines negotiation preference and is itself part of the fingerprint.

### The supported surface

Cipher suites, from [`cipher_suite.go`](../dtls/cipher_suite.go):

```
TLS_CHACHA20_POLY1305_SHA256                     (DTLS 1.3, authentication-neutral)
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384          0xc02c
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256    0xcca9
TLS_PSK_WITH_AES_128_GCM_SHA256                  0x00a8
TLS_PSK_WITH_CHACHA20_POLY1305_SHA256            0xccab
```

Named groups: `X25519` (0x001d), `P384` (0x0018) and the hybrid `X25519MLKEM768` (0x11ec) can
produce keypairs; `P256` (0x0017) is recognised but cannot.

Signature schemes offered, in preference order: ECDSA with SHA-256/384/512, Ed25519, then
RSA-PSS RSAE with SHA-256/384/512. The `RSA_PSS_PSS_*` schemes (0x0809–0x080b) are parsed for
wire-format compatibility but never negotiated — `IsUnsupported()` reports true for them.

Private keys accepted for our own certificates: ECDSA and Ed25519.

### Invariants

**Fingerprinting.** Cipher suite and group lists, extension order, signature scheme order,
handshake parameters and padding are all distinguishers. A change to any of them is a change to
how this implementation looks on the wire, and must be called out as such rather than made in
passing while doing something else.

**Fail closed.** When an algorithm, curve or scheme is not supported, the handshake must abort.
Never add a fallback to a weaker primitive, and prefer returning an error over continuing with
a partially initialised state.

**Interoperability.** The peer may be a browser, not this code. Removing something from the
offered lists can make an entire class of proxies unreachable, which no test in this repository
will detect.

### Testing this module

A red test here means one of three quite different things, and the fix differs completely.
Decide which before editing.

1. **The test is broken** — it asserts something that was never true. Fix the test; leave the
   code alone.
2. **The behaviour was removed on purpose** — an upstream test covers an algorithm this fork
   dropped. Adapt the fixture to a supported algorithm. If the test only made sense for the
   removed one, delete it and leave a comment where it was saying what it covered and why it
   cannot exist, so a later iteration does not reintroduce it. Better still, convert it into a
   test that the removed algorithm is *rejected*: that keeps the removal from being undone.
3. **The environment cannot run it** — an external binary or real network peers are needed.
   Report the requirement and move on.

**Never make a test pass by weakening what it asserts.** If an assertion cannot hold, work out
what invariant should hold instead, then write that. A test that checks nothing is worse than a
failing one, because it reports success.

Patterns that have been found in this module's tests more than once, worth checking before
concluding the code is at fault:

- **Inverted polarity** — `if err == nil { t.Fatal("expected an error") }` around a call that
  returns nil on success, or `!reflect.DeepEqual` under a message reading "should not equal".
  One such test asserted that the Finished MAC did *not* depend on the base key.
- **Pointer compared instead of value** — any pointer field compared with `!=`. The signature
  is an error message showing two identical renderings, or addresses that change between runs.
- **Comparing unrelated things** — a hash against raw bytes, a header against a payload, a
  header against the whole record, a message against a certificate.
- **Golden vectors for randomised algorithms** — a fixed expected signature can only work for a
  deterministic scheme. RSA-PSS is salted, ECDSA is randomised in Go, only Ed25519 is
  deterministic. Prefer a sign-then-verify round trip.
- **Impossible `{hash, scheme}` pairings** — a PSS scheme travels as a full `uint16` and carries
  its own hash, so `{hash.SHA256, RSA_PSS_RSAE_SHA512}` cannot survive a round trip.
- **`reflect.DeepEqual` against a standard library struct** — `x509.Certificate` gains fields
  across Go releases, and the module's `go` directive can be older than the toolchain, so a new
  field is populated at run time while being unnameable in source. Compare the fields the test
  is about.
- **Asymmetric round trips** — an input the parser skips cannot appear in a fixture that also
  asserts the re-marshalled bytes. Test skipping separately.
- **Residue from an earlier edit** — comments such as `// FIX APPLIED HERE`, a variable declared
  and never assigned, indentation that does not match the file. Read the whole function, not
  just the failing line.

### Known gaps

- The `e2e` package needs an external OpenSSL with DTLS support and hangs without one.
- `FromCertificate` maps every `x509` RSA-PSS algorithm to the `RSA_PSS_PSS_*` scheme, which
  `IsUnsupported()` then rejects. Go's `x509` cannot distinguish an `rsaEncryption` key from an
  `id-RSASSA-PSS` one, and the WebPKI mapping would be `RSA_PSS_RSAE_*`, so a peer's genuine
  RSA-PSS certificate is refused today.
- `flight4Generate` in
  [`flight4handler.go`](../dtls/internal/flight/flight12/flight4handler.go) dereferences
  `state.LocalKeypair` without a nil check, the only unguarded dereference in a function that
  checks every other failure. It is not reachable through the normal state machine, because
  flight 0 aborts when keypair generation fails, but the narrowed curve list widens exactly that
  scenario.
