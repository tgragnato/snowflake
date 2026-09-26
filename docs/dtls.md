**Table of Contents**

- [Overview](#overview)
- [Native SettingEngine Configuration](#native-settingengine-configuration)
- [Current Cryptographic Surface](#current-cryptographic-surface)
- [Invariants](#invariants)
- [Testing](#testing)

### Overview

The custom `pion/dtls` fork (previously a nested module under `dtls/` with a `replace` directive in `go.mod`) has been **completely removed**. We now use standard upstream `github.com/pion/dtls/v3` and `github.com/pion/webrtc/v4`.

Cryptographic restrictions are applied **natively** via `webrtc.SettingEngine` setter methods rather than through codebase modifications to the DTLS library.

```go
s := webrtc.SettingEngine{}
s.SetDTLSCipherSuites(
    dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    dtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
    dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
)
s.SetDTLSEllipticCurves(
    dtlsElliptic.X25519,
    dtlsElliptic.P384,
)
```

### Native SettingEngine Configuration

The `SettingEngine` is configured in `client/lib/webrtc.go`, `proxy/lib/snowflake.go`, and `probetest/probetest.go`. All three locations must stay consistent.

**Important:** Do **not** attempt to modify a DTLS fork or add a `replace` directive for `github.com/pion/dtls/v3`. The upstream module is used directly.

### Current Cryptographic Surface

**DTLS Cipher Suites** (configured via `SetDTLSCipherSuites`):

```
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384          0xc02c
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256    0xcca9
TLS_PSK_WITH_AES_128_GCM_SHA256                  0x00a8
TLS_PSK_WITH_CHACHA20_POLY1305_SHA256            0xccab
```

Only AEAD/GCM and ChaCha20 suites are offered; CBC and CCM suites are excluded by omission.

**Supported Elliptic Curves / Groups** (configured via `SetDTLSEllipticCurves`):

- `X25519` (0x001d)
- `P384` (0x0018)

`P256` is not configured and is not usable for keypair generation in this surface.

### Invariants

**Fingerprinting.** Cipher suite and group lists, extension order, and handshake parameters are distinguishers. Any change to `SetDTLSCipherSuites` or `SetDTLSEllipticCurves` changes the wire fingerprint and must be called out explicitly.

**Fail closed.** When an algorithm or curve is not in the configured lists, the handshake must abort. Never add a fallback to a weaker primitive.

**Interoperability.** The peer may be a browser running a different DTLS implementation. Removing a suite from the offered list can make an entire class of proxies unreachable.

### Testing

Tests that exercise WebRTC peer connections must pass with the upstream `pion/dtls/v3` module. If a test asserts behavior that depended on the removed fork (e.g., a specific fingerprint or a removed algorithm), adapt the fixture to the supported surface or delete the obsolete assertion.

Never make a test pass by weakening what it asserts.
