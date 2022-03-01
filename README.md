# Pion DTLS

## A Go implementation of DTLS

Native [DTLS 1.2][rfc6347] implementation in the Go programming language.

A long term goal is a professional security review, and maybe an inclusion in stdlib.

[rfc6347]: https://tools.ietf.org/html/rfc6347

### Goals/Progress
This will only be targeting DTLS 1.2, and the most modern/common cipher suites.
We would love contributions that fall under the 'Planned Features' and any bug fixes!

#### Current features
* DTLS 1.2 Client/Server
* Key Exchange via ECDHE(curve25519, nistp256, nistp384) and PSK
* Packet loss and re-ordering is handled during handshaking
* Key export ([RFC 5705][rfc5705])
* Serialization and Resumption of sessions
* Extended Master Secret extension ([RFC 7627][rfc7627])
* ALPN extension ([RFC 7301][rfc7301])

[rfc5705]: https://tools.ietf.org/html/rfc5705
[rfc7627]: https://tools.ietf.org/html/rfc7627
[rfc7301]: https://tools.ietf.org/html/rfc7301

#### Supported ciphers

##### ECDHE
* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ([RFC 5289][rfc5289])

##### PSK
* TLS_PSK_WITH_AES_128_GCM_SHA256 ([RFC 5487][rfc5487])

[rfc5289]: https://tools.ietf.org/html/rfc5289
[rfc5487]: https://tools.ietf.org/html/rfc5487

#### Planned Features
* Chacha20Poly1305

#### Excluded Features
* DTLS 1.0
* Renegotiation
* Compression

### Using

This library needs at least Go 1.17.

#### Pion DTLS
For a DTLS 1.2 Server that listens on 127.0.0.1:4444
```sh
go run examples/listen/selfsign/main.go
```

For a DTLS 1.2 Client that connects to 127.0.0.1:4444
```sh
go run examples/dial/selfsign/main.go
```

#### OpenSSL
Pion DTLS can connect to itself and OpenSSL.
```
  // Generate a certificate
  openssl ecparam -out key.pem -name prime256v1 -genkey
  openssl req -new -sha256 -key key.pem -out server.csr
  openssl x509 -req -sha256 -days 365 -in server.csr -signkey key.pem -out cert.pem

  // Use with examples/dial/selfsign/main.go
  openssl s_server -dtls1_2 -cert cert.pem -key key.pem -accept 4444

  // Use with examples/listen/selfsign/main.go
  openssl s_client -dtls1_2 -connect 127.0.0.1:4444 -debug -cert cert.pem -key key.pem
```

### Using with PSK
Pion DTLS also comes with examples that do key exchange via PSK


#### Pion DTLS
```sh
go run examples/listen/psk/main.go
```

```sh
go run examples/dial/psk/main.go
```

#### OpenSSL
```
  // Use with examples/dial/psk/main.go
  openssl s_server -dtls1_2 -accept 4444 -nocert -psk abc123 -cipher PSK-AES128-CCM8

  // Use with examples/listen/psk/main.go
  openssl s_client -dtls1_2 -connect 127.0.0.1:4444 -psk abc123 -cipher PSK-AES128-CCM8
```

### Contributing
Check out the **[contributing wiki](https://github.com/pion/webrtc/wiki/Contributing)** to join the group of amazing people making this project possible:

### License
MIT License - see [LICENSE](LICENSE) for full text
