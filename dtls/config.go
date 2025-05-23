// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/logging"
)

const keyLogLabelTLS12 = "CLIENT_RANDOM"

// Config is used to configure a DTLS client or server.
// After a Config is passed to a DTLS function it must not be modified.
type Config struct {
	// Certificates contains certificate chain to present to the other side of the connection.
	// Server MUST set this if PSK is non-nil
	// client SHOULD sets this so CertificateRequests can be handled if PSK is non-nil
	Certificates []tls.Certificate

	// CipherSuites is a list of supported cipher suites.
	// If CipherSuites is nil, a default list is used
	CipherSuites []CipherSuiteID

	// CustomCipherSuites is a list of CipherSuites that can be
	// provided by the user. This allow users to user Ciphers that are reserved
	// for private usage.
	CustomCipherSuites func() []CipherSuite

	// SignatureSchemes contains the signature and hash schemes that the peer requests to verify.
	SignatureSchemes []tls.SignatureScheme

	// SRTPProtectionProfiles are the supported protection profiles
	// Clients will send this via use_srtp and assert that the server properly responds
	// Servers will assert that clients send one of these profiles and will respond as needed
	SRTPProtectionProfiles []SRTPProtectionProfile

	// SRTPMasterKeyIdentifier value (if any) is sent via the use_srtp
	// extension for Clients and Servers
	SRTPMasterKeyIdentifier []byte

	// ClientAuth determines the server's policy for
	// TLS Client Authentication. The default is NoClientCert.
	ClientAuth ClientAuthType

	// RequireExtendedMasterSecret determines if the "Extended Master Secret" extension
	// should be disabled, requested, or required (default requested).
	ExtendedMasterSecret ExtendedMasterSecretType

	// FlightInterval controls how often we send outbound handshake messages
	// defaults to time.Second
	FlightInterval time.Duration

	// DisableRetransmitBackoff can be used to the disable the backoff feature
	// when sending outbound messages as specified in RFC 4347 4.2.4.1
	DisableRetransmitBackoff bool

	// PSK sets the pre-shared key used by this DTLS connection
	// If PSK is non-nil only PSK CipherSuites will be used
	PSK             PSKCallback
	PSKIdentityHint []byte

	// InsecureSkipVerify controls whether a client verifies the
	// server's certificate chain and host name.
	// If InsecureSkipVerify is true, TLS accepts any certificate
	// presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureSkipVerify bool

	// InsecureHashes allows the use of hashing algorithms that are known
	// to be vulnerable.
	InsecureHashes bool

	// VerifyPeerCertificate, if not nil, is called after normal
	// certificate verification by either a client or server. It
	// receives the certificate provided by the peer and also a flag
	// that tells if normal verification has succeedded. If it returns a
	// non-nil error, the handshake is aborted and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. If normal verification is disabled by
	// setting InsecureSkipVerify, or (for a server) when ClientAuth is
	// RequestClientCert or RequireAnyClientCert, then this callback will
	// be considered but the verifiedChains will always be nil.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyConnection, if not nil, is called after normal certificate
	// verification/PSK and after VerifyPeerCertificate by either a TLS client
	// or server. If it returns a non-nil error, the handshake is aborted
	// and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. This callback will run for all connections
	// regardless of InsecureSkipVerify or ClientAuth settings.
	VerifyConnection func(*State) error

	// RootCAs defines the set of root certificate authorities
	// that one peer uses when verifying the other peer's certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool

	// ClientCAs defines the set of root certificate authorities
	// that servers use if required to verify a client certificate
	// by the policy in ClientAuth.
	ClientCAs *x509.CertPool

	// ServerName is used to verify the hostname on the returned
	// certificates unless InsecureSkipVerify is given.
	ServerName string

	LoggerFactory logging.LoggerFactory

	// ConnectContextMaker is a function to make a context used in Dial(),
	// Client(), Server(), and Accept(). If nil, the default ConnectContextMaker
	// is used. It can be implemented as following.
	//
	// 	func ConnectContextMaker() (context.Context, func()) {
	// 		return context.WithTimeout(context.Background(), 30*time.Second)
	// 	}
	ConnectContextMaker func() (context.Context, func())

	// MTU is the length at which handshake messages will be fragmented to
	// fit within the maximum transmission unit (default is 1200 bytes)
	MTU int

	// ReplayProtectionWindow is the size of the replay attack protection window.
	// Duplication of the sequence number is checked in this window size.
	// Packet with sequence number older than this value compared to the latest
	// accepted packet will be discarded. (default is 64)
	ReplayProtectionWindow int

	// KeyLogWriter optionally specifies a destination for TLS master secrets
	// in NSS key log format that can be used to allow external programs
	// such as Wireshark to decrypt TLS connections.
	// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
	// Use of KeyLogWriter compromises security and should only be
	// used for debugging.
	KeyLogWriter io.Writer

	// SessionStore is the container to store session for resumption.
	SessionStore SessionStore

	// List of application protocols the peer supports, for ALPN
	SupportedProtocols []string

	// List of Elliptic Curves to use
	//
	// If an ECC ciphersuite is configured and EllipticCurves is empty
	// it will default to X25519, P-256, P-384 in this specific order.
	EllipticCurves []elliptic.Curve

	// GetCertificate returns a Certificate based on the given
	// ClientHelloInfo. It will only be called if the client supplies SNI
	// information or if Certificates is empty.
	//
	// If GetCertificate is nil or returns nil, then the certificate is
	// retrieved from NameToCertificate. If NameToCertificate is nil, the
	// best element of Certificates will be used.
	GetCertificate func(*ClientHelloInfo) (*tls.Certificate, error)

	// GetClientCertificate, if not nil, is called when a server requests a
	// certificate from a client. If set, the contents of Certificates will
	// be ignored.
	//
	// If GetClientCertificate returns an error, the handshake will be
	// aborted and that error will be returned. Otherwise
	// GetClientCertificate must return a non-nil Certificate. If
	// Certificate.Certificate is empty then no certificate will be sent to
	// the server. If this is unacceptable to the server then it may abort
	// the handshake.
	GetClientCertificate func(*CertificateRequestInfo) (*tls.Certificate, error)

	// InsecureSkipVerifyHello, if true and when acting as server, allow client to
	// skip hello verify phase and receive ServerHello after initial ClientHello.
	// This have implication on DoS attack resistance.
	InsecureSkipVerifyHello bool

	// ConnectionIDGenerator generates connection identifiers that should be
	// sent by the remote party if it supports the DTLS Connection Identifier
	// extension, as determined during the handshake. Generated connection
	// identifiers must always have the same length. Returning a zero-length
	// connection identifier indicates that the local party supports sending
	// connection identifiers but does not require the remote party to send
	// them. A nil ConnectionIDGenerator indicates that connection identifiers
	// are not supported.
	// https://datatracker.ietf.org/doc/html/rfc9146
	ConnectionIDGenerator func() []byte

	// PaddingLengthGenerator generates the number of padding bytes used to
	// inflate ciphertext size in order to obscure content size from observers.
	// The length of the content is passed to the generator such that both
	// deterministic and random padding schemes can be applied while not
	// exceeding maximum record size.
	// If no PaddingLengthGenerator is specified, padding will not be applied.
	// https://datatracker.ietf.org/doc/html/rfc9146#section-4
	PaddingLengthGenerator func(uint) uint

	// HelloRandomBytesGenerator generates custom client hello random bytes.
	HelloRandomBytesGenerator func() [handshake.RandomBytesLength]byte

	// Handshake hooks: hooks can be used for testing invalid messages,
	// mimicking other implementations or randomizing fields, which is valuable
	// for applications that need censorship-resistance by making
	// fingerprinting more difficult.

	// ClientHelloMessageHook, if not nil, is called when a Client Hello message is sent
	// from a client. The returned handshake message replaces the original message.
	ClientHelloMessageHook func(handshake.MessageClientHello) handshake.Message

	// ServerHelloMessageHook, if not nil, is called when a Server Hello message is sent
	// from a server. The returned handshake message replaces the original message.
	ServerHelloMessageHook func(handshake.MessageServerHello) handshake.Message

	// CertificateRequestMessageHook, if not nil, is called when a Certificate Request
	// message is sent from a server. The returned handshake message replaces the original message.
	CertificateRequestMessageHook func(handshake.MessageCertificateRequest) handshake.Message

	// OnConnectionAttempt is fired Whenever a connection attempt is made,
	// the server or application can call this callback function.
	// The callback function can then implement logic to handle the connection attempt, such as logging the attempt,
	// checking against a list of blocked IPs, or counting the attempts to prevent brute force attacks.
	// If the callback function returns an error, the connection attempt will be aborted.
	OnConnectionAttempt func(net.Addr) error
}

func (c *Config) includeCertificateSuites() bool {
	return c.PSK == nil || len(c.Certificates) > 0 || c.GetCertificate != nil || c.GetClientCertificate != nil
}

const defaultMTU = 1200 // bytes

var defaultCurves = []elliptic.Curve{elliptic.X25519, elliptic.P384}

// PSKCallback is called once we have the remote's PSKIdentityHint.
// If the remote provided none it will be nil.
type PSKCallback func([]byte) ([]byte, error)

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

// ClientAuthType enums.
const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

// ExtendedMasterSecretType declares the policy the client and server
// will follow for the Extended Master Secret extension.
type ExtendedMasterSecretType int

// ExtendedMasterSecretType enums.
const (
	RequestExtendedMasterSecret ExtendedMasterSecretType = iota
	RequireExtendedMasterSecret
	DisableExtendedMasterSecret
)

func validateConfig(config *Config) error {
	switch {
	case config == nil:
		return errNoConfigProvided
	case config.PSKIdentityHint != nil && config.PSK == nil:
		return errIdentityNoPSK
	}

	for _, cert := range config.Certificates {
		if cert.Certificate == nil {
			return errInvalidCertificate
		}
		if cert.PrivateKey != nil {
			signer, ok := cert.PrivateKey.(crypto.Signer)
			if !ok {
				return errInvalidPrivateKey
			}
			switch signer.Public().(type) {
			case ed25519.PublicKey:
			case *ecdsa.PublicKey:
			default:
				return errInvalidPrivateKey
			}
		}
	}

	_, err := parseCipherSuites(
		config.CipherSuites, config.CustomCipherSuites, config.includeCertificateSuites(), config.PSK != nil,
	)

	return err
}
