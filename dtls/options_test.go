// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/transport/v4/dpipe"
)

func TestClientWithOptionsValidatesOptionValues(t *testing.T) {
	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	_, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(),
		WithExtendedMasterSecret(ExtendedMasterSecretType(-1)))
	if !errors.Is(err, dtlserrors.ErrInvalidExtendedMasterSecretType) {
		t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidExtendedMasterSecretType, err)
	}
}

func TestServerWithOptionsValidatesOptionValues(t *testing.T) {
	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	// Test invalid client auth type
	_, err := ServerWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(),
		WithClientAuth(ClientAuthType(-1)))
	if !errors.Is(err, dtlserrors.ErrInvalidClientAuthType) {
		t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidClientAuthType, err)
	}
}

func TestWithOptionsCreatesConn(t *testing.T) {
	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal("error: ", err)
	}

	client, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(),
		WithCertificates(cert),
		WithInsecureSkipVerify(true),
	)
	if err != nil {
		t.Fatal("error: ", err)
	}

	server, err := ServerWithOptions(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(),
		WithCertificates(cert),
		WithInsecureSkipVerify(true),
	)
	if err != nil {
		t.Fatal("error: ", err)
	}

	if err := client.Close(); err != nil {
		t.Fatal("error: ", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal("error: ", err)
	}
}

func newOptionsClient(t *testing.T, opts ...ClientOption) (*Conn, error) {
	t.Helper()

	ca, cb := dpipe.Pipe()
	t.Cleanup(func() {
		_ = ca.Close()
		_ = cb.Close()
	})

	client, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts...)
	if err == nil {
		t.Cleanup(func() {
			_ = client.Close()
		})
	}

	return client, err
}

func newOptionsServer(t *testing.T, opts ...ServerOption) (*Conn, error) {
	t.Helper()

	ca, cb := dpipe.Pipe()
	t.Cleanup(func() {
		_ = ca.Close()
		_ = cb.Close()
	})

	server, err := ServerWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts...)
	if err == nil {
		t.Cleanup(func() {
			_ = server.Close()
		})
	}

	return server, err
}

func clientOptionsError(t *testing.T, opts ...ClientOption) error {
	t.Helper()

	client, err := newOptionsClient(t, opts...)
	if client != nil {
		_ = client.Close()
	}

	return err
}

func serverOptionsError(t *testing.T, opts ...ServerOption) error {
	t.Helper()

	server, err := newOptionsServer(t, opts...)
	if server != nil {
		_ = server.Close()
	}

	return err
}

// TestEmptySliceOptionsReturnError verifies that functional options return errors
// for explicitly empty slices.
func TestEmptySliceOptionsReturnError(t *testing.T) {
	t.Run("EmptyCertificates", func(t *testing.T) {
		err := clientOptionsError(t, WithCertificates())
		if !errors.Is(err, dtlserrors.ErrEmptyCertificates) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptyCertificates, err)
		}

		err = serverOptionsError(t, WithCertificates())
		if !errors.Is(err, dtlserrors.ErrEmptyCertificates) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptyCertificates, err)
		}
	})

	t.Run("EmptyCipherSuites", func(t *testing.T) {
		err := clientOptionsError(t, WithCipherSuites())
		if !errors.Is(err, dtlserrors.ErrEmptyCipherSuites) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptyCipherSuites, err)
		}

		err = serverOptionsError(t, WithCipherSuites())
		if !errors.Is(err, dtlserrors.ErrEmptyCipherSuites) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptyCipherSuites, err)
		}
	})

	t.Run("EmptySignatureSchemes", func(t *testing.T) {
		err := clientOptionsError(t, WithSignatureSchemes())
		if !errors.Is(err, dtlserrors.ErrEmptySignatureSchemes) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptySignatureSchemes, err)
		}

		err = serverOptionsError(t, WithSignatureSchemes())
		if !errors.Is(err, dtlserrors.ErrEmptySignatureSchemes) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptySignatureSchemes, err)
		}
	})

	t.Run("EmptySRTPProtectionProfiles", func(t *testing.T) {
		err := clientOptionsError(t, WithSRTPProtectionProfiles())
		if !errors.Is(err, dtlserrors.ErrEmptySRTPProtectionProfiles) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptySRTPProtectionProfiles, err)
		}

		err = serverOptionsError(t, WithSRTPProtectionProfiles())
		if !errors.Is(err, dtlserrors.ErrEmptySRTPProtectionProfiles) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptySRTPProtectionProfiles, err)
		}
	})

	t.Run("EmptySupportedProtocols", func(t *testing.T) {
		err := clientOptionsError(t, WithSupportedProtocols())
		if !errors.Is(err, dtlserrors.ErrEmptySupportedProtocols) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptySupportedProtocols, err)
		}

		err = serverOptionsError(t, WithSupportedProtocols())
		if !errors.Is(err, dtlserrors.ErrEmptySupportedProtocols) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptySupportedProtocols, err)
		}
	})

	t.Run("EmptyEllipticCurves", func(t *testing.T) {
		err := clientOptionsError(t, WithEllipticCurves())
		if !errors.Is(err, dtlserrors.ErrEmptyEllipticCurves) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptyEllipticCurves, err)
		}

		err = serverOptionsError(t, WithEllipticCurves())
		if !errors.Is(err, dtlserrors.ErrEmptyEllipticCurves) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrEmptyEllipticCurves, err)
		}
	})
}

// TestNilCallbackOptionsReturnError verifies that functional options return errors
// for nil callbacks.
func TestNilCallbackOptionsReturnError(t *testing.T) {
	t.Run("NilCustomCipherSuites", func(t *testing.T) {
		err := clientOptionsError(t, WithCustomCipherSuites(nil))
		if !errors.Is(err, dtlserrors.ErrNilCustomCipherSuites) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilCustomCipherSuites, err)
		}

		err = serverOptionsError(t, WithCustomCipherSuites(nil))
		if !errors.Is(err, dtlserrors.ErrNilCustomCipherSuites) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilCustomCipherSuites, err)
		}
	})

	t.Run("NilPSKCallback", func(t *testing.T) {
		err := clientOptionsError(t, WithPSK(nil))
		if !errors.Is(err, dtlserrors.ErrNilPSKCallback) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilPSKCallback, err)
		}

		err = serverOptionsError(t, WithPSK(nil))
		if !errors.Is(err, dtlserrors.ErrNilPSKCallback) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilPSKCallback, err)
		}
	})

	t.Run("NilVerifyPeerCertificate", func(t *testing.T) {
		err := clientOptionsError(t, WithVerifyPeerCertificate(nil))
		if !errors.Is(err, dtlserrors.ErrNilVerifyPeerCertificate) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilVerifyPeerCertificate, err)
		}

		err = serverOptionsError(t, WithVerifyPeerCertificate(nil))
		if !errors.Is(err, dtlserrors.ErrNilVerifyPeerCertificate) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilVerifyPeerCertificate, err)
		}
	})

	t.Run("NilVerifyConnection", func(t *testing.T) {
		err := clientOptionsError(t, WithVerifyConnection(nil))
		if !errors.Is(err, dtlserrors.ErrNilVerifyConnection) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilVerifyConnection, err)
		}

		err = serverOptionsError(t, WithVerifyConnection(nil))
		if !errors.Is(err, dtlserrors.ErrNilVerifyConnection) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilVerifyConnection, err)
		}
	})

	t.Run("NilGetClientCertificate", func(t *testing.T) {
		err := clientOptionsError(t, WithGetClientCertificate(nil))
		if !errors.Is(err, dtlserrors.ErrNilGetClientCertificate) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilGetClientCertificate, err)
		}

		err = serverOptionsError(t, WithGetClientCertificate(nil))
		if !errors.Is(err, dtlserrors.ErrNilGetClientCertificate) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilGetClientCertificate, err)
		}
	})

	t.Run("NilConnectionIDGenerator", func(t *testing.T) {
		err := clientOptionsError(t, WithConnectionIDGenerator(nil))
		if !errors.Is(err, dtlserrors.ErrNilConnectionIDGenerator) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilConnectionIDGenerator, err)
		}

		err = serverOptionsError(t, WithConnectionIDGenerator(nil))
		if !errors.Is(err, dtlserrors.ErrNilConnectionIDGenerator) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilConnectionIDGenerator, err)
		}
	})

	t.Run("NilPaddingLengthGenerator", func(t *testing.T) {
		err := clientOptionsError(t, WithPaddingLengthGenerator(nil))
		if !errors.Is(err, dtlserrors.ErrNilPaddingLengthGenerator) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilPaddingLengthGenerator, err)
		}

		err = serverOptionsError(t, WithPaddingLengthGenerator(nil))
		if !errors.Is(err, dtlserrors.ErrNilPaddingLengthGenerator) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilPaddingLengthGenerator, err)
		}
	})

	t.Run("NilHelloRandomBytesGenerator", func(t *testing.T) {
		err := clientOptionsError(t, WithHelloRandomBytesGenerator(nil))
		if !errors.Is(err, dtlserrors.ErrNilHelloRandomBytesGenerator) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilHelloRandomBytesGenerator, err)
		}

		err = serverOptionsError(t, WithHelloRandomBytesGenerator(nil))
		if !errors.Is(err, dtlserrors.ErrNilHelloRandomBytesGenerator) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilHelloRandomBytesGenerator, err)
		}
	})

	t.Run("NilClientHelloMessageHook", func(t *testing.T) {
		err := clientOptionsError(t, WithClientHelloMessageHook(nil))
		if !errors.Is(err, dtlserrors.ErrNilClientHelloMessageHook) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilClientHelloMessageHook, err)
		}

		err = serverOptionsError(t, WithClientHelloMessageHook(nil))
		if !errors.Is(err, dtlserrors.ErrNilClientHelloMessageHook) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilClientHelloMessageHook, err)
		}
	})
}

// TestServerOnlyNilCallbackOptionsReturnError verifies server-only options
// return errors for nil callbacks.
func TestServerOnlyNilCallbackOptionsReturnError(t *testing.T) {
	t.Run("NilGetCertificate", func(t *testing.T) {
		err := serverOptionsError(t, WithGetCertificate(nil))
		if !errors.Is(err, dtlserrors.ErrNilGetCertificate) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilGetCertificate, err)
		}
	})

	t.Run("NilServerHelloMessageHook", func(t *testing.T) {
		err := serverOptionsError(t, WithServerHelloMessageHook(nil))
		if !errors.Is(err, dtlserrors.ErrNilServerHelloMessageHook) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilServerHelloMessageHook, err)
		}
	})

	t.Run("NilCertificateRequestMessageHook", func(t *testing.T) {
		err := serverOptionsError(t, WithCertificateRequestMessageHook(nil))
		if !errors.Is(err, dtlserrors.ErrNilCertificateRequestMessageHook) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilCertificateRequestMessageHook, err)
		}
	})

	t.Run("NilOnConnectionAttempt", func(t *testing.T) {
		err := serverOptionsError(t, WithOnConnectionAttempt(nil))
		if !errors.Is(err, dtlserrors.ErrNilOnConnectionAttempt) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNilOnConnectionAttempt, err)
		}
	})
}

// TestInvalidNumericOptionsReturnError verifies that invalid numeric values
// return appropriate errors.
func TestInvalidNumericOptionsReturnError(t *testing.T) {
	t.Run("InvalidFlightInterval", func(t *testing.T) {
		err := clientOptionsError(t, WithFlightInterval(0))
		if !errors.Is(err, dtlserrors.ErrInvalidFlightInterval) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidFlightInterval, err)
		}

		err = clientOptionsError(t, WithFlightInterval(-time.Second))
		if !errors.Is(err, dtlserrors.ErrInvalidFlightInterval) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidFlightInterval, err)
		}

		err = serverOptionsError(t, WithFlightInterval(0))
		if !errors.Is(err, dtlserrors.ErrInvalidFlightInterval) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidFlightInterval, err)
		}
	})

	t.Run("InvalidMTU", func(t *testing.T) {
		err := clientOptionsError(t, WithMTU(0))
		if !errors.Is(err, dtlserrors.ErrInvalidMTU) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidMTU, err)
		}

		err = clientOptionsError(t, WithMTU(-100))
		if !errors.Is(err, dtlserrors.ErrInvalidMTU) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidMTU, err)
		}

		err = serverOptionsError(t, WithMTU(0))
		if !errors.Is(err, dtlserrors.ErrInvalidMTU) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidMTU, err)
		}
	})

	t.Run("InvalidReplayProtectionWindow", func(t *testing.T) {
		err := clientOptionsError(t, WithReplayProtectionWindow(-1))
		if !errors.Is(err, dtlserrors.ErrInvalidReplayProtectionWindow) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidReplayProtectionWindow, err)
		}

		err = serverOptionsError(t, WithReplayProtectionWindow(-1))
		if !errors.Is(err, dtlserrors.ErrInvalidReplayProtectionWindow) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidReplayProtectionWindow, err)
		}
	})

	t.Run("InvalidClientAuthType", func(t *testing.T) {
		err := serverOptionsError(t, WithClientAuth(ClientAuthType(-1)))
		if !errors.Is(err, dtlserrors.ErrInvalidClientAuthType) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidClientAuthType, err)
		}

		err = serverOptionsError(t, WithClientAuth(ClientAuthType(100)))
		if !errors.Is(err, dtlserrors.ErrInvalidClientAuthType) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidClientAuthType, err)
		}
	})

	t.Run("InvalidExtendedMasterSecretType", func(t *testing.T) {
		err := clientOptionsError(t, WithExtendedMasterSecret(ExtendedMasterSecretType(-1)))
		if !errors.Is(err, dtlserrors.ErrInvalidExtendedMasterSecretType) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidExtendedMasterSecretType, err)
		}

		err = serverOptionsError(t, WithExtendedMasterSecret(ExtendedMasterSecretType(100)))
		if !errors.Is(err, dtlserrors.ErrInvalidExtendedMasterSecretType) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrInvalidExtendedMasterSecretType, err)
		}
	})

	t.Run("InvalidVersions", func(t *testing.T) {
		err := clientOptionsError(t, WithMinVersion(protocol.Version{}))
		if !errors.Is(err, dtlserrors.ErrUnsupportedProtocolVersion) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrUnsupportedProtocolVersion, err)
		}

		err = clientOptionsError(t, WithMaxVersion(protocol.Version{}))
		if !errors.Is(err, dtlserrors.ErrUnsupportedProtocolVersion) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrUnsupportedProtocolVersion, err)
		}
	})
}

func TestX25519MLKEM768RequiresDTLS13(t *testing.T) {
	t.Run("DTLS12OnlyClient", func(t *testing.T) {
		err := clientOptionsError(t,
			WithMaxVersion(protocol.Version1_2),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		if !errors.Is(err, dtlserrors.ErrUnsupportedEllipticCurveVersion) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrUnsupportedEllipticCurveVersion, err)
		}
	})

	t.Run("DTLS12OnlyServer", func(t *testing.T) {
		err := serverOptionsError(t,
			WithMaxVersion(protocol.Version1_2),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		if !errors.Is(err, dtlserrors.ErrUnsupportedEllipticCurveVersion) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrUnsupportedEllipticCurveVersion, err)
		}
	})

	t.Run("DualStackMLKEMOnlyClient", func(t *testing.T) {
		err := clientOptionsError(t,
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		if !errors.Is(err, dtlserrors.ErrUnsupportedEllipticCurveVersion) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrUnsupportedEllipticCurveVersion, err)
		}
	})

	t.Run("DualStackMLKEMOnlyServer", func(t *testing.T) {
		err := serverOptionsError(t,
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		if !errors.Is(err, dtlserrors.ErrUnsupportedEllipticCurveVersion) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrUnsupportedEllipticCurveVersion, err)
		}
	})

	t.Run("DualStackWithClassicalFallback", func(t *testing.T) {
		_, err := newOptionsClient(t,
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768, elliptic.X25519),
		)
		if err != nil {
			t.Fatal("error: ", err)
		}

		_, err = newOptionsServer(t,
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768, elliptic.X25519),
		)
		if err != nil {
			t.Fatal("error: ", err)
		}
	})

	t.Run("DTLS13OnlyClient", func(t *testing.T) {
		_, err := newOptionsClient(t,
			WithMinVersion(protocol.Version1_3),
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		if err != nil {
			t.Fatal("error: ", err)
		}
	})

	t.Run("DTLS13OnlyServer", func(t *testing.T) {
		_, err := newOptionsServer(t,
			WithMinVersion(protocol.Version1_3),
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		if err != nil {
			t.Fatal("error: ", err)
		}
	})
}

// TestDefaultsAreApplied verifies that defaults are applied before options.
func TestDefaultsAreApplied(t *testing.T) {
	t.Run("ClientDefaults", func(t *testing.T) {
		client, err := newOptionsClient(t)
		if err != nil {
			t.Fatal("error: ", err)
		}

		config := client.handshakeConfig
		if dtlsconfig.ExtendedMasterSecretType(RequestExtendedMasterSecret) != config.ExtendedMasterSecret {
			t.Fatalf("expected %v, got %v", dtlsconfig.ExtendedMasterSecretType(RequestExtendedMasterSecret), config.ExtendedMasterSecret)
		}
		if time.Second != config.InitialRetransmitInterval {
			t.Fatalf("expected %v, got %v", time.Second, config.InitialRetransmitInterval)
		}
		if defaultMTU != client.maximumTransmissionUnit {
			t.Fatalf("expected %v, got %v", defaultMTU, client.maximumTransmissionUnit)
		}
		if uint(defaultReplayProtectionWindow) != client.replayProtectionWindow {
			t.Fatalf("expected %v, got %v", uint(defaultReplayProtectionWindow), client.replayProtectionWindow)
		}
	})

	t.Run("ServerDefaults", func(t *testing.T) {
		server, err := newOptionsServer(t)
		if err != nil {
			t.Fatal("error: ", err)
		}

		config := server.handshakeConfig
		if dtlsconfig.ExtendedMasterSecretType(RequestExtendedMasterSecret) != config.ExtendedMasterSecret {
			t.Fatalf("expected %v, got %v", dtlsconfig.ExtendedMasterSecretType(RequestExtendedMasterSecret), config.ExtendedMasterSecret)
		}
		if time.Second != config.InitialRetransmitInterval {
			t.Fatalf("expected %v, got %v", time.Second, config.InitialRetransmitInterval)
		}
		if defaultMTU != server.maximumTransmissionUnit {
			t.Fatalf("expected %v, got %v", defaultMTU, server.maximumTransmissionUnit)
		}
		if uint(defaultReplayProtectionWindow) != server.replayProtectionWindow {
			t.Fatalf("expected %v, got %v", uint(defaultReplayProtectionWindow), server.replayProtectionWindow)
		}
	})
}

// TestOptionsOverrideDefaults verifies that options override defaults.
func TestOptionsOverrideDefaults(t *testing.T) {
	t.Run("ClientOptionsOverrideDefaults", func(t *testing.T) {
		client, err := newOptionsClient(t,
			WithExtendedMasterSecret(RequireExtendedMasterSecret),
			WithFlightInterval(2*time.Second),
			WithMTU(1500),
			WithReplayProtectionWindow(128),
		)
		if err != nil {
			t.Fatal("error: ", err)
		}

		config := client.handshakeConfig
		if dtlsconfig.ExtendedMasterSecretType(RequireExtendedMasterSecret) != config.ExtendedMasterSecret {
			t.Fatalf("expected %v, got %v", dtlsconfig.ExtendedMasterSecretType(RequireExtendedMasterSecret), config.ExtendedMasterSecret)
		}
		if 2*time.Second != config.InitialRetransmitInterval {
			t.Fatalf("expected %v, got %v", 2*time.Second, config.InitialRetransmitInterval)
		}
		if 1500 != client.maximumTransmissionUnit {
			t.Fatalf("expected %v, got %v", 1500, client.maximumTransmissionUnit)
		}
		if uint(128) != client.replayProtectionWindow {
			t.Fatalf("expected %v, got %v", uint(128), client.replayProtectionWindow)
		}
	})

	t.Run("ServerOptionsOverrideDefaults", func(t *testing.T) {
		server, err := newOptionsServer(t,
			WithExtendedMasterSecret(DisableExtendedMasterSecret),
			WithFlightInterval(3*time.Second),
			WithMTU(1400),
			WithReplayProtectionWindow(256),
			WithClientAuth(RequireAndVerifyClientCert),
		)
		if err != nil {
			t.Fatal("error: ", err)
		}

		config := server.handshakeConfig
		if dtlsconfig.ExtendedMasterSecretType(DisableExtendedMasterSecret) != config.ExtendedMasterSecret {
			t.Fatalf("expected %v, got %v", dtlsconfig.ExtendedMasterSecretType(DisableExtendedMasterSecret), config.ExtendedMasterSecret)
		}
		if 3*time.Second != config.InitialRetransmitInterval {
			t.Fatalf("expected %v, got %v", 3*time.Second, config.InitialRetransmitInterval)
		}
		if 1400 != server.maximumTransmissionUnit {
			t.Fatalf("expected %v, got %v", 1400, server.maximumTransmissionUnit)
		}
		if uint(256) != server.replayProtectionWindow {
			t.Fatalf("expected %v, got %v", uint(256), server.replayProtectionWindow)
		}
		if dtlsconfig.ClientAuthType(RequireAndVerifyClientCert) != config.ClientAuth {
			t.Fatalf("expected %v, got %v", dtlsconfig.ClientAuthType(RequireAndVerifyClientCert), config.ClientAuth)
		}
	})
}

// TestValidOptionsSucceed verifies that valid options don't return errors.
func TestValidOptionsSucceed(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal("error: ", err)
	}

	t.Run("ClientValidOptions", func(t *testing.T) {
		client, err := newOptionsClient(t,
			WithCertificates(cert),
			WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
			WithSignatureSchemes(tls.ECDSAWithP256AndSHA256),
			WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80),
			WithEllipticCurves(elliptic.P256),
			WithSupportedProtocols("h2", "http/1.1"),
			WithInsecureSkipVerify(true),
			WithServerName("example.com"),
		)
		if err != nil {
			t.Fatal("error: ", err)
		}

		config := client.handshakeConfig
		if len(config.LocalCertificates) != 1 {
			t.Fatalf("expected len %d, got %d", 1, len(config.LocalCertificates))
		}
		if len(config.LocalCipherSuites) != 1 {
			t.Fatalf("expected len %d, got %d", 1, len(config.LocalCipherSuites))
		}
		if len(config.LocalSignatureSchemes) != 1 {
			t.Fatalf("expected len %d, got %d", 1, len(config.LocalSignatureSchemes))
		}
		if len(config.LocalSRTPProtectionProfiles) != 1 {
			t.Fatalf("expected len %d, got %d", 1, len(config.LocalSRTPProtectionProfiles))
		}
		if len(config.EllipticCurves) != 1 {
			t.Fatalf("expected len %d, got %d", 1, len(config.EllipticCurves))
		}
		if len(config.SupportedProtocols) != 2 {
			t.Fatalf("expected len %d, got %d", 2, len(config.SupportedProtocols))
		}
		if !config.InsecureSkipVerify {
			t.Fatal("condition is false")
		}
		if "example.com" != config.ServerName {
			t.Fatalf("expected %v, got %v", "example.com", config.ServerName)
		}
	})

	t.Run("ServerValidOptions", func(t *testing.T) {
		server, err := newOptionsServer(t,
			WithCertificates(cert),
			WithClientAuth(RequireAndVerifyClientCert),
			WithInsecureSkipVerifyHello(true),
			WithListenConfig(net.ListenConfig{
				Control: func(network, address string, c syscall.RawConn) error {
					return nil
				},
			}),
		)
		if err != nil {
			t.Fatal("error: ", err)
		}

		config := server.handshakeConfig
		if len(config.LocalCertificates) != 1 {
			t.Fatalf("expected len %d, got %d", 1, len(config.LocalCertificates))
		}
		if dtlsconfig.ClientAuthType(RequireAndVerifyClientCert) != config.ClientAuth {
			t.Fatalf("expected %v, got %v", dtlsconfig.ClientAuthType(RequireAndVerifyClientCert), config.ClientAuth)
		}
		if !config.InsecureSkipHelloVerify {
			t.Fatal("condition is false")
		}
	})
}

// TestOptionImmutability verifies that modifying slices after passing them to options
// does not affect the built config.
func TestOptionImmutability(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal("error: ", err)
	}

	t.Run("certificates", func(t *testing.T) {
		certs := []tls.Certificate{cert}
		client, err := newOptionsClient(t, WithCertificates(certs...))
		if err != nil {
			t.Fatal("error: ", err)
		}

		_ = append(certs, cert)

		if len(client.handshakeConfig.LocalCertificates) != 1 {
			t.Fatalf("expected len %d, got %d", 1, len(client.handshakeConfig.LocalCertificates))
		}
	})

	t.Run("cipherSuites", func(t *testing.T) {
		suites := []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
		client, err := newOptionsClient(t, WithCipherSuites(suites...))
		if err != nil {
			t.Fatal("error: ", err)
		}

		suites[0] = TLS_PSK_WITH_CHACHA20_POLY1305_SHA256

		if TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 != client.handshakeConfig.LocalCipherSuites[0].ID() {
			t.Fatalf("expected %v, got %v", TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, client.handshakeConfig.LocalCipherSuites[0].ID())
		}
	})

	t.Run("signatureSchemes", func(t *testing.T) {
		schemes := []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
		client, err := newOptionsClient(t, WithSignatureSchemes(schemes...))
		if err != nil {
			t.Fatal("error: ", err)
		}

		schemes[0] = tls.ECDSAWithP384AndSHA384

		expected, err := signaturehash.ParseSignatureSchemes([]tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}, false)
		if err != nil {
			t.Fatal("error: ", err)
		}
		if expected[0] != client.handshakeConfig.LocalSignatureSchemes[0] {
			t.Fatalf("expected %v, got %v", expected[0], client.handshakeConfig.LocalSignatureSchemes[0])
		}
	})

	t.Run("srtpProtectionProfiles", func(t *testing.T) {
		profiles := []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80}
		client, err := newOptionsClient(t, WithSRTPProtectionProfiles(profiles...))
		if err != nil {
			t.Fatal("error: ", err)
		}

		profiles[0] = SRTP_AES128_CM_HMAC_SHA1_32

		if SRTP_AES128_CM_HMAC_SHA1_80 != client.handshakeConfig.LocalSRTPProtectionProfiles[0] {
			t.Fatalf("expected %v, got %v", SRTP_AES128_CM_HMAC_SHA1_80, client.handshakeConfig.LocalSRTPProtectionProfiles[0])
		}
	})

	t.Run("SupportedProtocols", func(t *testing.T) {
		protocols := []string{"h2", "http/1.1"}
		client, err := newOptionsClient(t, WithSupportedProtocols(protocols...))
		if err != nil {
			t.Fatal("error: ", err)
		}

		protocols[0] = "grpc"

		if "h2" != client.handshakeConfig.SupportedProtocols[0] {
			t.Fatalf("expected %v, got %v", "h2", client.handshakeConfig.SupportedProtocols[0])
		}
		if "http/1.1" != client.handshakeConfig.SupportedProtocols[1] {
			t.Fatalf("expected %v, got %v", "http/1.1", client.handshakeConfig.SupportedProtocols[1])
		}
	})

	t.Run("EllipticCurves", func(t *testing.T) {
		curves := []elliptic.Curve{elliptic.P256}
		client, err := newOptionsClient(t, WithEllipticCurves(curves...))
		if err != nil {
			t.Fatal("error: ", err)
		}

		curves[0] = elliptic.P384

		if elliptic.P256 != client.handshakeConfig.EllipticCurves[0] {
			t.Fatalf("expected %v, got %v", elliptic.P256, client.handshakeConfig.EllipticCurves[0])
		}
	})

	t.Run("pskIdentityHint", func(t *testing.T) {
		hint := []byte("test-hint")
		client, err := newOptionsClient(t,
			WithPSK(func([]byte) ([]byte, error) { return nil, nil }),
			WithPSKIdentityHint(hint),
			WithCipherSuites(TLS_PSK_WITH_CHACHA20_POLY1305_SHA256),
		)
		if err != nil {
			t.Fatal("error: ", err)
		}

		hint[0] = 'X'

		if bytes.Equal([]byte("test-hint"), client.handshakeConfig.LocalPSKIdentityHint) != true {
			t.Fatalf("expected %v, got %v", []byte("test-hint"), client.handshakeConfig.LocalPSKIdentityHint)
		}
	})

	t.Run("srtpMasterKeyIdentifier", func(t *testing.T) {
		identifier := []byte{0x01, 0x02, 0x03}
		client, err := newOptionsClient(t, WithSRTPMasterKeyIdentifier(identifier))
		if err != nil {
			t.Fatal("error: ", err)
		}

		identifier[0] = 0xFF

		if bytes.Equal([]byte{0x01, 0x02, 0x03}, client.handshakeConfig.LocalSRTPMasterKeyIdentifier) != true {
			t.Fatalf("expected %v, got %v", []byte{0x01, 0x02, 0x03}, client.handshakeConfig.LocalSRTPMasterKeyIdentifier)
		}
	})
}
