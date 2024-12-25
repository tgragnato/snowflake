// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

// Typed errors
var (
	ErrConnClosed = &FatalError{Err: errors.New("conn is closed")}

	errDeadlineExceeded   = &TimeoutError{Err: fmt.Errorf("read/write timeout: %w", context.DeadlineExceeded)}
	errInvalidContentType = &TemporaryError{Err: errors.New("invalid content type")}

	errBufferTooSmall               = &TemporaryError{Err: errors.New("buffer is too small")}
	errContextUnsupported           = &TemporaryError{Err: errors.New("context is not supported for ExportKeyingMaterial")}
	errHandshakeInProgress          = &TemporaryError{Err: errors.New("handshake is in progress")}
	errReservedExportKeyingMaterial = &TemporaryError{Err: errors.New("ExportKeyingMaterial can not be used with a reserved label")}
	errApplicationDataEpochZero     = &TemporaryError{Err: errors.New("ApplicationData with epoch of 0")}
	errUnhandledContextType         = &TemporaryError{Err: errors.New("unhandled contentType")}

	errCertificateVerifyNoCertificate    = &FatalError{Err: errors.New("client sent certificate verify but we have no certificate to verify")}
	errCipherSuiteNoIntersection         = &FatalError{Err: errors.New("client+server do not support any shared cipher suites")}
	errClientCertificateNotVerified      = &FatalError{Err: errors.New("client sent certificate but did not verify it")}
	errClientCertificateRequired         = &FatalError{Err: errors.New("server required client verification, but got none")}
	errClientNoMatchingSRTPProfile       = &FatalError{Err: errors.New("server responded with SRTP Profile we do not support")}
	errClientRequiredButNoServerEMS      = &FatalError{Err: errors.New("client required Extended Master Secret extension, but server does not support it")}
	errCookieMismatch                    = &FatalError{Err: errors.New("client+server cookie does not match")}
	errIdentityNoPSK                     = &FatalError{Err: errors.New("PSK Identity Hint provided but PSK is nil")}
	errInvalidCertificate                = &FatalError{Err: errors.New("no certificate provided")}
	errInvalidCipherSuite                = &FatalError{Err: errors.New("invalid or unknown cipher suite")}
	errInvalidECDSASignature             = &FatalError{Err: errors.New("ECDSA signature contained zero or negative values")}
	errInvalidPrivateKey                 = &FatalError{Err: errors.New("invalid private key type")}
	errInvalidSignatureAlgorithm         = &FatalError{Err: errors.New("invalid signature algorithm")}
	errKeySignatureMismatch              = &FatalError{Err: errors.New("expected and actual key signature do not match")}
	errNilNextConn                       = &FatalError{Err: errors.New("Conn can not be created with a nil nextConn")}
	errNoAvailableCipherSuites           = &FatalError{Err: errors.New("connection can not be created, no CipherSuites satisfy this Config")}
	errNoAvailablePSKCipherSuite         = &FatalError{Err: errors.New("connection can not be created, pre-shared key present but no compatible CipherSuite")}
	errNoAvailableCertificateCipherSuite = &FatalError{Err: errors.New("connection can not be created, certificate present but no compatible CipherSuite")}
	errNoAvailableSignatureSchemes       = &FatalError{Err: errors.New("connection can not be created, no SignatureScheme satisfy this Config")}
	errNoCertificates                    = &FatalError{Err: errors.New("no certificates configured")}
	errNoConfigProvided                  = &FatalError{Err: errors.New("no config provided")}
	errNoSupportedEllipticCurves         = &FatalError{Err: errors.New("client requested zero or more elliptic curves that are not supported by the server")}
	errUnsupportedProtocolVersion        = &FatalError{Err: errors.New("unsupported protocol version")}
	errPSKAndIdentityMustBeSetForClient  = &FatalError{Err: errors.New("PSK and PSK Identity Hint must both be set for client")}
	errRequestedButNoSRTPExtension       = &FatalError{Err: errors.New("SRTP support was requested but server did not respond with use_srtp extension")}
	errServerNoMatchingSRTPProfile       = &FatalError{Err: errors.New("client requested SRTP but we have no matching profiles")}
	errServerRequiredButNoClientEMS      = &FatalError{Err: errors.New("server requires the Extended Master Secret extension, but the client does not support it")}
	errVerifyDataMismatch                = &FatalError{Err: errors.New("expected and actual verify data does not match")}
	errNotAcceptableCertificateChain     = &FatalError{Err: errors.New("certificate chain is not signed by an acceptable CA")}

	errInvalidFlight                     = &InternalError{Err: errors.New("invalid flight number")}
	errKeySignatureGenerateUnimplemented = &InternalError{Err: errors.New("unable to generate key signature, unimplemented")}
	errKeySignatureVerifyUnimplemented   = &InternalError{Err: errors.New("unable to verify key signature, unimplemented")}
	errLengthMismatch                    = &InternalError{Err: errors.New("data length and declared length do not match")}
	errSequenceNumberOverflow            = &InternalError{Err: errors.New("sequence number overflow")}
	errInvalidFSMTransition              = &InternalError{Err: errors.New("invalid state machine transition")}
	errFailedToAccessPoolReadBuffer      = &InternalError{Err: errors.New("failed to access pool read buffer")}
	errFragmentBufferOverflow            = &InternalError{Err: errors.New("fragment buffer overflow")}
)

// FatalError indicates that the DTLS connection is no longer available.
// It is mainly caused by wrong configuration of server or client.
type FatalError = protocol.FatalError

// InternalError indicates and internal error caused by the implementation, and the DTLS connection is no longer available.
// It is mainly caused by bugs or tried to use unimplemented features.
type InternalError = protocol.InternalError

// TemporaryError indicates that the DTLS connection is still available, but the request was failed temporary.
type TemporaryError = protocol.TemporaryError

// TimeoutError indicates that the request was timed out.
type TimeoutError = protocol.TimeoutError

// HandshakeError indicates that the handshake failed.
type HandshakeError = protocol.HandshakeError

// errInvalidCipherSuite indicates an attempt at using an unsupported cipher suite.
type invalidCipherSuiteError struct {
	id CipherSuiteID
}

func (e *invalidCipherSuiteError) Error() string {
	return fmt.Sprintf("CipherSuite with id(%d) is not valid", e.id)
}

func (e *invalidCipherSuiteError) Is(err error) bool {
	var other *invalidCipherSuiteError
	if errors.As(err, &other) {
		return e.id == other.id
	}
	return false
}

// errAlert wraps DTLS alert notification as an error
type alertError struct {
	*alert.Alert
}

func (e *alertError) Error() string {
	return fmt.Sprintf("alert: %s", e.Alert.String())
}

func (e *alertError) IsFatalOrCloseNotify() bool {
	return e.Level == alert.Fatal || e.Description == alert.CloseNotify
}

func (e *alertError) Is(err error) bool {
	var other *alertError
	if errors.As(err, &other) {
		return e.Level == other.Level && e.Description == other.Description
	}
	return false
}

// netError translates an error from underlying Conn to corresponding net.Error.
func netError(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Return io.EOF and context errors as is.
		return err
	}

	var (
		ne      net.Error
		opError *net.OpError
		se      *os.SyscallError
	)

	if errors.As(err, &opError) {
		if errors.As(opError, &se) {
			if se.Timeout() {
				return &TimeoutError{Err: err}
			}
			if isOpErrorTemporary(se) {
				return &TemporaryError{Err: err}
			}
		}
	}

	if errors.As(err, &ne) {
		return err
	}

	return &FatalError{Err: err}
}
