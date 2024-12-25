// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"errors"

	"github.com/pion/dtls/v3/pkg/protocol"
)

// Typed errors
var (
	errUnableToMarshalFragmented = &protocol.InternalError{Err: errors.New("unable to marshal fragmented handshakes")}
	errHandshakeMessageUnset     = &protocol.InternalError{Err: errors.New("handshake message unset, unable to marshal")}
	errBufferTooSmall            = &protocol.TemporaryError{Err: errors.New("buffer is too small")}
	errLengthMismatch            = &protocol.InternalError{Err: errors.New("data length and declared length do not match")}
	errInvalidClientKeyExchange  = &protocol.FatalError{Err: errors.New("unable to determine if ClientKeyExchange is a public key or PSK Identity")}
	errInvalidHashAlgorithm      = &protocol.FatalError{Err: errors.New("invalid hash algorithm")}
	errInvalidSignatureAlgorithm = &protocol.FatalError{Err: errors.New("invalid signature algorithm")}
	errCookieTooLong             = &protocol.FatalError{Err: errors.New("cookie must not be longer then 255 bytes")}
	errInvalidEllipticCurveType  = &protocol.FatalError{Err: errors.New("invalid or unknown elliptic curve type")}
	errInvalidNamedCurve         = &protocol.FatalError{Err: errors.New("invalid named curve")}
	errCipherSuiteUnset          = &protocol.FatalError{Err: errors.New("server hello can not be created without a cipher suite")}
	errCompressionMethodUnset    = &protocol.FatalError{Err: errors.New("server hello can not be created without a compression method")}
	errInvalidCompressionMethod  = &protocol.FatalError{Err: errors.New("invalid or unknown compression method")}
	errNotImplemented            = &protocol.InternalError{Err: errors.New("feature has not been implemented yet")}
)
