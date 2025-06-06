// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package recordlayer implements the TLS Record Layer https://tools.ietf.org/html/rfc5246#section-6
package recordlayer

import (
	"errors"

	"github.com/pion/dtls/v3/pkg/protocol"
)

var (
	// ErrInvalidPacketLength is returned when the packet length too small
	// or declared length do not match.
	ErrInvalidPacketLength = &protocol.TemporaryError{
		Err: errors.New("packet length and declared length do not match"),
	}

	errBufferTooSmall             = &protocol.TemporaryError{Err: errors.New("buffer is too small")}
	errSequenceNumberOverflow     = &protocol.InternalError{Err: errors.New("sequence number overflow")}
	errUnsupportedProtocolVersion = &protocol.FatalError{Err: errors.New("unsupported protocol version")}
	errInvalidContentType         = &protocol.TemporaryError{Err: errors.New("invalid content type")}
)
