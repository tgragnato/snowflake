// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"

	"github.com/pion/dtls/v3/pkg/protocol"
)

var (
	// ErrALPNInvalidFormat is raised when the ALPN format is invalid.
	ErrALPNInvalidFormat = &protocol.FatalError{
		Err: errors.New("invalid alpn format"),
	}
	errALPNNoAppProto = &protocol.FatalError{
		Err: errors.New("no application protocol"),
	}
	errBufferTooSmall = &protocol.TemporaryError{
		Err: errors.New("buffer is too small"),
	}
	errInvalidExtensionType = &protocol.FatalError{
		Err: errors.New("invalid extension type"),
	}
	errInvalidSNIFormat = &protocol.FatalError{
		Err: errors.New("invalid server name format"),
	}
	errInvalidCIDFormat = &protocol.FatalError{
		Err: errors.New("invalid connection ID format"),
	}
	errLengthMismatch = &protocol.InternalError{
		Err: errors.New("data length and declared length do not match"),
	}
	errMasterKeyIdentifierTooLarge = &protocol.FatalError{
		Err: errors.New("master key identifier is over 255 bytes"),
	}
)
