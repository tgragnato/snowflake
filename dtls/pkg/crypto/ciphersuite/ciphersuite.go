// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ciphersuite provides the crypto operations needed for a DTLS CipherSuite
package ciphersuite

import (
	"encoding/binary"
	"errors"

	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"golang.org/x/crypto/cryptobyte"
)

const (
	// 8 bytes of 0xff.
	// https://datatracker.ietf.org/doc/html/rfc9146#name-record-payload-protection
	seqNumPlaceholder = 0xffffffffffffffff
)

var (
	errNotEnoughRoomForNonce = &protocol.InternalError{Err: errors.New("buffer not long enough to contain nonce")}
	errDecryptPacket         = &protocol.TemporaryError{Err: errors.New("failed to decrypt packet")}
)

func generateAEADAdditionalData(h *recordlayer.Header, payloadLen int) []byte {
	var additionalData [13]byte

	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(additionalData[:], h.SequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], h.Epoch)
	additionalData[8] = byte(h.ContentType)
	additionalData[9] = h.Version.Major
	additionalData[10] = h.Version.Minor
	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(payloadLen))

	return additionalData[:]
}

// generateAEADAdditionalDataCID generates additional data for AEAD ciphers
// according to https://datatracker.ietf.org/doc/html/rfc9146#name-aead-ciphers
func generateAEADAdditionalDataCID(h *recordlayer.Header, payloadLen int) []byte {
	var b cryptobyte.Builder

	b.AddUint64(seqNumPlaceholder)
	b.AddUint8(uint8(protocol.ContentTypeConnectionID))
	b.AddUint8(uint8(len(h.ConnectionID)))
	b.AddUint8(uint8(protocol.ContentTypeConnectionID))
	b.AddUint8(h.Version.Major)
	b.AddUint8(h.Version.Minor)
	b.AddUint16(h.Epoch)
	util.AddUint48(&b, h.SequenceNumber)
	b.AddBytes(h.ConnectionID)
	b.AddUint16(uint16(payloadLen))

	return b.BytesOrPanic()
}
