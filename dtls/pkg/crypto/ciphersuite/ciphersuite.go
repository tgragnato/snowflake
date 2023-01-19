// Package ciphersuite provides the crypto operations needed for a DTLS CipherSuite
package ciphersuite

import (
	"encoding/binary"
	"errors"

	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
)

var (
	errNotEnoughRoomForNonce = &protocol.InternalError{Err: errors.New("buffer not long enough to contain nonce")} //nolint:goerr113
	errDecryptPacket         = &protocol.TemporaryError{Err: errors.New("failed to decrypt packet")}               //nolint:goerr113
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
