// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

type oversizedPlaintextContent13 struct{}

func (oversizedPlaintextContent13) ContentType() protocol.ContentType {
	return protocol.ContentTypeAlert
}

func (oversizedPlaintextContent13) Marshal() ([]byte, error) {
	return make([]byte, maxDTLSPlaintextRecordLen+1), nil
}

func (oversizedPlaintextContent13) Unmarshal([]byte) error {
	return nil
}

func ciphertext13Payload(seed byte) []byte {
	out := make([]byte, minDTLSCiphertextRecordLen)
	for i := range out {
		out[i] = seed + byte(i)
	}

	return out
}

func TestPlaintextRecord13RoundTrip(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{
			Version: protocol.Version1_2,
		},
		Content: &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify},
	}

	raw, err := record.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte{
		0x15, 0xfe, 0xfd,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x02,
		0x01, 0x00,
	}, raw) {
		t.Fatalf("expected %v, got %v", []byte{
			0x15, 0xfe, 0xfd,
			0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x02,
			0x01, 0x00,
		}, raw)
	}

	var roundTrip PlaintextRecord13
	if roundTrip.Unmarshal(raw) != nil {
		t.Fatal(roundTrip.Unmarshal(raw))
	}
	if protocol.ContentTypeAlert != roundTrip.Header.ContentType {
		t.Fatalf("expected %v, got %v", protocol.ContentTypeAlert, roundTrip.Header.ContentType)
	}
	if protocol.Version1_2 != roundTrip.Header.Version {
		t.Fatalf("expected %v, got %v", protocol.Version1_2, roundTrip.Header.Version)
	}
	if uint16(0) != roundTrip.Header.Epoch {
		t.Fatalf("expected %v, got %v", uint16(0), roundTrip.Header.Epoch)
	}
	if uint16(2) != roundTrip.Header.ContentLen {
		t.Fatalf("expected %v, got %v", uint16(2), roundTrip.Header.ContentLen)
	}

	got, ok := roundTrip.Content.(*alert.Alert)
	if !ok {
		t.Fatal("expected true")
	}
	if alert.Warning != got.Level {
		t.Fatalf("expected %v, got %v", alert.Warning, got.Level)
	}
	if alert.CloseNotify != got.Description {
		t.Fatalf("expected %v, got %v", alert.CloseNotify, got.Description)
	}
}

func TestPlaintextRecord13ACKRoundTrip(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{
			Version: protocol.Version1_2,
		},
		Content: &protocol.ACK{
			Records: []protocol.RecordNumber{
				{Epoch: 2, SequenceNumber: 3},
			},
		},
	}

	raw, err := record.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if protocol.ContentTypeACK != record.Header.ContentType {
		t.Fatalf("expected %v, got %v", protocol.ContentTypeACK, record.Header.ContentType)
	}
	if uint16(18) != record.Header.ContentLen {
		t.Fatalf("expected %v, got %v", uint16(18), record.Header.ContentLen)
	}

	var roundTrip PlaintextRecord13
	if roundTrip.Unmarshal(raw) != nil {
		t.Fatal(roundTrip.Unmarshal(raw))
	}
	if protocol.ContentTypeACK != roundTrip.Header.ContentType {
		t.Fatalf("expected %v, got %v", protocol.ContentTypeACK, roundTrip.Header.ContentType)
	}

	got, ok := roundTrip.Content.(*protocol.ACK)
	if !ok {
		t.Fatal("expected true")
	}
	if !reflect.DeepEqual([]protocol.RecordNumber{{Epoch: 2, SequenceNumber: 3}}, got.Records) {
		t.Fatalf("expected %v, got %v", []protocol.RecordNumber{{Epoch: 2, SequenceNumber: 3}}, got.Records)
	}
}

func TestPlaintextRecord13RejectsProtectedEpoch(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{
			Version: protocol.Version1_2,
			Epoch:   1,
		},
		Content: &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify},
	}

	_, err := record.Marshal()
	if !errors.Is(err, dtlserrors.ErrInvalidEpoch) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidEpoch, err)
	}
}

func TestPlaintextRecord13MarshalRejectsUnsupportedDTLS10Version(t *testing.T) {
	// RFC 9147 permits DTLS 1.0 only for initial-ClientHello compatibility,
	// but Pion does not support DTLS 1.0.
	record := &PlaintextRecord13{
		Header:  Header{Version: protocol.Version1_0},
		Content: &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify},
	}

	_, err := record.Marshal()
	if !errors.Is(err, dtlserrors.ErrUnsupportedProtocolVersion) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrUnsupportedProtocolVersion, err)
	}
}

func TestPlaintextRecord13UnmarshalIgnoresLegacyRecordVersion(t *testing.T) {
	var roundTrip PlaintextRecord13
	err := roundTrip.Unmarshal([]byte{
		0x15, 0x01, 0x02,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x02,
		0x01, 0x00,
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedVersion := protocol.Version{Major: 0x01, Minor: 0x02}
	if expectedVersion != roundTrip.Header.Version {
		t.Fatalf("expected version %v, got %v", expectedVersion, roundTrip.Header.Version)
	}

	got, ok := roundTrip.Content.(*alert.Alert)
	if !ok {
		t.Fatal("expected true")
	}
	if alert.Warning != got.Level {
		t.Fatalf("expected %v, got %v", alert.Warning, got.Level)
	}
	if alert.CloseNotify != got.Description {
		t.Fatalf("expected %v, got %v", alert.CloseNotify, got.Description)
	}
}

func TestPlaintextRecord13AllowsDTLS10LegacyVersionForInitialClientHello(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{Version: protocol.Version1_0},
		Content: &handshake.Handshake{
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				CompressionMethods: []*protocol.CompressionMethod{{}},
			},
		},
	}

	raw, err := record.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if protocol.Version1_0 != record.Header.Version {
		t.Fatalf("expected %v, got %v", protocol.Version1_0, record.Header.Version)
	}

	var roundTrip PlaintextRecord13
	if roundTrip.Unmarshal(raw) != nil {
		t.Fatal(roundTrip.Unmarshal(raw))
	}

	gotHandshake, ok := roundTrip.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	if handshake.TypeClientHello != gotHandshake.Header.Type {
		t.Fatalf("expected %v, got %v", handshake.TypeClientHello, gotHandshake.Header.Type)
	}
	if uint16(0) != gotHandshake.Header.MessageSequence {
		t.Fatalf("expected %v, got %v", uint16(0), gotHandshake.Header.MessageSequence)
	}
	_, ok = gotHandshake.Message.(*handshake.MessageClientHello)
	if !ok {
		t.Fatal("expected true")
	}
}

func TestPlaintextRecord13MarshalRejectsDTLS10LegacyVersionForNonInitialClientHello(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{Version: protocol.Version1_0},
		Content: &handshake.Handshake{
			Header: handshake.Header{MessageSequence: 1},
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				CompressionMethods: []*protocol.CompressionMethod{{}},
			},
		},
	}

	_, err := record.Marshal()
	if !errors.Is(err, dtlserrors.ErrUnsupportedProtocolVersion) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrUnsupportedProtocolVersion, err)
	}
}

func TestPlaintextRecord13UnmarshalAcceptsDTLS10LegacyVersionForNonInitialClientHello(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{Version: protocol.Version1_2},
		Content: &handshake.Handshake{
			Header: handshake.Header{MessageSequence: 1},
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				CompressionMethods: []*protocol.CompressionMethod{{}},
			},
		},
	}

	raw, err := record.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	raw[1], raw[2] = protocol.Version1_0.Major, protocol.Version1_0.Minor

	var roundTrip PlaintextRecord13
	if roundTrip.Unmarshal(raw) != nil {
		t.Fatal(roundTrip.Unmarshal(raw))
	}
	if protocol.Version1_0 != roundTrip.Header.Version {
		t.Fatalf("expected %v, got %v", protocol.Version1_0, roundTrip.Header.Version)
	}

	gotHandshake, ok := roundTrip.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	if handshake.TypeClientHello != gotHandshake.Header.Type {
		t.Fatalf("expected %v, got %v", handshake.TypeClientHello, gotHandshake.Header.Type)
	}
	if uint16(1) != gotHandshake.Header.MessageSequence {
		t.Fatalf("expected %v, got %v", uint16(1), gotHandshake.Header.MessageSequence)
	}
	_, ok = gotHandshake.Message.(*handshake.MessageClientHello)
	if !ok {
		t.Fatal("expected true")
	}
}

func TestPlaintextRecord13RejectsLegacyPlaintextContentTypes(t *testing.T) {
	record := &PlaintextRecord13{
		Header:  Header{Version: protocol.Version1_2},
		Content: &protocol.ChangeCipherSpec{},
	}

	_, err := record.Marshal()
	if !errors.Is(err, dtlserrors.ErrInvalidContentType) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidContentType, err)
	}

	header := Header{
		ContentType: protocol.ContentTypeApplicationData,
		Version:     protocol.Version1_2,
		ContentLen:  1,
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, 0xaa)

	var roundTrip PlaintextRecord13
	err = roundTrip.Unmarshal(raw)
	if !errors.Is(err, dtlserrors.ErrInvalidContentType) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidContentType, err)
	}
}

func TestPlaintextRecord13RejectsOversizedContent(t *testing.T) {
	record := &PlaintextRecord13{
		Header:  Header{Version: protocol.Version1_2},
		Content: oversizedPlaintextContent13{},
	}

	_, err := record.Marshal()
	if !errors.Is(err, ErrInvalidPacketLength) {
		t.Fatalf("expected error %v, got %v", ErrInvalidPacketLength, err)
	}
}

func TestPlaintextRecord13RejectsOversizedUnmarshal(t *testing.T) {
	header := Header{
		ContentType: protocol.ContentTypeApplicationData,
		Version:     protocol.Version1_2,
		ContentLen:  maxDTLSPlaintextRecordLen + 1,
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, make([]byte, maxDTLSPlaintextRecordLen+1)...)

	var record PlaintextRecord13
	err = record.Unmarshal(raw)
	if !errors.Is(err, ErrInvalidPacketLength) {
		t.Fatalf("expected error %v, got %v", ErrInvalidPacketLength, err)
	}
}

func TestCiphertextRecord13RoundTrip(t *testing.T) {
	encryptedRecord := ciphertext13Payload(0xde)
	record := &CiphertextRecord13{
		Header: UnifiedHeader{
			EpochLow:       3,
			SequenceNumber: 0xaabb,
		},
		EncryptedRecord: encryptedRecord,
	}

	raw, err := record.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	expectedBytes := []byte{
		0x2f, 0xaa, 0xbb,
		0x00, 0x10,
	}
	if !bytes.Equal(expectedBytes, encryptedRecord) {
		t.Fatalf("expected %v, got %v", expectedBytes, encryptedRecord)
	}

	var roundTrip CiphertextRecord13
	if roundTrip.Unmarshal(raw) != nil {
		t.Fatal(roundTrip.Unmarshal(raw))
	}
	if uint8(3) != roundTrip.Header.EpochLow {
		t.Fatalf("expected %v, got %v", uint8(3), roundTrip.Header.EpochLow)
	}
	if uint16(0xaabb) != roundTrip.Header.SequenceNumber {
		t.Fatalf("expected %v, got %v", uint16(0xaabb), roundTrip.Header.SequenceNumber)
	}
	if !roundTrip.Header.SeqBit {
		t.Fatal("expected true")
	}
	if uint16(16) != roundTrip.Header.Length {
		t.Fatalf("expected %v, got %v", uint16(16), roundTrip.Header.Length)
	}
	if !roundTrip.Header.LengthBit {
		t.Fatal("expected true")
	}
	if !bytes.Equal(encryptedRecord, roundTrip.EncryptedRecord) {
		t.Fatalf("expected %v, got %v", encryptedRecord, roundTrip.EncryptedRecord)
	}
}

func TestCiphertextRecord13MarshalRefreshesLength(t *testing.T) {
	encryptedRecord := ciphertext13Payload(0xaa)
	record := &CiphertextRecord13{
		Header: UnifiedHeader{
			SequenceNumber: 0x01,
			Length:         4,
		},
		EncryptedRecord: encryptedRecord,
	}

	raw, err := record.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	expectedBytes := []byte{0x2c, 0x00, 0x01, 0x00, 0x10}
	if !bytes.Equal(expectedBytes, raw) {
		t.Fatalf("expected %v, got %v", expectedBytes, raw)
	}
	if uint16(16) != record.Header.Length {
		t.Fatalf("expected %v, got %v", uint16(16), record.Header.Length)
	}
	if !record.Header.SeqBit {
		t.Fatal("expected true")
	}
	if !record.Header.LengthBit {
		t.Fatal("expected true")
	}
}

func TestCiphertextRecord13MarshalRejectsShortEncryptedRecord(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		record := &CiphertextRecord13{
			EncryptedRecord: make([]byte, recordLen),
		}

		_, err := record.Marshal()
		if !errors.Is(err, ErrInvalidPacketLength) {
			t.Fatalf("Expected error to be %v, but got a different error (%v)",
				ErrInvalidPacketLength, err)
		}
	}
}

func TestCiphertextRecord13RejectsOversizedEncryptedRecord(t *testing.T) {
	record := &CiphertextRecord13{
		EncryptedRecord: make([]byte, maxDTLSCiphertextRecordLen+1),
	}

	_, err := record.Marshal()
	if !errors.Is(err, ErrInvalidPacketLength) {
		t.Fatalf("expected error %v, got %v", ErrInvalidPacketLength, err)
	}
}

func TestCiphertextRecord13WithoutLengthUsesRemainder(t *testing.T) {
	encryptedRecord := ciphertext13Payload(0xaa)
	raw := append([]byte{0x21, 0x12}, encryptedRecord...)

	var roundTrip CiphertextRecord13
	if roundTrip.Unmarshal(raw) != nil {
		t.Fatal(roundTrip.Unmarshal(raw))
	}
	if uint8(1) != roundTrip.Header.EpochLow {
		t.Fatalf("expected %v, got %v", uint8(1), roundTrip.Header.EpochLow)
	}
	if uint16(0x12) != roundTrip.Header.SequenceNumber {
		t.Fatalf("expected %v, got %v", uint16(0x12), roundTrip.Header.SequenceNumber)
	}
	if roundTrip.Header.SeqBit {
		t.Fatal("expected false")
	}
	if uint16(0) != roundTrip.Header.Length {
		t.Fatalf("expected %v, got %v", uint16(0), roundTrip.Header.Length)
	}
	if roundTrip.Header.LengthBit {
		t.Fatal("expected false")
	}
	if !bytes.Equal(encryptedRecord, roundTrip.EncryptedRecord) {
		t.Fatalf("expected %v, got %v", encryptedRecord, roundTrip.EncryptedRecord)
	}
}

func TestCiphertextRecord13RejectsLengthMismatch(t *testing.T) {
	var record CiphertextRecord13
	err := record.Unmarshal([]byte{0x2c, 0x00, 0x01, 0x00, 0x04, 0xaa, 0xbb})
	if !errors.Is(err, ErrInvalidPacketLength) {
		t.Fatalf("expected error %v, got %v", ErrInvalidPacketLength, err)
	}
}

func TestCiphertextRecord13UnmarshalRejectsShortEncryptedRecord(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		var recordWithoutLength CiphertextRecord13
		rawWithoutLength := append([]byte{0x20, 0x01}, make([]byte, recordLen)...)
		err := recordWithoutLength.Unmarshal(rawWithoutLength)
		if errors.Is(err, ErrInvalidPacketLength) == false {
			t.Fatalf("Expected specific error '%v', but got a different error (%v) for length %d",
				ErrInvalidPacketLength, err, recordLen)
		}

		var recordWithLength CiphertextRecord13
		rawWithLength := []byte{
			0x2c, 0x00, 0x01,
			byte(recordLen >> 8), byte(recordLen),
		}
		rawWithLength = append(rawWithLength, make([]byte, recordLen)...)
		err = recordWithLength.Unmarshal(rawWithLength)
		if errors.Is(err, ErrInvalidPacketLength) == false {
			t.Fatalf("Expected specific error '%v', but got a different error (%v) for length %d with length bit",
				ErrInvalidPacketLength, err, recordLen)
		}
	}
}

func TestUnpackDatagram13Plaintext(t *testing.T) {
	plaintext := &PlaintextRecord13{
		Header:  Header{Version: protocol.Version1_2},
		Content: &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify},
	}
	plaintextRaw, err := plaintext.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	records, err := UnpackDatagram13(plaintextRaw, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual([][]byte{plaintextRaw}, records) {
		t.Fatalf("expected %v, got %v", [][]byte{plaintextRaw}, records)
	}
}

func TestUnpackDatagram13Ciphertext(t *testing.T) {
	encryptedRecord := ciphertext13Payload(0xaa)
	ciphertextWithLength := &CiphertextRecord13{
		Header: UnifiedHeader{
			SequenceNumber: 0x01,
		},
		EncryptedRecord: encryptedRecord,
	}
	ciphertextWithLengthRaw, err := ciphertextWithLength.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ciphertextWithoutLengthRaw := append([]byte{0x20, 0x02}, ciphertext13Payload(0xcc)...)
	if bytes.Equal(ciphertextWithLengthRaw, ciphertextWithoutLengthRaw) {
		t.Fatalf("Expected byte slices to NOT be equal, but found equality.")
	}

	datagram := append(append([]byte{}, ciphertextWithLengthRaw...), ciphertextWithoutLengthRaw...)
	_, err = UnpackDatagram13(datagram, 0, true)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnpackDatagram13RejectsShortFinalCiphertextRecordWithoutLength(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		raw := append([]byte{0x20, 0x01}, make([]byte, recordLen)...)

		_, err := UnpackDatagram13(raw, 0, true)
		if errors.Is(err, ErrInvalidPacketLength) == false {
			t.Fatalf("Expected specific error '%v', but got a different error (%v) for length %d", ErrInvalidPacketLength, err, recordLen)
		}
	}
}

func TestUnpackDatagram13RejectsShortCiphertextRecordWithLength(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		raw := []byte{
			0x2c, 0x00, 0x01,
			byte(recordLen >> 8), byte(recordLen),
		}
		raw = append(raw, make([]byte, recordLen)...)

		_, err := UnpackDatagram13(raw, 0, true)
		if !errors.Is(err, ErrInvalidPacketLength) {
			t.Fatalf("Expected specific error '%v', but got a different error (%v) for length %d", ErrInvalidPacketLength, err, recordLen)
		}
	}
}

func TestUnpackDatagram13MixedPlaintextAndCiphertext(t *testing.T) {
	plaintext := &PlaintextRecord13{
		Header:  Header{Version: protocol.Version1_2},
		Content: &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify},
	}
	plaintextRaw, err := plaintext.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := &CiphertextRecord13{
		Header: UnifiedHeader{
			SequenceNumber: 0x01,
		},
		EncryptedRecord: ciphertext13Payload(0xaa),
	}
	ciphertextRaw, err := ciphertext.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	datagram := append(append([]byte{}, plaintextRaw...), ciphertextRaw...)
	records, err := UnpackDatagram13(datagram, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual([][]byte{plaintextRaw, ciphertextRaw}, records) {
		t.Fatalf("expected %v, got %v", [][]byte{plaintextRaw, ciphertextRaw}, records)
	}
}

func TestUnpackDatagram13RejectsCiphertextMissingNegotiatedCID(t *testing.T) {
	ciphertext := &CiphertextRecord13{
		Header: UnifiedHeader{
			SequenceNumber: 0x01,
		},
		EncryptedRecord: ciphertext13Payload(0xaa),
	}
	raw, err := ciphertext.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	_, err = UnpackDatagram13(raw, 4, true)
	if !errors.Is(err, dtlserrors.ErrInvalidCiphertextHeader) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidCiphertextHeader, err)
	}
}

func TestUnpackDatagram13RejectsCiphertextWithUnexpectedCID(t *testing.T) {
	ciphertext := &CiphertextRecord13{
		Header: UnifiedHeader{
			ConnectionID:   []byte{0x01, 0x02, 0x03, 0x04},
			SequenceNumber: 0x01,
		},
		EncryptedRecord: ciphertext13Payload(0xaa),
	}
	raw, err := ciphertext.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	_, err = UnpackDatagram13(raw, 0, true)
	if !errors.Is(err, dtlserrors.ErrInvalidCiphertextHeader) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidCiphertextHeader, err)
	}
}

func TestUnpackDatagram13RejectsTruncatedCID(t *testing.T) {
	_, err := UnpackDatagram13([]byte{0x30, 0x01, 0x02}, 4, true)
	if !errors.Is(err, dtlserrors.ErrInvalidUnifiedHeaderFormat) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidUnifiedHeaderFormat, err)
	}
}

func TestUnpackDatagram13DiscardsRemainderOnMismatchedCID(t *testing.T) {
	first := &CiphertextRecord13{
		Header: UnifiedHeader{
			ConnectionID:   []byte{0x01, 0x02, 0x03, 0x04},
			SequenceNumber: 0x01,
		},
		EncryptedRecord: ciphertext13Payload(0xaa),
	}
	firstRaw, err := first.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	second := &CiphertextRecord13{
		Header: UnifiedHeader{
			ConnectionID:   []byte{0x04, 0x03, 0x02, 0x01},
			SequenceNumber: 0x02,
		},
		EncryptedRecord: ciphertext13Payload(0xba),
	}
	secondRaw, err := second.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	records, err := UnpackDatagram13(append(append([]byte{}, firstRaw...), secondRaw...), 4, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual([][]byte{firstRaw}, records) {
		t.Fatalf("expected %v, got %v", [][]byte{firstRaw}, records)
	}
}

func TestUnpackDatagram13RejectsLegacyPlaintextWhenCiphertextHeadersEnabled(t *testing.T) {
	header := Header{
		ContentType: protocol.ContentTypeApplicationData,
		Version:     protocol.Version1_2,
		ContentLen:  1,
	}
	raw, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, 0xaa)

	_, err = UnpackDatagram13(raw, 0, true)
	if !errors.Is(err, dtlserrors.ErrInvalidContentType) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidContentType, err)
	}
}

func TestRecordLayer13Interface(t *testing.T) {
	var plaintext RecordLayer13 = &PlaintextRecord13{}
	if reflect.TypeOf(plaintext.RecordHeader()) != reflect.TypeOf(&Header{}) {
		t.Fatalf("expected type %T, got %T", &Header{}, plaintext.RecordHeader())
	}

	var ciphertext RecordLayer13 = &CiphertextRecord13{}
	if reflect.TypeOf(ciphertext.RecordHeader()) != reflect.TypeOf(&UnifiedHeader{}) {
		t.Fatalf("expected type %T, got %T", &UnifiedHeader{}, ciphertext.RecordHeader())
	}
}
