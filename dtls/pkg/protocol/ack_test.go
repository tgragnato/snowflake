// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

import (
	"bytes"
	"errors"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestACK(t *testing.T) {
	ack := ACK{
		Records: []RecordNumber{
			{Epoch: 1, SequenceNumber: 42},
		},
	}

	raw, err := ack.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x00, 0x10, // record list length (1 record × 16 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // epoch = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, // sequence_number = 42
	}
	if !bytes.Equal(expect, raw) {
		t.Errorf("marshaled bytes mismatch: expected %x, got %x", expect, raw)
	}

	newACK := ACK{}
	if err := newACK.Unmarshal(expect); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if len(newACK.Records) != 1 {
		t.Errorf("expected 1 record, got %d", len(newACK.Records))
	}
	if newACK.Records[0].Epoch != uint64(1) {
		t.Errorf("expected epoch 1, got %d", newACK.Records[0].Epoch)
	}
	if newACK.Records[0].SequenceNumber != uint64(42) {
		t.Errorf("expected sequence number 42, got %d", newACK.Records[0].SequenceNumber)
	}
}

func TestACK_MultipleRecords(t *testing.T) {
	ack := ACK{
		Records: []RecordNumber{
			{Epoch: 1, SequenceNumber: 1},
			{Epoch: 1, SequenceNumber: 2},
			{Epoch: 2, SequenceNumber: 0},
		},
	}

	raw, err := ack.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	expect := []byte{
		0x00, 0x30, // record list length (3 × 16 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // epoch = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence_number = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // epoch = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // sequence_number = 2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // epoch = 2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sequence_number = 0
	}
	if !bytes.Equal(expect, raw) {
		t.Errorf("marshaled bytes mismatch: expected %x, got %x", expect, raw)
	}

	newACK := ACK{}
	if err := newACK.Unmarshal(expect); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if len(newACK.Records) != 3 {
		t.Errorf("expected 3 records, got %d", len(newACK.Records))
	}
	if newACK.Records[0].Epoch != uint64(1) {
		t.Errorf("expected epoch 1, got %d", newACK.Records[0].Epoch)
	}
	if newACK.Records[0].SequenceNumber != uint64(1) {
		t.Errorf("expected sequence number 1, got %d", newACK.Records[0].SequenceNumber)
	}
	if newACK.Records[1].Epoch != uint64(1) {
		t.Errorf("expected epoch 1, got %d", newACK.Records[1].Epoch)
	}
	if newACK.Records[1].SequenceNumber != uint64(2) {
		t.Errorf("expected sequence number 2, got %d", newACK.Records[1].SequenceNumber)
	}
	if newACK.Records[2].Epoch != uint64(2) {
		t.Errorf("expected epoch 2, got %d", newACK.Records[2].Epoch)
	}
	if newACK.Records[2].SequenceNumber != uint64(0) {
		t.Errorf("expected sequence number 0, got %d", newACK.Records[2].SequenceNumber)
	}
}

func TestACK_EmptyRecords(t *testing.T) {
	ack := ACK{Records: []RecordNumber{}}

	raw, err := ack.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	expect := []byte{
		0x00, 0x00, // record list length (empty)
	}
	if !bytes.Equal(expect, raw) {
		t.Errorf("marshaled bytes mismatch: expected %x, got %x", expect, raw)
	}

	newACK := ACK{}
	if err := newACK.Unmarshal(expect); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if len(newACK.Records) != 0 {
		t.Errorf("expected empty records, got %d records", len(newACK.Records))
	}
}

func TestACK_UnmarshalTruncatedRecord(t *testing.T) {
	// Length prefix claims 16 bytes but only 7 are present.
	raw := []byte{
		0x00, 0x10, // record list length = 16
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // only 7 bytes of epoch
	}
	newACK := ACK{}
	err := newACK.Unmarshal(raw)
	if !errors.Is(err, dtlserrors.ErrLengthMismatch) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrLengthMismatch, err)
	}
}

func TestACK_UnmarshalTrailingData(t *testing.T) {
	// Valid record list followed by unexpected trailing bytes.
	raw := []byte{
		0x00, 0x10, // record list length = 16 (one record)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // epoch = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence_number = 1
		0xde, 0xad, // trailing garbage
	}
	newACK := ACK{}
	err := newACK.Unmarshal(raw)
	if !errors.Is(err, dtlserrors.ErrLengthMismatch) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrLengthMismatch, err)
	}
}

func TestACK_UnmarshalEmpty(t *testing.T) {
	newACK := ACK{}
	if err := newACK.Unmarshal([]byte{0x00, 0x00}); err != nil {
		t.Error(err)
	}
}
