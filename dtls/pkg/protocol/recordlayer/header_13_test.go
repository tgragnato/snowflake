// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"bytes"
	"testing"
)

func TestUnifiedHeader(t *testing.T) {
	uh := UnifiedHeader{SequenceNumber: 0xaabb, SeqBit: true, Length: 42, LengthBit: true, EpochLow: 15}

	raw, err := uh.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x2f,       // 0b00101111
		0xaa, 0xbb, // Sequence number
		0x00, 0x2a, // length
	}
	if !bytes.Equal(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newUh := UnifiedHeader{}
	err = newUh.Unmarshal(expect)

	if err != nil {
		t.Error(err)
	}
	if len(newUh.ConnectionID) != 0 {
		t.Error("expected empty")
	}
	if uh.SequenceNumber != newUh.SequenceNumber {
		t.Errorf("expected %v, got %v", uh.SequenceNumber, newUh.SequenceNumber)
	}
	if !newUh.SeqBit {
		t.Error("expected true")
	}
	if uh.Length != newUh.Length {
		t.Errorf("expected %v, got %v", uh.Length, newUh.Length)
	}
	if !newUh.LengthBit {
		t.Error("expected true")
	}
	if uh.EpochLow&0b11 != newUh.EpochLow {
		t.Errorf("expected %v, got %v", uh.EpochLow&0b11, newUh.EpochLow)
	}
}

func TestUnifiedHeader_Minimal(t *testing.T) {
	uh := UnifiedHeader{SequenceNumber: 0x42}

	raw, err := uh.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x20, // 0b00100000
		0x42, // Sequence number
	}
	if !bytes.Equal(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newUh := UnifiedHeader{}
	err = newUh.Unmarshal(expect)

	if err != nil {
		t.Error(err)
	}
	if len(newUh.ConnectionID) != 0 {
		t.Error("expected empty")
	}
	if uh.SequenceNumber != newUh.SequenceNumber {
		t.Errorf("expected %v, got %v", uh.SequenceNumber, newUh.SequenceNumber)
	}
	if newUh.SeqBit {
		t.Error("expected false")
	}
	if uh.Length != newUh.Length {
		t.Errorf("expected %v, got %v", uh.Length, newUh.Length)
	}
	if newUh.LengthBit {
		t.Error("expected false")
	}
	if uint8(0b00) != newUh.EpochLow {
		t.Errorf("expected %v, got %v", uint8(0b00), newUh.EpochLow)
	}
}

func TestUnifiedHeader_CID(t *testing.T) {
	CID := []byte{0x1, 0x2, 0x3, 0x4}
	uh := UnifiedHeader{ConnectionID: CID, SequenceNumber: 0xaa}

	raw, err := uh.Marshal()
	if err != nil {
		t.Error(err)
	}

	expect := []byte{
		0x30,      // 0b00110000
		0x01, 0x2, // CID
		0x03, 0x4, // CID
		0xaa, // Seq no
	}
	if !bytes.Equal(expect, raw) {
		t.Errorf("expected %v, got %v", expect, raw)
	}

	newUh := UnifiedHeader{ConnectionID: make([]byte, len(CID))}
	err = newUh.Unmarshal(expect)

	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(uh.ConnectionID, newUh.ConnectionID) {
		t.Errorf("expected %v, got %v", uh.ConnectionID, newUh.ConnectionID)
	}
	if uh.SequenceNumber != newUh.SequenceNumber {
		t.Errorf("expected %v, got %v", uh.SequenceNumber, newUh.SequenceNumber)
	}
	if newUh.SeqBit {
		t.Error("expected false")
	}
	if uh.Length != newUh.Length {
		t.Errorf("expected %v, got %v", uh.Length, newUh.Length)
	}
	if newUh.LengthBit {
		t.Error("expected false")
	}
	if uint8(0b00) != newUh.EpochLow {
		t.Errorf("expected %v, got %v", uint8(0b00), newUh.EpochLow)
	}
}

func TestUnifiedHeaderSizeUsesEncodedBits(t *testing.T) {
	uh := UnifiedHeader{
		SeqBit:    true,
		LengthBit: true,
	}
	if 5 != uh.Size() {
		t.Errorf("expected %v, got %v", 5, uh.Size())
	}

	uh = UnifiedHeader{
		SequenceNumber: 0x0100,
		Length:         1,
	}
	if 2 != uh.Size() {
		t.Errorf("expected %v, got %v", 2, uh.Size())
	}
}

func TestUnifiedHeaderUnmarshalClearsBits(t *testing.T) {
	uh := UnifiedHeader{
		SeqBit:    true,
		Length:    5,
		LengthBit: true,
	}

	err := uh.Unmarshal([]byte{0x20, 0x42})
	if err != nil {
		t.Error(err)
	}
	if uh.SeqBit {
		t.Error("expected false")
	}
	if uh.LengthBit {
		t.Error("expected false")
	}
	if 2 != uh.Size() {
		t.Errorf("expected %v, got %v", 2, uh.Size())
	}
}

func FuzzUnifiedHeaderUnmarshal(f *testing.F) {
	testcases := [][]byte{
		{
			0x2f,       // 0b00101111
			0xaa, 0xbb, // Sequence number
			0x00, 0x2a, // length
		},
		{
			0x20, // 0b00100000
			0x42, // Sequence number
		},
		{
			0x30,      // 0b00110000
			0x01, 0x2, // CID
			0x03, 0x4, // CID
			0xaa, // Seq no
		},
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		uh := UnifiedHeader{}
		err := uh.Unmarshal(data)
		if err != nil {
			return
		}
		content := data[0]
		if !(int(content) < 64) {
			t.Errorf("expected %v < %v", int(content), 64)
		}
		if !(int(content) > 31) {
			t.Errorf("expected %v > %v", int(content), 31)
		}
		parsedLength := len(uh.ConnectionID)
		if parsedLength != 0 {
			t.Errorf("expected zero")
		}
		if !(uh.EpochLow <= uint8(0b000000011)) {
			t.Errorf("expected %v <= %v", uh.EpochLow, uint8(0b000000011))
		}
	})
}

func FuzzUnifiedHeaderCIDUnmarshal(f *testing.F) {
	testcases := [][]byte{
		{
			0x2f,       // 0b00101111
			0xaa, 0xbb, // Sequence number
			0x00, 0x2a, // length
		},
		{
			0x20, // 0b00100000
			0x42, // Sequence number
		},
		{
			0x30,      // 0b00110000
			0x01, 0x2, // CID
			0x03, 0x4, // CID
			0xaa, // Seq no
		},
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cidLength := 32
		uh := UnifiedHeader{ConnectionID: make([]byte, cidLength)}
		err := uh.Unmarshal(data)
		if err != nil {
			return
		}
		content := data[0]
		if !(int(content) < 64) {
			t.Errorf("expected %v < %v", int(content), 64)
		}
		if !(int(content) > 31) {
			t.Errorf("expected %v > %v", int(content), 31)
		}
		if (content & UnifiedHeaderCIDBit) != 0 {
			parsedLength := len(uh.ConnectionID)
			if cidLength != parsedLength {
				t.Errorf("expected %v, got %v", cidLength, parsedLength)
			}
		}
		if !(uh.EpochLow <= uint8(0b000000011)) {
			t.Errorf("expected %v <= %v", uh.EpochLow, uint8(0b000000011))
		}
	})
}
