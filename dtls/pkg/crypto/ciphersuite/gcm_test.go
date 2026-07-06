// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func FuzzGCM_RoundTrip(f *testing.F) {
	f.Add([]byte{}, []byte("x"), uint64(0), uint16(0))
	f.Add([]byte{7, 8, 9}, []byte("alpha"), uint64(5), uint16(1))
	f.Add(make([]byte, 2048), []byte("left"), uint64(0x0a0b0c0d0e0f), uint16(3))

	f.Fuzz(func(t *testing.T, plain []byte, seed []byte, seq uint64, epoch uint16) {
		if len(plain) > 1<<14 {
			plain = plain[:1<<14]
		}

		h := sha256.Sum256(seed)
		localKey := h[:16]
		localWriteIV := h[16:20]

		gcmAEAD, err := NewGCM(localKey, localWriteIV, localKey, localWriteIV)
		if err != nil {
			t.Fatal(err)
		}

		hdr := recordlayer.Header{
			ContentType:    protocol.ContentTypeApplicationData,
			Version:        protocol.Version1_2,
			Epoch:          epoch,
			SequenceNumber: seq,
		}

		headerRaw, err := hdr.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		raw := make([]byte, len(headerRaw)+len(plain))
		copy(raw, headerRaw)
		copy(raw[len(headerRaw):], plain)

		enc, err := gcmAEAD.Encrypt(&recordlayer.RecordLayer{Header: hdr}, raw)
		if err != nil {
			t.Fatal(err)
		}

		dec, err := gcmAEAD.Decrypt(recordlayer.Header{}, enc)
		if err != nil {
			t.Fatal(err)
		}

		var parsedHdr recordlayer.Header
		if err := parsedHdr.Unmarshal(dec); err != nil {
			t.Fatal(err)
		}
		got := dec[parsedHdr.Size():]

		if !bytes.Equal(plain, got) {
			t.Fatalf("expected %v, got %v", plain, got)
		}
	})
}

func FuzzGCM_Bidirectional_RoundTrip(f *testing.F) {
	f.Add([]byte("hello"), []byte("seedA"), uint64(1), uint16(0),
		[]byte("world"), []byte("seedB"), uint64(2), uint16(1))

	f.Add([]byte{}, []byte("zero"), uint64(0), uint16(0),
		[]byte{1, 2, 3, 4}, []byte("other"), uint64(5), uint16(2))

	f.Add(make([]byte, 2048), []byte("AAA"), uint64(123456), uint16(3),
		make([]byte, 17), []byte("BBB"), uint64(789), uint16(4))

	f.Fuzz(func(t *testing.T,
		pA []byte, sA []byte, seqA uint64, epochA uint16,
		pB []byte, sB []byte, seqB uint64, epochB uint16,
	) {
		if len(pA) > 1<<14 {
			pA = pA[:1<<14]
		}

		if len(pB) > 1<<14 {
			pB = pB[:1<<14]
		}

		hA := sha256.Sum256(sA)
		hB := sha256.Sum256(sB)
		localKeyA, localWriteIVA := hA[:16], hA[16:20]
		localKeyB, localWriteIVB := hB[:16], hB[16:20]

		// A uses (keyA,ivA) to send and expects (keyB, ivB) for receive.
		gcmA, err := NewGCM(localKeyA, localWriteIVA, localKeyB, localWriteIVB)
		if err != nil {
			t.Fatal(err)
		}

		// B uses (keyB,ivB) to send and expects (keyA, ivA) for receive.
		gcmB, err := NewGCM(localKeyB, localWriteIVB, localKeyA, localWriteIVA)
		if err != nil {
			t.Fatal(err)
		}

		// A -> B
		hdrA := recordlayer.Header{
			ContentType:    protocol.ContentTypeApplicationData,
			Version:        protocol.Version1_2,
			Epoch:          epochA,
			SequenceNumber: seqA,
		}

		headerRawA, err := hdrA.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		rawA := make([]byte, len(headerRawA)+len(pA))
		copy(rawA, headerRawA)
		copy(rawA[len(headerRawA):], pA)

		encA, err := gcmA.Encrypt(&recordlayer.RecordLayer{Header: hdrA}, rawA)
		if err != nil {
			t.Fatal(err)
		}

		decAonB, err := gcmB.Decrypt(recordlayer.Header{}, encA)
		if err != nil {
			t.Fatal(err)
		}

		// parse header from decrypted bytes to compute payload offset safely.
		var parsedHdrA recordlayer.Header
		if parsedHdrA.Unmarshal(decAonB) != nil {
			t.Fatal(parsedHdrA.Unmarshal(decAonB))
		}

		gotA := decAonB[parsedHdrA.Size():]
		if !bytes.Equal(pA, gotA) {
			t.Fatalf("expected %v, got %v", pA, gotA)
		}

		// B -> A
		hdrB := recordlayer.Header{
			ContentType:    protocol.ContentTypeApplicationData,
			Version:        protocol.Version1_2,
			Epoch:          epochB,
			SequenceNumber: seqB,
		}

		headerRawB, err := hdrB.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		rawB := make([]byte, len(headerRawB)+len(pB))
		copy(rawB, headerRawB)
		copy(rawB[len(headerRawB):], pB)

		encB, err := gcmB.Encrypt(&recordlayer.RecordLayer{Header: hdrB}, rawB)
		if err != nil {
			t.Fatal(err)
		}

		decBonA, err := gcmA.Decrypt(recordlayer.Header{}, encB)
		if err != nil {
			t.Fatal(err)
		}

		var parsedHdrB recordlayer.Header
		if parsedHdrB.Unmarshal(decBonA) != nil {
			t.Fatal(parsedHdrB.Unmarshal(decBonA))
		}

		gotB := decBonA[parsedHdrB.Size():]
		if !bytes.Equal(pB, gotB) {
			t.Fatalf("expected %v, got %v", pB, gotB)
		}
	})
}
