// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
)

func TestUDPDecode(t *testing.T) {
	for _, test := range []struct {
		Name      string
		Data      []byte
		Want      [][]byte
		WantError error
	}{
		{
			Name: "Change Cipher Spec, single packet",
			Data: []byte{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
			Want: [][]byte{
				{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
			},
		},
		{
			Name: "Change Cipher Spec, multi packet",
			Data: []byte{
				0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
				0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01,
			},
			Want: [][]byte{
				{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
				{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01},
			},
		},
		{
			Name:      "Invalid packet length",
			Data:      []byte{0x14, 0xfe},
			WantError: ErrInvalidPacketLength,
		},
		{
			Name:      "Packet declared invalid length",
			Data:      []byte{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0xFF, 0x01},
			WantError: ErrInvalidPacketLength,
		},
	} {
		dtlsPkts, err := UnpackDatagram(test.Data)
		if !errors.Is(err, test.WantError) {
			t.Errorf("Unexpected Error %q: exp: %v got: %v", test.Name, test.WantError, err)
		} else if !reflect.DeepEqual(test.Want, dtlsPkts) {
			t.Errorf("%q UDP decode: got %q, want %q", test.Name, dtlsPkts, test.Want)
		}
	}
}

func TestRecordLayerRoundTrip(t *testing.T) {
	for _, test := range []struct {
		Name               string
		Data               []byte
		Want               *RecordLayer
		WantMarshalError   error
		WantUnmarshalError error
	}{
		{
			Name: "Change Cipher Spec, single packet",
			Data: []byte{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
			Want: &RecordLayer{
				Header: Header{
					ContentType:    protocol.ContentTypeChangeCipherSpec,
					ContentLen:     1,
					Version:        protocol.Version1_2,
					Epoch:          0,
					SequenceNumber: 18,
				},
				Content: &protocol.ChangeCipherSpec{},
			},
		},
	} {
		r := &RecordLayer{}
		if err := r.Unmarshal(test.Data); !errors.Is(err, test.WantUnmarshalError) {
			t.Errorf("Unexpected Error %q: exp: %v got: %v", test.Name, test.WantUnmarshalError, err)
		} else if !reflect.DeepEqual(test.Want, r) {
			t.Errorf("%q recordLayer.unmarshal: got %q, want %q", test.Name, r, test.Want)
		}

		data, marshalErr := r.Marshal()
		if !errors.Is(marshalErr, test.WantMarshalError) {
			t.Errorf("Unexpected Error %q: exp: %v got: %v", test.Name, test.WantMarshalError, marshalErr)
		} else if !reflect.DeepEqual(test.Data, data) {
			t.Errorf("%q recordLayer.marshal: got % 02x, want % 02x", test.Name, data, test.Data)
		}
	}
}

func FuzzRecordLayer_Unmarshal_No_Panics(f *testing.F) {
	f.Add([]byte{
		0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
	})

	f.Fuzz(func(_ *testing.T, data []byte) {
		var r RecordLayer
		_ = r.Unmarshal(data)
	})
}

func FuzzUnpackDatagram_No_Panics(f *testing.F) {
	Datasingle := []byte{
		0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
	}
	Datamulti := []byte{
		0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
		0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01,
	}
	f.Add(Datasingle)
	f.Add(Datamulti)

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = UnpackDatagram(data)
	})
}

func FuzzRecordLayer_MarshalUnmarshal_RoundTrip(f *testing.F) {
	f.Add([]byte{}, uint16(0), uint64(0))
	f.Add([]byte{1, 2, 3}, uint16(1), uint64(5))

	f.Fuzz(func(t *testing.T, payload []byte, epoch uint16, seq uint64) {
		if len(payload) > 1<<14 {
			payload = payload[:1<<14]
		}

		recordLayer := &RecordLayer{
			Header: Header{
				ContentType:    protocol.ContentTypeApplicationData,
				Version:        protocol.Version1_2,
				Epoch:          epoch,
				SequenceNumber: seq,
			},
			Content: &protocol.ApplicationData{Data: payload},
		}

		raw, err := recordLayer.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		var back RecordLayer
		if err := back.Unmarshal(raw); err != nil {
			t.Fatalf("Expected successful unmarshaling, but got error: %v", err)
		}

		if recordLayer.Header.ContentType != back.Header.ContentType {
			t.Fatalf("expected %v, got %v", recordLayer.Header.ContentType, back.Header.ContentType)
		}
		if recordLayer.Header.Version != back.Header.Version {
			t.Fatalf("expected %v, got %v", recordLayer.Header.Version, back.Header.Version)
		}
		if recordLayer.Header.Epoch != back.Header.Epoch {
			t.Fatalf("expected %v, got %v", recordLayer.Header.Epoch, back.Header.Epoch)
		}
		if recordLayer.Header.SequenceNumber != back.Header.SequenceNumber {
			t.Fatalf("expected %v, got %v", recordLayer.Header.SequenceNumber, back.Header.SequenceNumber)
		}

		bodyLen := len(raw) - back.Header.Size()
		appData, ok := back.Content.(*protocol.ApplicationData)
		if !ok {
			t.Fatal("expected true")
		}
		if bodyLen != len(appData.Data) {
			t.Fatalf("Expected data length (%d), but got %d", len(appData.Data), bodyLen)
		}

		if !bytes.Equal(payload, appData.Data) {
			t.Fatalf("expected %v, got %v", payload, appData.Data)
		}

		raw2, err := back.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, raw2) {
			t.Fatalf("expected %v, got %v", raw, raw2)
		}
	})
}

func FuzzRecordLayer_UnpackDatagram_RoundTrip(f *testing.F) {
	f.Add(uint8(1), []byte("a"), []byte{}, []byte{}, []byte{})
	f.Add(uint8(3), []byte("one"), []byte("two"), []byte("three"), []byte(""))

	f.Fuzz(func(t *testing.T, n uint8, p1, p2, p3, p4 []byte) {
		count := int(n%4) + 1
		all := [][]byte{p1, p2, p3, p4}
		all = all[:count]

		for i := range all {
			if len(all[i]) > 1<<14 {
				all[i] = all[i][:1<<14] // i is bounded by range over all slice
			}
			if len(all[i]) == 0 { // i is bounded by range over all slice
				all[i] = []byte{0} // ensure a non-empty record
			}
		}

		var dat []byte
		want := make([][]byte, 0, count)
		for i := range count {
			rl := &RecordLayer{
				Header: Header{
					ContentType:    protocol.ContentTypeApplicationData,
					Version:        protocol.Version1_2,
					Epoch:          uint16(i),                // G115: i is bounded (<= 4)
					SequenceNumber: uint64(1000) + uint64(i), // G115: i is bounded (<= 4)
				},
				Content: &protocol.ApplicationData{Data: all[i]}, // G115: no out of range access.
			}
			raw, err := rl.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			dat = append(dat, raw...)
			want = append(want, raw)
		}

		chunks, err := UnpackDatagram(dat)
		if err != nil {
			t.Fatal(err)
		}
		if len(want) != len(chunks) {
			t.Fatalf("expected %v, got %v", len(want), len(chunks))
		}

		for i := range chunks {
			if !bytes.Equal(want[i], chunks[i]) {
				t.Fatalf("expected %v, got %v", want[i], chunks[i])
			}

			if !(len(chunks[i]) >= FixedHeaderSize+1) {
				t.Fatal("expected true")
			}
			ln := int(binary.BigEndian.Uint16(chunks[i][11:]))
			if ln != len(chunks[i])-FixedHeaderSize {
				t.Fatalf("expected %v, got %v", ln, len(chunks[i])-FixedHeaderSize)
			}

			var rl RecordLayer
			if rl.Unmarshal(chunks[i]) != nil {
				t.Fatal(rl.Unmarshal(chunks[i]))
			}
		}

		if len(dat) >= FixedHeaderSize+2 {
			bad := append([]byte{}, dat...)
			orig := binary.BigEndian.Uint16(bad[11:])
			binary.BigEndian.PutUint16(bad[11:], orig+1)
			_, err = UnpackDatagram(bad)
			if !errors.Is(err, ErrInvalidPacketLength) {
				t.Fatalf("expected error %v, got %v", ErrInvalidPacketLength, err)
			}
		}

		if len(dat) > 0 {
			_, err = UnpackDatagram(dat[:len(dat)-1])
			if !errors.Is(err, ErrInvalidPacketLength) {
				t.Fatalf("expected error %v, got %v", ErrInvalidPacketLength, err)
			}
		}
	})
}

func FuzzRecordLayer_ContentAwareUnpackDatagram_RoundTrip(f *testing.F) {
	f.Add(uint8(5), []byte("hello"), []byte("world"))
	f.Add(uint8(0), []byte{}, []byte("x"))

	f.Fuzz(func(t *testing.T, cidLen uint8, p1, p2 []byte) {
		cl := int(cidLen % 8)

		bound := func(b []byte) []byte {
			if len(b) > 1<<14 {
				b = b[:1<<14]
			}
			if len(b) == 0 {
				b = []byte{0}
			}

			return b
		}
		p1, p2 = bound(p1), bound(p2)

		cid := make([]byte, cl)
		for i := range cid {
			cid[i] = byte(i)
		}

		makeCIDRecord := func(epoch uint16, seq uint64, payload []byte) []byte {
			header := make([]byte, FixedHeaderSize-2) // 11 bytes before len
			if cl > 0 {
				header[0] = byte(protocol.ContentTypeConnectionID)
			} else {
				header[0] = byte(protocol.ContentTypeApplicationData)
			}

			header[1], header[2] = protocol.Version1_2.Major, protocol.Version1_2.Minor
			binary.BigEndian.PutUint16(header[3:], epoch)

			// 48-bit sequence number
			seq48 := seq & 0x0000ffffffffffff
			header[5] = byte((seq48 >> 40) & 0xff)
			header[6] = byte((seq48 >> 32) & 0xff)
			header[7] = byte((seq48 >> 24) & 0xff)
			header[8] = byte((seq48 >> 16) & 0xff)
			header[9] = byte((seq48 >> 8) & 0xff)
			header[10] = byte(seq48 & 0xff)

			out := make([]byte, 0, len(header)+cl+2+len(payload))
			out = append(out, header...)
			if cl > 0 {
				out = append(out, cid...)
			}

			// G115: payload <= 1<<14
			binary.BigEndian.PutUint16(out[len(out):len(out)+2], uint16(len(payload)))
			out = out[:len(out)+2]
			out = append(out, payload...)

			return out
		}

		raw1 := makeCIDRecord(0, 10, p1)
		raw2 := makeCIDRecord(1, 11, p2)
		data := append(append([]byte{}, raw1...), raw2...)

		parts, err := ContentAwareUnpackDatagram(data, cl)
		if err != nil {
			t.Fatal(err)
		}
		if 2 != len(parts) {
			t.Fatalf("expected %v, got %v", 2, len(parts))
		}
		if !bytes.Equal(raw1, parts[0]) {
			t.Fatalf("expected %v, got %v", raw1, parts[0])
		}
		if !bytes.Equal(raw2, parts[1]) {
			t.Fatalf("expected %v, got %v", raw2, parts[1])
		}

		// Validate length field and header size per record.
		for _, part := range parts {
			hdrExtra := 0
			if protocol.ContentType(part[0]) == protocol.ContentTypeConnectionID {
				hdrExtra = cl
			}

			if !(len(part) >= FixedHeaderSize+hdrExtra) {
				t.Fatalf("expected %v >= %v", len(part), FixedHeaderSize+hdrExtra)
			}

			lenIdx := fixedHeaderLenIdx + hdrExtra
			if !(len(part) >= lenIdx+2) {
				t.Fatalf("expected %v >= %v", len(part), lenIdx+2)
			}

			decl := int(binary.BigEndian.Uint16(part[lenIdx:]))
			if decl != len(part)-(FixedHeaderSize+hdrExtra) {
				t.Fatalf("expected %v, got %v", decl, len(part)-(FixedHeaderSize+hdrExtra))
			}
		}

		// Negative: corrupt the first record's length.
		{
			bad := append([]byte{}, data...)
			hdrExtra := 0
			if protocol.ContentType(bad[0]) == protocol.ContentTypeConnectionID {
				hdrExtra = cl
			}
			lenIdx := fixedHeaderLenIdx + hdrExtra
			orig := binary.BigEndian.Uint16(bad[lenIdx:])
			binary.BigEndian.PutUint16(bad[lenIdx:], orig+1)
			_, err = ContentAwareUnpackDatagram(bad, cl)
			if !errors.Is(err, ErrInvalidPacketLength) {
				t.Fatalf("expected error %v, got %v", ErrInvalidPacketLength, err)
			}
		}

		// Negative: truncate the datagram.
		if len(data) > 0 {
			_, err = ContentAwareUnpackDatagram(data[:len(data)-1], cl)
			if !errors.Is(err, ErrInvalidPacketLength) {
				t.Fatalf("expected error %v, got %v", ErrInvalidPacketLength, err)
			}
		}
	})
}
