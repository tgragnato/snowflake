// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"bytes"
	"errors"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
)

func TestInnerPlaintextRoundTrip(t *testing.T) {
	inner := &InnerPlaintext{
		Content:  []byte{0x01, 0x02},
		RealType: protocol.ContentTypeApplicationData,
		Zeros:    2,
	}

	raw, err := inner.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte{0x01, 0x02, 0x17, 0x00, 0x00}, raw) {
		t.Fatalf("expected %v, got %v", []byte{0x01, 0x02, 0x17, 0x00, 0x00}, raw)
	}

	var roundTrip InnerPlaintext
	if roundTrip.Unmarshal(raw) != nil {
		t.Fatal(roundTrip.Unmarshal(raw))
	}
	if !bytes.Equal(inner.Content, roundTrip.Content) {
		t.Fatalf("expected %v, got %v", inner.Content, roundTrip.Content)
	}
	if inner.RealType != roundTrip.RealType {
		t.Fatalf("expected %v, got %v", inner.RealType, roundTrip.RealType)
	}
	if inner.Zeros != roundTrip.Zeros {
		t.Fatalf("expected %v, got %v", inner.Zeros, roundTrip.Zeros)
	}
}

func TestInnerPlaintextAllowsEmptyContent(t *testing.T) {
	var inner InnerPlaintext
	if inner.Unmarshal([]byte{byte(protocol.ContentTypeAlert)}) != nil {
		t.Fatal(inner.Unmarshal([]byte{byte(protocol.ContentTypeAlert)}))
	}
	if len(inner.Content) != 0 {
		t.Fatal("expected empty")
	}
	if protocol.ContentTypeAlert != inner.RealType {
		t.Fatalf("expected %v, got %v", protocol.ContentTypeAlert, inner.RealType)
	}
	if uint(0) != inner.Zeros {
		t.Fatalf("expected %v, got %v", uint(0), inner.Zeros)
	}
}

func TestInnerPlaintextRejectsMissingContentType(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{},
		{0x00},
		{0x00, 0x00},
	} {
		var inner InnerPlaintext
		if !errors.Is(inner.Unmarshal(raw), dtlserrors.ErrBufferTooSmall) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrBufferTooSmall, inner.Unmarshal(raw))
		}
	}
}
