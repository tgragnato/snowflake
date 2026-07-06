// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"reflect"
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

func TestHandshakeCacheSinglePush(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Rule     []dtlsflight.HandshakeCachePullRule
		Input    []dtlsflight.HandshakeCacheItem
		Expected []byte
	}{
		{
			Name: "Single Push",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 0, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 0, Epoch: 0, IsClient: true, Optional: false},
			},
			Expected: []byte{0x00},
		},
		{
			Name: "Multi Push",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 0, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: 2, IsClient: true, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 0, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 2, Epoch: 0, IsClient: true, Optional: false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Rules set order",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 2, IsClient: true, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
				{Typ: 0, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 0, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 2, Epoch: 0, IsClient: true, Optional: false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},

		{
			Name: "Multi Push, Dupe Seqnum",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 0, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 0, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
			},
			Expected: []byte{0x00, 0x01},
		},
		{
			Name: "Multi Push, Dupe Seqnum Client/Server",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 0, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: 1, IsClient: false, Epoch: 0, MessageSequence: 1, Data: []byte{0x02}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 0, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 1, Epoch: 0, IsClient: false, Optional: false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Dupe Seqnum with Unique HandshakeType",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 2, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: 3, IsClient: false, Epoch: 0, MessageSequence: 0, Data: []byte{0x02}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 2, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 3, Epoch: 0, IsClient: false, Optional: false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Wrong epoch",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 2, IsClient: true, Epoch: 1, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: 2, IsClient: true, Epoch: 0, MessageSequence: 2, Data: []byte{0x11}},
				{Typ: 3, IsClient: false, Epoch: 0, MessageSequence: 0, Data: []byte{0x02}},
				{Typ: 3, IsClient: false, Epoch: 1, MessageSequence: 0, Data: []byte{0x12}},
				{Typ: 3, IsClient: false, Epoch: 2, MessageSequence: 0, Data: []byte{0x12}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 2, Epoch: 1, IsClient: true, Optional: false},
				{Typ: 3, Epoch: 0, IsClient: false, Optional: false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
	} {
		h := dtlsflight.NewCache()
		for _, i := range test.Input {
			h.Push(i.Data, i.Epoch, i.MessageSequence, i.Typ, i.IsClient)
		}
		verifyData := h.PullAndMerge(test.Rule...)
		if !reflect.DeepEqual(test.Expected, verifyData) {
			t.Errorf("expected %v, got %v", test.Expected, verifyData)
		}
	}
}

func TestHandshakeCacheFullPullMapItemsReturnsAcceptedRawItems(t *testing.T) {
	cipherSuiteID := uint16(TLS_PSK_WITH_CHACHA20_POLY1305_SHA256)
	rawClientHello := marshalHandshakeCacheTestMessage(t, 0, &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		CipherSuiteIDs:     []uint16{uint16(TLS_PSK_WITH_CHACHA20_POLY1305_SHA256)},
		CompressionMethods: defaultCompressionMethods(),
	})
	rawServerHello := marshalHandshakeCacheTestMessage(t, 1, &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, 0, 1, handshake.TypeServerHello, false)
	cache.Push(rawClientHello, 0, 0, handshake.TypeClientHello, true)

	seq, msgs, items, ok := cache.FullPullMapItems(0, nil,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: 0, IsClient: true, Optional: false},
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: 0, IsClient: false, Optional: false},
	)

	if !ok {
		t.Fatal("expected true")
	}
	if 2 != seq {
		t.Errorf("expected %v, got %v", 2, seq)
	}
	if _, ok := msgs[handshake.TypeClientHello].(*handshake.MessageClientHello); !ok {
		t.Fatalf("expected *handshake.MessageClientHello, got %T", msgs[handshake.TypeClientHello])
	}
	if _, ok := msgs[handshake.TypeServerHello].(*handshake.MessageServerHello); !ok {
		t.Fatalf("expected *handshake.MessageServerHello, got %T", msgs[handshake.TypeServerHello])
	}
	if len(items) != 2 {
		t.Fatalf("expected len %d, got %d", 2, len(items))
	}
	if !reflect.DeepEqual(rawClientHello, items[0].Data) {
		t.Errorf("expected %v, got %v", rawClientHello, items[0].Data)
	}
	if !reflect.DeepEqual(rawServerHello, items[1].Data) {
		t.Errorf("expected %v, got %v", rawServerHello, items[1].Data)
	}
}

func marshalHandshakeCacheTestMessage(t *testing.T, seq uint16, message handshake.Message) []byte {
	t.Helper()

	raw, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: seq},
		Message: message,
	}).Marshal()
	if err != nil {
		t.Fatal("error: ", err)
	}

	return raw
}

func TestHandshakeCacheSessionHash(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Rule     []dtlsflight.HandshakeCachePullRule
		Input    []dtlsflight.HandshakeCacheItem
		Expected []byte
	}{
		{
			Name: "Standard Handshake",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: handshake.TypeClientHello, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: handshake.TypeServerHello, IsClient: false, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: handshake.TypeCertificate, IsClient: false, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
				{Typ: handshake.TypeServerKeyExchange, IsClient: false, Epoch: 0, MessageSequence: 3, Data: []byte{0x03}},
				{Typ: handshake.TypeServerHelloDone, IsClient: false, Epoch: 0, MessageSequence: 4, Data: []byte{0x04}},
				{Typ: handshake.TypeClientKeyExchange, IsClient: true, Epoch: 0, MessageSequence: 5, Data: []byte{0x05}},
			},
			Expected: []byte{
				0x79, 0xf4, 0x73, 0x87, 0x06, 0xfc, 0xe9, 0x65, 0x0a, 0xc6, 0x02, 0x66, 0x67, 0x5c, 0x3c, 0xd0,
				0x72, 0x98, 0xb0, 0x99, 0x23, 0x85, 0x0d, 0x52, 0x56, 0x04, 0xd0, 0x40, 0xe6, 0xe4, 0x48, 0xad,
				0xc7, 0xdc, 0x22, 0x78, 0x0d, 0x7e, 0x1b, 0x95, 0xbf, 0xea, 0xa8, 0x6a, 0x67, 0x8e, 0x45, 0x52,
			},
		},
		{
			Name: "Handshake With Client Cert Request",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: handshake.TypeClientHello, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: handshake.TypeServerHello, IsClient: false, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: handshake.TypeCertificate, IsClient: false, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
				{Typ: handshake.TypeServerKeyExchange, IsClient: false, Epoch: 0, MessageSequence: 3, Data: []byte{0x03}},
				{Typ: handshake.TypeCertificateRequest, IsClient: false, Epoch: 0, MessageSequence: 4, Data: []byte{0x04}},
				{Typ: handshake.TypeServerHelloDone, IsClient: false, Epoch: 0, MessageSequence: 5, Data: []byte{0x05}},
				{Typ: handshake.TypeClientKeyExchange, IsClient: true, Epoch: 0, MessageSequence: 6, Data: []byte{0x06}},
			},
			Expected: []byte{
				0xe6, 0xce, 0x18, 0x96, 0xc9, 0x78, 0x3a, 0x70, 0xac, 0x4c, 0x90, 0x27, 0x6c, 0xc3, 0x7b, 0x37,
				0x68, 0x7d, 0x7e, 0x30, 0xc7, 0x53, 0x97, 0x57, 0x62, 0xf9, 0x61, 0xae, 0x37, 0x11, 0x8d, 0x9a,
				0x61, 0x02, 0x42, 0x71, 0x6e, 0x83, 0x59, 0xef, 0xc4, 0x97, 0x5a, 0xa9, 0x8c, 0x63, 0x2d, 0xcf,
			},
		},
		{
			Name: "Handshake Ignores after ClientKeyExchange",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: handshake.TypeClientHello, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: handshake.TypeServerHello, IsClient: false, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: handshake.TypeCertificate, IsClient: false, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
				{Typ: handshake.TypeServerKeyExchange, IsClient: false, Epoch: 0, MessageSequence: 3, Data: []byte{0x03}},
				{Typ: handshake.TypeCertificateRequest, IsClient: false, Epoch: 0, MessageSequence: 4, Data: []byte{0x04}},
				{Typ: handshake.TypeServerHelloDone, IsClient: false, Epoch: 0, MessageSequence: 5, Data: []byte{0x05}},
				{Typ: handshake.TypeClientKeyExchange, IsClient: true, Epoch: 0, MessageSequence: 6, Data: []byte{0x06}},
				{Typ: handshake.TypeCertificateVerify, IsClient: true, Epoch: 0, MessageSequence: 7, Data: []byte{0x07}},
				{Typ: handshake.TypeFinished, IsClient: true, Epoch: 1, MessageSequence: 7, Data: []byte{0x08}},
				{Typ: handshake.TypeFinished, IsClient: false, Epoch: 1, MessageSequence: 7, Data: []byte{0x09}},
			},
			Expected: []byte{
				0xe6, 0xce, 0x18, 0x96, 0xc9, 0x78, 0x3a, 0x70, 0xac, 0x4c, 0x90, 0x27, 0x6c, 0xc3, 0x7b, 0x37,
				0x68, 0x7d, 0x7e, 0x30, 0xc7, 0x53, 0x97, 0x57, 0x62, 0xf9, 0x61, 0xae, 0x37, 0x11, 0x8d, 0x9a,
				0x61, 0x02, 0x42, 0x71, 0x6e, 0x83, 0x59, 0xef, 0xc4, 0x97, 0x5a, 0xa9, 0x8c, 0x63, 0x2d, 0xcf,
			},
		},
		{
			Name: "Handshake Ignores wrong epoch",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: handshake.TypeClientHello, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: handshake.TypeServerHello, IsClient: false, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: handshake.TypeCertificate, IsClient: false, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
				{Typ: handshake.TypeServerKeyExchange, IsClient: false, Epoch: 0, MessageSequence: 3, Data: []byte{0x03}},
				{Typ: handshake.TypeCertificateRequest, IsClient: false, Epoch: 0, MessageSequence: 4, Data: []byte{0x04}},
				{Typ: handshake.TypeServerHelloDone, IsClient: false, Epoch: 0, MessageSequence: 5, Data: []byte{0x05}},
				{Typ: handshake.TypeClientKeyExchange, IsClient: true, Epoch: 0, MessageSequence: 6, Data: []byte{0x06}},
				{Typ: handshake.TypeCertificateVerify, IsClient: true, Epoch: 0, MessageSequence: 7, Data: []byte{0x07}},
				{Typ: handshake.TypeFinished, IsClient: true, Epoch: 0, MessageSequence: 7, Data: []byte{0xf0}},
				{Typ: handshake.TypeFinished, IsClient: false, Epoch: 0, MessageSequence: 7, Data: []byte{0xf1}},
				{Typ: handshake.TypeFinished, IsClient: true, Epoch: 1, MessageSequence: 7, Data: []byte{0x08}},
				{Typ: handshake.TypeFinished, IsClient: false, Epoch: 1, MessageSequence: 7, Data: []byte{0x09}},
				{Typ: handshake.TypeFinished, IsClient: true, Epoch: 0, MessageSequence: 7, Data: []byte{0xf0}},
				{Typ: handshake.TypeFinished, IsClient: false, Epoch: 0, MessageSequence: 7, Data: []byte{0xf1}},
			},
			Expected: []byte{
				0xe6, 0xce, 0x18, 0x96, 0xc9, 0x78, 0x3a, 0x70, 0xac, 0x4c, 0x90, 0x27, 0x6c, 0xc3, 0x7b, 0x37,
				0x68, 0x7d, 0x7e, 0x30, 0xc7, 0x53, 0x97, 0x57, 0x62, 0xf9, 0x61, 0xae, 0x37, 0x11, 0x8d, 0x9a,
				0x61, 0x02, 0x42, 0x71, 0x6e, 0x83, 0x59, 0xef, 0xc4, 0x97, 0x5a, 0xa9, 0x8c, 0x63, 0x2d, 0xcf,
			},
		},
	} {
		h := dtlsflight.NewCache()
		for _, i := range test.Input {
			h.Push(i.Data, i.Epoch, i.MessageSequence, i.Typ, i.IsClient)
		}

		cipherSuite := ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{}
		verifyData, err := h.SessionHash(cipherSuite.HashFunc(), 0)
		if err != nil {
			t.Error("error: ", err)
		}
		if !reflect.DeepEqual(test.Expected, verifyData) {
			t.Errorf("handshakeCacheSessionHash: expected %v, got %v", test.Expected, verifyData)
		}
	}
}
