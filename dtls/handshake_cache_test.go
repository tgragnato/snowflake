// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"testing"

	"github.com/pion/dtls/v2/internal/ciphersuite"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
)

func TestHandshakeCacheSinglePush(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Rule     []handshakeCachePullRule
		Input    []handshakeCacheItem
		Expected []byte
	}{
		{
			Name: "Single Push",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
			},
			Rule: []handshakeCachePullRule{
				{0, 0, true, false},
			},
			Expected: []byte{0x00},
		},
		{
			Name: "Multi Push",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
				{1, true, 0, 1, []byte{0x01}},
				{2, true, 0, 2, []byte{0x02}},
			},
			Rule: []handshakeCachePullRule{
				{0, 0, true, false},
				{1, 0, true, false},
				{2, 0, true, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Rules set order",
			Input: []handshakeCacheItem{
				{2, true, 0, 2, []byte{0x02}},
				{0, true, 0, 0, []byte{0x00}},
				{1, true, 0, 1, []byte{0x01}},
			},
			Rule: []handshakeCachePullRule{
				{0, 0, true, false},
				{1, 0, true, false},
				{2, 0, true, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},

		{
			Name: "Multi Push, Dupe Seqnum",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
				{1, true, 0, 1, []byte{0x01}},
				{1, true, 0, 1, []byte{0x01}},
			},
			Rule: []handshakeCachePullRule{
				{0, 0, true, false},
				{1, 0, true, false},
			},
			Expected: []byte{0x00, 0x01},
		},
		{
			Name: "Multi Push, Dupe Seqnum Client/Server",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
				{1, true, 0, 1, []byte{0x01}},
				{1, false, 0, 1, []byte{0x02}},
			},
			Rule: []handshakeCachePullRule{
				{0, 0, true, false},
				{1, 0, true, false},
				{1, 0, false, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Dupe Seqnum with Unique HandshakeType",
			Input: []handshakeCacheItem{
				{1, true, 0, 0, []byte{0x00}},
				{2, true, 0, 1, []byte{0x01}},
				{3, false, 0, 0, []byte{0x02}},
			},
			Rule: []handshakeCachePullRule{
				{1, 0, true, false},
				{2, 0, true, false},
				{3, 0, false, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Wrong epoch",
			Input: []handshakeCacheItem{
				{1, true, 0, 0, []byte{0x00}},
				{2, true, 1, 1, []byte{0x01}},
				{2, true, 0, 2, []byte{0x11}},
				{3, false, 0, 0, []byte{0x02}},
				{3, false, 1, 0, []byte{0x12}},
				{3, false, 2, 0, []byte{0x12}},
			},
			Rule: []handshakeCachePullRule{
				{1, 0, true, false},
				{2, 1, true, false},
				{3, 0, false, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
	} {
		h := newHandshakeCache()
		for _, i := range test.Input {
			h.push(i.data, i.epoch, i.messageSequence, i.typ, i.isClient)
		}
		verifyData := h.pullAndMerge(test.Rule...)
		if !bytes.Equal(verifyData, test.Expected) {
			t.Errorf("handshakeCache '%s' exp: % 02x actual % 02x", test.Name, test.Expected, verifyData)
		}
	}
}

func TestHandshakeCacheSessionHash(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Rule     []handshakeCachePullRule
		Input    []handshakeCacheItem
		Expected []byte
	}{
		{
			Name: "Standard Handshake",
			Input: []handshakeCacheItem{
				{handshake.TypeClientHello, true, 0, 0, []byte{0x00}},
				{handshake.TypeServerHello, false, 0, 1, []byte{0x01}},
				{handshake.TypeCertificate, false, 0, 2, []byte{0x02}},
				{handshake.TypeServerKeyExchange, false, 0, 3, []byte{0x03}},
				{handshake.TypeServerHelloDone, false, 0, 4, []byte{0x04}},
				{handshake.TypeClientKeyExchange, true, 0, 5, []byte{0x05}},
			},
			Expected: []byte{0x79, 0xf4, 0x73, 0x87, 0x06, 0xfc, 0xe9, 0x65, 0x0a, 0xc6, 0x02, 0x66, 0x67, 0x5c, 0x3c, 0xd0, 0x72, 0x98, 0xb0, 0x99, 0x23, 0x85, 0x0d, 0x52, 0x56, 0x04, 0xd0, 0x40, 0xe6, 0xe4, 0x48, 0xad, 0xc7, 0xdc, 0x22, 0x78, 0x0d, 0x7e, 0x1b, 0x95, 0xbf, 0xea, 0xa8, 0x6a, 0x67, 0x8e, 0x45, 0x52},
		},
		{
			Name: "Handshake With Client Cert Request",
			Input: []handshakeCacheItem{
				{handshake.TypeClientHello, true, 0, 0, []byte{0x00}},
				{handshake.TypeServerHello, false, 0, 1, []byte{0x01}},
				{handshake.TypeCertificate, false, 0, 2, []byte{0x02}},
				{handshake.TypeServerKeyExchange, false, 0, 3, []byte{0x03}},
				{handshake.TypeCertificateRequest, false, 0, 4, []byte{0x04}},
				{handshake.TypeServerHelloDone, false, 0, 5, []byte{0x05}},
				{handshake.TypeClientKeyExchange, true, 0, 6, []byte{0x06}},
			},
			Expected: []byte{0xe6, 0xce, 0x18, 0x96, 0xc9, 0x78, 0x3a, 0x70, 0xac, 0x4c, 0x90, 0x27, 0x6c, 0xc3, 0x7b, 0x37, 0x68, 0x7d, 0x7e, 0x30, 0xc7, 0x53, 0x97, 0x57, 0x62, 0xf9, 0x61, 0xae, 0x37, 0x11, 0x8d, 0x9a, 0x61, 0x02, 0x42, 0x71, 0x6e, 0x83, 0x59, 0xef, 0xc4, 0x97, 0x5a, 0xa9, 0x8c, 0x63, 0x2d, 0xcf},
		},
		{
			Name: "Handshake Ignores after ClientKeyExchange",
			Input: []handshakeCacheItem{
				{handshake.TypeClientHello, true, 0, 0, []byte{0x00}},
				{handshake.TypeServerHello, false, 0, 1, []byte{0x01}},
				{handshake.TypeCertificate, false, 0, 2, []byte{0x02}},
				{handshake.TypeServerKeyExchange, false, 0, 3, []byte{0x03}},
				{handshake.TypeCertificateRequest, false, 0, 4, []byte{0x04}},
				{handshake.TypeServerHelloDone, false, 0, 5, []byte{0x05}},
				{handshake.TypeClientKeyExchange, true, 0, 6, []byte{0x06}},
				{handshake.TypeCertificateVerify, true, 0, 7, []byte{0x07}},
				{handshake.TypeFinished, true, 1, 7, []byte{0x08}},
				{handshake.TypeFinished, false, 1, 7, []byte{0x09}},
			},
			Expected: []byte{0xe6, 0xce, 0x18, 0x96, 0xc9, 0x78, 0x3a, 0x70, 0xac, 0x4c, 0x90, 0x27, 0x6c, 0xc3, 0x7b, 0x37, 0x68, 0x7d, 0x7e, 0x30, 0xc7, 0x53, 0x97, 0x57, 0x62, 0xf9, 0x61, 0xae, 0x37, 0x11, 0x8d, 0x9a, 0x61, 0x02, 0x42, 0x71, 0x6e, 0x83, 0x59, 0xef, 0xc4, 0x97, 0x5a, 0xa9, 0x8c, 0x63, 0x2d, 0xcf},
		},
		{
			Name: "Handshake Ignores wrong epoch",
			Input: []handshakeCacheItem{
				{handshake.TypeClientHello, true, 0, 0, []byte{0x00}},
				{handshake.TypeServerHello, false, 0, 1, []byte{0x01}},
				{handshake.TypeCertificate, false, 0, 2, []byte{0x02}},
				{handshake.TypeServerKeyExchange, false, 0, 3, []byte{0x03}},
				{handshake.TypeCertificateRequest, false, 0, 4, []byte{0x04}},
				{handshake.TypeServerHelloDone, false, 0, 5, []byte{0x05}},
				{handshake.TypeClientKeyExchange, true, 0, 6, []byte{0x06}},
				{handshake.TypeCertificateVerify, true, 0, 7, []byte{0x07}},
				{handshake.TypeFinished, true, 0, 7, []byte{0xf0}},
				{handshake.TypeFinished, false, 0, 7, []byte{0xf1}},
				{handshake.TypeFinished, true, 1, 7, []byte{0x08}},
				{handshake.TypeFinished, false, 1, 7, []byte{0x09}},
				{handshake.TypeFinished, true, 0, 7, []byte{0xf0}},
				{handshake.TypeFinished, false, 0, 7, []byte{0xf1}},
			},
			Expected: []byte{0xe6, 0xce, 0x18, 0x96, 0xc9, 0x78, 0x3a, 0x70, 0xac, 0x4c, 0x90, 0x27, 0x6c, 0xc3, 0x7b, 0x37, 0x68, 0x7d, 0x7e, 0x30, 0xc7, 0x53, 0x97, 0x57, 0x62, 0xf9, 0x61, 0xae, 0x37, 0x11, 0x8d, 0x9a, 0x61, 0x02, 0x42, 0x71, 0x6e, 0x83, 0x59, 0xef, 0xc4, 0x97, 0x5a, 0xa9, 0x8c, 0x63, 0x2d, 0xcf},
		},
	} {
		h := newHandshakeCache()
		for _, i := range test.Input {
			h.push(i.data, i.epoch, i.messageSequence, i.typ, i.isClient)
		}

		cipherSuite := ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{}
		verifyData, err := h.sessionHash(cipherSuite.HashFunc(), 0)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(verifyData, test.Expected) {
			t.Errorf("handshakeCacheSesssionHassh '%s' exp: % 02x actual % 02x", test.Name, test.Expected, verifyData)
		}
	}
}
