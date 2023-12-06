// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"testing"
	"time"

	"github.com/pion/dtls/v2/internal/ciphersuite"
	"github.com/pion/dtls/v2/pkg/protocol/alert"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"github.com/pion/logging"
	"github.com/pion/transport/v3/test"
)

type flight1TestMockFlightConn struct{}

func (f *flight1TestMockFlightConn) notify(context.Context, alert.Level, alert.Description) error {
	return nil
}
func (f *flight1TestMockFlightConn) writePackets(context.Context, []*packet) error { return nil }
func (f *flight1TestMockFlightConn) recvHandshake() <-chan chan struct{}           { return nil }
func (f *flight1TestMockFlightConn) setLocalEpoch(uint16)                          {}
func (f *flight1TestMockFlightConn) handleQueuedPackets(context.Context) error     { return nil }
func (f *flight1TestMockFlightConn) sessionKey() []byte                            { return nil }

type flight1TestMockCipherSuite struct {
	ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256

	t *testing.T
}

func (f *flight1TestMockCipherSuite) IsInitialized() bool {
	f.t.Fatal("IsInitialized called with Certificate but not CertificateVerify")
	return true
}

// When "server hello" arrives later than "certificate",
// "server key exchange", "certificate request", "server hello done",
// is it normal for the flight1Parse method to handle it
func TestFlight1_Process_ServerHelloLateArrival(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	mockConn := &flight1TestMockFlightConn{}
	state := &State{
		cipherSuite: &flight1TestMockCipherSuite{t: t},
	}
	cache := newHandshakeCache()
	cfg := &handshakeConfig{
		localSRTPProtectionProfiles: []SRTPProtectionProfile{SRTP_AEAD_AES_128_GCM},
		localCipherSuites:           []CipherSuite{},
	}
	cfg.localCipherSuites = []CipherSuite{cipherSuiteForID(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil)}
	cfg.log = logging.NewDefaultLoggerFactory().NewLogger("dtls")

	serverHello := []byte{
		0x02, 0x00, 0x00, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x62, 0xfe, 0xfd, 0x07, 0x46, 0xb7, 0xbf, 0xde, 0x78,
		0xab, 0x38, 0x69, 0x36, 0x74, 0x10, 0xa6, 0x50, 0x67, 0x7b,
		0x4b, 0x85, 0xdf, 0x71, 0x71, 0x62, 0x3a, 0xb1, 0xd7, 0xa4,
		0x79, 0x6a, 0x38, 0x13, 0x5e, 0xa1, 0x20, 0xbd, 0x64, 0xaf,
		0xb3, 0x36, 0x77, 0x73, 0x8a, 0x62, 0x75, 0xb2, 0x64, 0xbe,
		0xf6, 0x2a, 0xb1, 0x6e, 0x7b, 0xf6, 0x00, 0xd6, 0x24, 0xd5,
		0xb1, 0x1e, 0x54, 0xa3, 0x76, 0xb3, 0xac, 0x76, 0x8f, 0xc0,
		0x2f, 0x00, 0x00, 0x1a, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
		0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0e, 0x00,
		0x05, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x17, 0x00, 0x00,
	}
	certificate1 := []byte{0x0b, 0x00, 0x05, 0x5b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x04, 0xe4, 0x00, 0x05, 0x58, 0x00, 0x05, 0x55, 0x30, 0x82,
		0x05, 0x51, 0x30, 0x82, 0x04, 0x39, 0xa0, 0x03, 0x02, 0x01,
		0x02, 0x02, 0x0c, 0x56, 0x8b, 0xb4, 0x68, 0xed, 0x70, 0xce,
		0xb6, 0x8d, 0x44, 0x65, 0x4b, 0x30, 0x0d, 0x06, 0x09, 0x2a,
		0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
		0x30, 0x66, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
		0x06, 0x13, 0x02, 0x42, 0x45, 0x31, 0x19, 0x30, 0x17, 0x06,
		0x03, 0x55, 0x04, 0x0a, 0x13, 0x10, 0x47, 0x6c, 0x6f, 0x62,
		0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x6e, 0x76, 0x2d,
		0x73, 0x61, 0x31, 0x3c, 0x30, 0x3a, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x13, 0x33, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53,
		0x69, 0x67, 0x6e, 0x20, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69,
		0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x56, 0x61, 0x6c,
		0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x43, 0x41,
		0x20, 0x2d, 0x20, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x20,
		0x2d, 0x20, 0x47, 0x32, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37,
		0x30, 0x34, 0x32, 0x30, 0x31, 0x31, 0x31, 0x39, 0x35, 0x39,
		0x5a, 0x17, 0x0d, 0x31, 0x38, 0x30, 0x34, 0x32, 0x31, 0x31,
		0x31, 0x31, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81, 0x84, 0x31,
		0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
		0x43, 0x4e, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04,
		0x08, 0x13, 0x09, 0x67, 0x75, 0x61, 0x6e, 0x67, 0x64, 0x6f,
		0x6e, 0x67, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04,
		0x07, 0x13, 0x08, 0x73, 0x68, 0x65, 0x6e, 0x7a, 0x68, 0x65,
		0x6e, 0x31, 0x36, 0x30, 0x34, 0x06, 0x03, 0x55, 0x04, 0x0a,
		0x13, 0x2d, 0x54, 0x65, 0x6e, 0x63, 0x65, 0x6e, 0x74, 0x20,
		0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c, 0x6f, 0x67, 0x79,
		0x20, 0x28, 0x53, 0x68, 0x65, 0x6e, 0x7a, 0x68, 0x65, 0x6e,
		0x29, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x79, 0x20,
		0x4c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x31, 0x16, 0x30,
		0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0d, 0x77, 0x65,
		0x62, 0x72, 0x74, 0x63, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f,
		0x6d, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a,
		0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
		0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02,
		0x82, 0x01, 0x01, 0x00, 0xb6, 0x00, 0xa7, 0x09, 0x0a, 0xc4,
		0x96, 0x24, 0x72, 0xa0, 0x09, 0xda, 0xac, 0x63, 0xe4, 0x9a,
		0xfe, 0x8b, 0x9b, 0x99, 0x8c, 0xe3, 0xab, 0x4b, 0x7c, 0xbd,
		0x4f, 0x31, 0x1e, 0x2f, 0xff, 0x34, 0x54, 0xb5, 0xb0, 0x99,
		0xcd, 0x00, 0x7c, 0x5b, 0x12, 0x96, 0xfa, 0x9b, 0x6b, 0x79,
		0xc7, 0xfb, 0x00, 0x53, 0xaf, 0xb6, 0x00, 0x45, 0x46, 0x20,
		0x7d, 0x95, 0xca, 0x86, 0xcc, 0x4b, 0xe8, 0x25, 0x52, 0x5b,
		0x9c, 0xe7, 0x58, 0xcd, 0xd0, 0x8f, 0x4a, 0xd8, 0x77, 0x7d,
		0x45, 0xa0, 0x70, 0xe8, 0x16, 0x45, 0x23, 0xfb, 0xbc, 0x43,
		0x36, 0xdd, 0x5b, 0x8f, 0x01, 0xc3, 0xc0, 0xa2, 0xab, 0x80,
		0xf1, 0x97, 0x72, 0x38, 0xab, 0x6f, 0xa1, 0x28, 0x09, 0xdd,
		0x31, 0x7e, 0x50, 0xc8, 0x51, 0xde, 0x8d, 0x05, 0xbc, 0x72,
		0x79, 0x94, 0x6e, 0xd4, 0xb7, 0xf0, 0x97, 0xd0, 0x76, 0x9c,
		0x9d, 0xb4, 0x34, 0xf1, 0x8a, 0x82, 0x20, 0x9b, 0x24, 0x4b,
		0x38, 0xc9, 0x63, 0xe6, 0x02, 0xf5, 0xb2, 0x9b, 0x70, 0xa4,
		0x97, 0x9f, 0xaa, 0x1f, 0x36, 0x9c, 0xfd, 0x81, 0x93, 0x81,
		0xd7, 0x4e, 0xca, 0xd2, 0xa7, 0x7c, 0x29, 0x9d, 0x28, 0xf2,
		0x3e, 0x3b, 0xea, 0xe6, 0x22, 0x51, 0x8f, 0x0b, 0xe7, 0x65,
		0xa1, 0x28, 0xdd, 0x55, 0x6a, 0x59, 0x53, 0x67, 0xb6, 0xb3,
		0xd2, 0x4c, 0x90, 0x69, 0xd1, 0x1e, 0x62, 0xab, 0x33, 0x47,
		0x29, 0x45, 0x18, 0x1f, 0xeb, 0x6d, 0x13, 0xb4, 0x61, 0xf5,
		0x15, 0x03, 0xf7, 0x4f, 0x9c, 0x4c, 0x2c, 0xae, 0x5e, 0xde,
		0xd2, 0x11, 0x32, 0xb5, 0x17, 0xb5, 0xe8, 0xa3, 0xb2, 0x1f,
		0xc3, 0x9f, 0x78, 0xa1, 0xf5, 0x80, 0xb4, 0x96, 0x90, 0x6b,
		0x77, 0x9e, 0xe9, 0x39, 0x61, 0x2c, 0x18, 0xf5, 0x7b, 0xab,
		0x1e, 0x09, 0x88, 0x7d, 0xc3, 0x75, 0x5e, 0x4d, 0xcf, 0xf3,
		0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0xde, 0x30,
		0x82, 0x01, 0xda, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f,
		0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30,
		0x81, 0xa0, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
		0x01, 0x01, 0x04, 0x81, 0x93, 0x30, 0x81, 0x90, 0x30, 0x4d,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02,
		0x86, 0x41, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x73,
		0x65, 0x63, 0x75, 0x72, 0x65, 0x2e, 0x67, 0x6c, 0x6f, 0x62,
		0x61, 0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d,
		0x2f, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74, 0x2f, 0x67, 0x73,
		0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69,
		0x6f, 0x6e, 0x76, 0x61, 0x6c, 0x73, 0x68, 0x61, 0x32, 0x67,
		0x32, 0x72, 0x31, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x3f, 0x06,
		0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86,
		0x33, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63,
		0x73, 0x70, 0x32, 0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c,
		0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67,
		0x73, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74,
		0x69, 0x6f, 0x6e, 0x76, 0x61, 0x6c, 0x73, 0x68, 0x61, 0x32,
		0x67, 0x32, 0x30, 0x56, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04,
		0x4f, 0x30, 0x4d, 0x30, 0x41, 0x06, 0x09, 0x2b, 0x06, 0x01,
		0x04, 0x01, 0xa0, 0x32, 0x01, 0x14, 0x30, 0x34, 0x30, 0x32,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01,
		0x16, 0x26, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,
		0x77, 0x77, 0x77, 0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c,
		0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x72,
		0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72, 0x79, 0x2f,
		0x30, 0x08, 0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x02,
		0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30,
		0x00, 0x30, 0x49, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x42,
		0x30, 0x40, 0x30, 0x3e, 0xa0, 0x3c, 0xa0, 0x3a, 0x86, 0x38,
		0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c,
		0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x73, 0x69, 0x67,
		0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x73, 0x2f, 0x67,
		0x73, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74,
		0x69, 0x6f, 0x6e, 0x76, 0x61, 0x6c, 0x73, 0x68, 0x61, 0x32,
		0x67, 0x32, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x18, 0x06, 0x03,
		0x55, 0x1d, 0x11, 0x04, 0x11, 0x30, 0x0f, 0x82, 0x0d, 0x77,
		0x65, 0x62, 0x72, 0x74, 0x63, 0x2e, 0x71, 0x71, 0x2e, 0x63,
		0x6f, 0x6d, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04,
		0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
		0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
		0x07, 0x03, 0x02, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
		0x04, 0x16, 0x04, 0x14, 0x28, 0xff, 0xe2, 0x97, 0xf3, 0x6f,
		0x2a, 0xef, 0x0f, 0xbc, 0x4c, 0x61, 0x9b, 0xd9, 0x23, 0x7b,
		0x3a, 0xef, 0xc2, 0xe7, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d,
		0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x96, 0xde, 0x61,
		0xf1, 0xbd, 0x1c, 0x16, 0x29, 0x53, 0x1c, 0xc0, 0xcc, 0x7d,
		0x3b, 0x83, 0x00, 0x40, 0xe6, 0x1a, 0x7c, 0x30, 0x0d, 0x06,
		0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
		0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x30, 0xc1, 0xcc,
		0xd6, 0x97, 0xf7, 0xf5, 0xa7, 0x93, 0xa5, 0x78, 0xc8, 0xcb,
		0x81, 0x44, 0xd4, 0x1f, 0x2a, 0xa6, 0xc1, 0x48, 0xa8, 0x1a,
		0xbd, 0x17, 0x10, 0x0e, 0xdf, 0x21, 0xea, 0x02, 0x3e, 0xb3,
		0xbd, 0x45, 0x1e, 0x64, 0x85, 0x3f, 0x04, 0x9a, 0xc0, 0x78,
		0xf4, 0x81, 0x2e, 0x38, 0x39, 0x3a, 0x04, 0x2d, 0x5f, 0xec,
		0xc4, 0x10, 0x57, 0xfb, 0x1b, 0x32, 0xe0, 0x8e, 0xfc, 0xe3,
		0x6d, 0x4b, 0xc6, 0xf0, 0x07, 0xb7, 0xc6, 0x19, 0xd7, 0x99,
		0x93, 0xbd, 0x60, 0x58, 0xad, 0xbb, 0x94, 0xcf, 0xd8, 0x05,
		0x5c, 0x14, 0x70, 0xec, 0x2e, 0xb7, 0x60, 0x52, 0x3c, 0xd3,
		0x03, 0xf8, 0xcd, 0xe5, 0x4e, 0x84, 0xcf, 0xef, 0x2f, 0x12,
		0xdd, 0x74, 0xfd, 0x95, 0x9d, 0x03, 0xa9, 0x81, 0x18, 0x3a,
		0x6e, 0xe6, 0xc2, 0xdd, 0x07, 0x1e, 0xea, 0x8c, 0xe6, 0xd9,
		0x31, 0x72, 0x63, 0x25, 0xcd, 0xf2, 0x19, 0xf2, 0x4e, 0x3c,
		0x18, 0xfb, 0xb2, 0x74,
	}
	certificate2 := []byte{
		0x0b, 0x00, 0x05, 0x5b, 0x00, 0x01, 0x00, 0x04, 0xe4, 0x00,
		0x00, 0x77, 0xc1, 0x6b, 0x67, 0xec, 0x34, 0x05, 0xe8, 0x63,
		0xfc, 0x74, 0x4b, 0x11, 0x3f, 0x3a, 0xe4, 0x4e, 0x06, 0x89,
		0x96, 0x24, 0x3c, 0x15, 0x83, 0xc5, 0x1d, 0xeb, 0xc0, 0x19,
		0x71, 0x35, 0x6c, 0xfa, 0xf1, 0x51, 0x06, 0x0e, 0x8e, 0xfb,
		0x9b, 0x4e, 0xaa, 0x50, 0x24, 0x77, 0xac, 0x86, 0x14, 0x50,
		0x52, 0x35, 0x68, 0x15, 0x9b, 0xdd, 0x8b, 0xdb, 0x83, 0x1d,
		0xed, 0x45, 0x05, 0x78, 0x53, 0xd6, 0xc4, 0x21, 0xaf, 0x68,
		0x45, 0x91, 0xe7, 0x30, 0x36, 0x4c, 0xb1, 0xfb, 0xf1, 0x65,
		0x9a, 0xe4, 0x49, 0x90, 0x1c, 0x0c, 0xa8, 0x63, 0xe9, 0x04,
		0xe3, 0x17, 0x61, 0x8d, 0x20, 0x29, 0xca, 0x41, 0xa6, 0x8b,
		0x32, 0x53, 0xa5, 0x84, 0x29, 0x5a, 0x62, 0xe7, 0x84, 0x38,
		0x32, 0x56, 0xbb, 0x8b, 0xbc, 0x25, 0xc7, 0xa3, 0x28, 0x3b,
		0x35,
	}
	serverKeyExchange := []byte{
		0x0c, 0x00, 0x01, 0x28, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x28, 0x03, 0x00, 0x1d, 0x20, 0x59, 0xa2, 0x0f, 0xc4,
		0x7b, 0xd8, 0x03, 0xf6, 0xb0, 0xcf, 0x5d, 0xf0, 0x45, 0x7f,
		0x7e, 0xf2, 0x98, 0xab, 0xc0, 0x24, 0xf1, 0xdf, 0xba, 0x63,
		0x3e, 0xfb, 0xe5, 0x02, 0x31, 0xcf, 0xd1, 0x05, 0x04, 0x01,
		0x01, 0x00, 0x7b, 0x52, 0x9c, 0xe7, 0x54, 0x8b, 0xb0, 0xc9,
		0xfd, 0xaf, 0xe2, 0x91, 0x19, 0x9d, 0x6c, 0xb8, 0xbe, 0xa5,
		0xe1, 0x48, 0xa0, 0xfd, 0xc5, 0x76, 0x62, 0x47, 0xf2, 0xd1,
		0x35, 0x76, 0x4e, 0x33, 0xf4, 0xa1, 0xf1, 0x58, 0xdc, 0xd5,
		0x45, 0x3f, 0x76, 0x64, 0x40, 0xba, 0x32, 0xe3, 0x07, 0xb7,
		0x4b, 0xbe, 0xe2, 0x77, 0x99, 0xad, 0x11, 0x73, 0x54, 0xe6,
		0xbb, 0xfb, 0xd4, 0xb1, 0x83, 0x9f, 0xc6, 0x50, 0xc6, 0xd8,
		0xbb, 0x92, 0x0d, 0x93, 0xf9, 0x63, 0x29, 0xf9, 0xc3, 0xce,
		0x24, 0x40, 0x29, 0x95, 0x43, 0xf0, 0x32, 0x00, 0x21, 0xde,
		0xdf, 0x64, 0xfe, 0xb6, 0x11, 0xa0, 0x11, 0x44, 0x12, 0x2a,
		0x1c, 0x96, 0x44, 0x4b, 0x79, 0x31, 0x23, 0x46, 0x4e, 0xe8,
		0x16, 0x5b, 0xf5, 0x9a, 0x5f, 0x51, 0x10, 0x5b, 0x11, 0xa3,
		0xb8, 0x1f, 0xb7, 0xf1, 0x11, 0xad, 0x05, 0x82, 0x2b, 0xc3,
		0x65, 0x8c, 0x41, 0xb4, 0x8e, 0x60, 0x42, 0x89, 0x92, 0xd1,
		0x83, 0x73, 0xe7, 0x35, 0xb4, 0xc9, 0xd1, 0xbc, 0x5c, 0x84,
		0x5b, 0xdb, 0x44, 0x34, 0xea, 0xd8, 0x06, 0xe4, 0xfb, 0xbd,
		0x40, 0x35, 0x18, 0x60, 0x33, 0xb6, 0xed, 0xbc, 0x9b, 0x3a,
		0xff, 0x2f, 0xa1, 0xe8, 0x5d, 0x5c, 0xbb, 0xe8, 0xe1, 0xa6,
		0xbb, 0x84, 0x0f, 0x50, 0x51, 0x0d, 0xa5, 0x8f, 0x96, 0xb6,
		0x35, 0x37, 0x7b, 0x58, 0xaf, 0x4f, 0x77, 0x9d, 0x5d, 0xb2,
		0xff, 0x5f, 0xd6, 0xb8, 0x82, 0x64, 0x5f, 0x79, 0xd0, 0x06,
		0x44, 0x6d, 0x3a, 0x82, 0x25, 0x21, 0xca, 0xbb, 0xa0, 0x79,
		0xdd, 0x6e, 0x15, 0xb6, 0x57, 0x9b, 0x04, 0x84, 0x63, 0x88,
		0x1d, 0x41, 0xff, 0xe1, 0x20, 0x61, 0xd5, 0x3f, 0xc7, 0xca,
		0x0c, 0xd9, 0xe0, 0x74, 0x86, 0x78, 0xed, 0x60, 0x18, 0x2d,
		0x9e, 0x69, 0x66, 0x77, 0xf7, 0xd0, 0xe9, 0x9c,
	}
	certificateRequest := []byte{
		0x0d, 0x00, 0x00, 0x26, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x26, 0x03, 0x01, 0x02, 0x40, 0x00, 0x1e, 0x06, 0x01,
		0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03,
		0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02,
		0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x00,
	}
	serverHelloDone := []byte{
		0x0e, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	cache.push(certificate2, 0, 2, handshake.TypeCertificate, false)
	cache.push(serverKeyExchange, 0, 3, handshake.TypeServerKeyExchange, false)
	cache.push(certificateRequest, 0, 4, handshake.TypeCertificateRequest, false)
	cache.push(serverHelloDone, 0, 5, handshake.TypeServerHelloDone, false)

	if _, alt, err := flight1Parse(context.TODO(), mockConn, state, cache, cfg); err != nil {
		t.Fatal(err)
	} else if alt != nil {
		t.Fatal(alt.String())
	}

	cache.push(serverHello, 0, 0, handshake.TypeServerHello, false)
	cache.push(certificate1, 0, 1, handshake.TypeCertificate, false)
	if _, alt, err := flight1Parse(context.TODO(), mockConn, state, cache, cfg); err != nil {
		t.Fatal(err)
	} else if alt != nil {
		t.Fatal(alt.String())
	}
}
