// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/logging"
)

func TestHandshakeFSM13OwnsTranscriptAndPropagatesContext(t *testing.T) {
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fsm.transcript == nil {
		t.Fatal("fsm.transcript is nil")
	}

	flightCtx := fsm.flightContext()
	if state != flightCtx.state {
		t.Errorf("state mismatch")
	}
	if cache != flightCtx.cache {
		t.Errorf("cache mismatch")
	}
	if cfg != flightCtx.cfg {
		t.Errorf("cfg mismatch")
	}
	if fsm.transcript != flightCtx.transcript {
		t.Errorf("transcript mismatch")
	}
}

func TestHandshakeFSM13DualStackClientHelloSeedsTranscript(t *testing.T) {
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)
	cfg.ClientHelloMessageHook = func(ch handshake.MessageClientHello) handshake.Message {
		ch.SessionID = []byte{0xaa, 0xbb}

		return &ch
	}

	transcript := newHandshakeTranscript13()
	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dtlsAlert != nil {
		t.Fatalf("expected nil, got %v", dtlsAlert)
	}
	if len(pkts) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(pkts))
	}

	const messageSequence = 7
	content, ok := pkts[0].Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	content.Header.MessageSequence = messageSequence

	expected := canonicalPacketHandshake13(t, pkts[0])
	appended, err := appendClientHelloInitialFlights13(transcript, pkts)
	if err != nil {
		t.Fatal(err)
	}
	if !appended {
		t.Fatal("expected true")
	}

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight1, pkts, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if fsm.transcript == nil {
		t.Fatal("expected non-nil")
	}
	if transcript != fsm.transcript {
		t.Fatalf("expected same pointer")
	}
	if len(fsm.transcript.pending) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(fsm.transcript.pending))
	}
	if len(fsm.transcript.order) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(fsm.transcript.order))
	}

	expectedMessageID := transcriptMessageID13{
		sender: transcriptClient13,
		seq:    messageSequence,
	}
	if !reflect.DeepEqual(expected, fsm.transcript.pending[0]) {
		t.Errorf("expected %v, got %v", expected, fsm.transcript.pending[0])
	}
	if !reflect.DeepEqual(expected, fsm.transcript.transcript) {
		t.Errorf("expected %v, got %v", expected, fsm.transcript.transcript)
	}
	if !reflect.DeepEqual(expectedMessageID, fsm.transcript.order[0].id) {
		t.Errorf("Expected message ID to be %v, got %v", expectedMessageID, fsm.transcript.order[0].id)
	}
	if handshake.TypeClientHello != fsm.transcript.order[0].typ {
		t.Errorf("expected %v, got %v", handshake.TypeClientHello, fsm.transcript.order[0].typ)
	}
}

func TestHandshakeFSM13TranscriptSurvivesStateChangesAndRetransmitSeed(t *testing.T) {
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)
	transcript := newHandshakeTranscript13()

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dtlsAlert != nil {
		t.Fatalf("expected nil, got %v", dtlsAlert)
	}

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight1, pkts, transcript)
	if err != nil {
		t.Fatal(err)
	}

	transcript = fsm.transcript
	before := append([]byte(nil), transcript.transcript...)
	if len(transcript.pending) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(transcript.pending))
	}

	fsm.currentFlight = dtlsflight13.Flight2
	fsm.retransmit = true
	fsm.retransmitInterval *= 2

	if transcript != fsm.transcript {
		t.Errorf("expected same pointer")
	}
	if !reflect.DeepEqual(before, fsm.transcript.transcript) {
		t.Errorf("expected %v, got %v", before, fsm.transcript.transcript)
	}
	if transcript != fsm.flightContext().transcript {
		t.Errorf("expected same pointer")
	}

	if fsm.seedTranscriptFromInitialFlights() != nil {
		t.Fatal(fsm.seedTranscriptFromInitialFlights())
	}
	if transcript != fsm.transcript {
		t.Errorf("expected same pointer")
	}
	if !reflect.DeepEqual(before, fsm.transcript.transcript) {
		t.Errorf("expected %v, got %v", before, fsm.transcript.transcript)
	}
	if len(fsm.transcript.pending) != 1 {
		t.Errorf("expected len %d, got %d", 1, len(fsm.transcript.pending))
	}
}

func TestHandshakeFSM13DualStackClientHelloRequired(t *testing.T) {
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)

	fsm, err := newHandshakeFSM13(
		state, cache, cfg, dtlsflight13.Flight1, []*dtlsflight.Packet{}, newHandshakeTranscript13(),
	)
	if fsm != nil {
		t.Fatalf("expected nil, got %v", fsm)
	}
	if !errors.Is(err, dtlserrors.ErrHandshakeTranscriptMissingClientHello) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrHandshakeTranscriptMissingClientHello, err)
	}
}

func TestHandshakeFSM13PrepareHelloRetryRequestRequiresSeededTranscript(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		CipherSuite:  cfg.LocalCipherSuites[0],
	}
	cache := dtlsflight.NewCache()

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	nextState, err := fsm.prepare(context.Background(), nil)
	if !errors.Is(err, dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid, err)
	}
	if handshakeErrored != nextState {
		t.Errorf("expected %v, got %v", handshakeErrored, nextState)
	}
	if len(fsm.flights) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(fsm.flights))
	}
	if len(fsm.transcript.order) != 0 {
		t.Error("expected empty")
	}
	if len(fsm.transcript.transcript) != 0 {
		t.Error("expected empty")
	}
	if 1 != state.HandshakeSendSequence {
		t.Errorf("expected %v, got %v", 1, state.HandshakeSendSequence)
	}
}

func TestHandshakeFSM13PrepareCommitsOutboundClientHello(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	nextState, err := fsm.prepare(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if handshakeSending != nextState {
		t.Errorf("expected %v, got %v", handshakeSending, nextState)
	}
	if len(fsm.flights) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(fsm.flights))
	}

	expected := canonicalPacketHandshake13(t, fsm.flights[0])
	if len(fsm.transcript.order) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(fsm.transcript.order))
	}
	expectedMessageID := transcriptMessageID13{
		sender: transcriptClient13,
		seq:    0,
	}
	if !reflect.DeepEqual(expectedMessageID, fsm.transcript.order[0].id) {
		t.Errorf("expected %v, got %v", expectedMessageID, fsm.transcript.order[0].id)
	}
	if handshake.TypeClientHello != fsm.transcript.order[0].typ {
		t.Errorf("expected %v, got %v", handshake.TypeClientHello, fsm.transcript.order[0].typ)
	}
	if !reflect.DeepEqual(expected, fsm.transcript.transcript) {
		t.Errorf("expected %v, got %v", expected, fsm.transcript.transcript)
	}
	if 1 != state.HandshakeSendSequence {
		t.Errorf("expected %v, got %v", 1, state.HandshakeSendSequence)
	}
}

func TestHandshakeFSM13PrepareCommitsOutboundHelloRetryRequestWithSeededTranscript(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		CipherSuite:  cfg.LocalCipherSuites[0],
	}
	cache := dtlsflight.NewCache()
	transcript := newHandshakeTranscript13()
	clientHello := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello)
	if appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{clientHello}) != nil {
		t.Fatal(appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{clientHello}))
	}

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight2, nil, transcript)
	if err != nil {
		t.Fatal(err)
	}

	nextState, err := fsm.prepare(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if handshakeSending != nextState {
		t.Errorf("expected %v, got %v", handshakeSending, nextState)
	}
	if len(fsm.flights) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(fsm.flights))
	}

	helloRetryRequestCanonical := canonicalPacketHandshake13(t, fsm.flights[0])
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, hashTranscript13(clientHelloCanonical))
	expectedTranscript := append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...)

	if !reflect.DeepEqual(expectedTranscript, fsm.transcript.transcript) {
		t.Errorf("expected %v, got %v", expectedTranscript, fsm.transcript.transcript)
	}
	if len(fsm.transcript.order) != 2 {
		t.Fatalf("expected len %d, got %d", 2, len(fsm.transcript.order))
	}
	expectedMessageID := transcriptMessageID13{
		sender: transcriptServer13,
		seq:    0,
	}
	if !reflect.DeepEqual(expectedMessageID, fsm.transcript.order[1].id) {
		t.Errorf("Expected message ID to be %v, got %v", expectedMessageID, fsm.transcript.order[1].id)
	}
	if handshake.TypeServerHello != fsm.transcript.order[1].typ {
		t.Errorf("expected %v, got %v", handshake.TypeServerHello, fsm.transcript.order[1].typ)
	}
	if 1 != state.HandshakeSendSequence {
		t.Errorf("expected %v, got %v", 1, state.HandshakeSendSequence)
	}
}

func TestHandshakeFSM13PrepareDerivesTrafficSecretsBeforeEncryptedExtensions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	group := cfg.EllipticCurves[0]
	keypair, err := elliptic.GenerateKeypair(group)
	if err != nil {
		t.Fatal(err)
	}

	state := &dtlsstate.State{
		LocalVersion:    protocol.Version1_3,
		CipherSuite:     cfg.LocalCipherSuites[0],
		LocalKeypair:    keypair,
		LocalRandom:     handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		PreMasterSecret: []byte{0x01, 0x02, 0x03},
	}
	transcript := newHandshakeTranscript13()
	clientHello := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello)
	if appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{clientHello}) != nil {
		t.Fatal(appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{clientHello}))
	}

	fsm, err := newHandshakeFSM13(state, dtlsflight.NewCache(), cfg, dtlsflight13.Flight4, nil, transcript)
	if err != nil {
		t.Fatal(err)
	}

	nextState, err := fsm.prepare(context.Background(), &flightTestConn{})
	if err != nil {
		t.Fatal(err)
	}
	if handshakeSending != nextState {
		t.Errorf("expected %v, got %v", handshakeSending, nextState)
	}
	if len(fsm.flights) != 2 {
		t.Fatalf("expected len %d, got %d", 2, len(fsm.flights))
	}

	serverHelloCanonical := canonicalPacketHandshake13(t, fsm.flights[0])
	encryptedExtensionsCanonical := canonicalPacketHandshake13(t, fsm.flights[1])
	expectedTranscript := append(append(append([]byte(nil), clientHelloCanonical...), serverHelloCanonical...),
		encryptedExtensionsCanonical...)
	if !reflect.DeepEqual(expectedTranscript, fsm.transcript.transcript) {
		t.Errorf("expected %v, got %v", expectedTranscript, fsm.transcript.transcript)
	}
	if !reflect.DeepEqual([]transcriptMessage13{
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 0}, typ: handshake.TypeServerHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 1}, typ: handshake.TypeEncryptedExtensions},
	}, fsm.transcript.order) {
		t.Errorf("expected %v, got %v", []transcriptMessage13{
			{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
			{id: transcriptMessageID13{sender: transcriptServer13, seq: 0}, typ: handshake.TypeServerHello},
			{id: transcriptMessageID13{sender: transcriptServer13, seq: 1}, typ: handshake.TypeEncryptedExtensions},
		}, fsm.transcript.order)
	}

	expectedSecrets, err := deriveHandshakeTrafficSecrets13(
		state.CipherSuite.HashFunc(),
		state.PreMasterSecret,
		hashTranscript13(clientHelloCanonical, serverHelloCanonical),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expectedSecrets, state.HandshakeTrafficSecrets13) {
		t.Errorf("expected %v, got %v", expectedSecrets, state.HandshakeTrafficSecrets13)
	}
}

func canonicalPacketHandshake13(t *testing.T, p *dtlsflight.Packet) []byte {
	t.Helper()

	content, ok := p.Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	raw, err := content.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalHandshake13(raw)
	if err != nil {
		t.Fatal(err)
	}

	return canonical
}

func testHandshakeConfig13(t *testing.T) *handshakeConfig {
	t.Helper()

	cipherSuites, err := parseCipherSuitesForVersions(
		nil,
		nil,
		true,
		false,
		protocol.Version1_3,
		protocol.Version1_3,
	)
	if err != nil {
		t.Fatal(err)
	}

	loggerFactory := logging.NewDefaultLoggerFactory()

	return &handshakeConfig{
		LocalCipherSuites:           cipherSuites,
		EllipticCurves:              defaultCurves,
		InitialRetransmitInterval:   time.Second,
		ExtendedMasterSecret:        dtlsconfig.ExtendedMasterSecretType(RequestExtendedMasterSecret),
		Log:                         loggerFactory.NewLogger("dtls"),
		MinVersion:                  protocol.Version1_3,
		MaxVersion:                  protocol.Version1_3,
		LocalSignatureSchemes:       signaturehash.Algorithms13(),
		LocalCertSignatureSchemes:   nil,
		LocalSRTPProtectionProfiles: nil,
	}
}

func TestAppendOutboundHandshakeFlight13ClientHello(t *testing.T) {
	transcript := newHandshakeTranscript13()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 3)
	expected := canonicalPacketHandshake13(t, pkt)

	err := appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{pkt})
	if err != nil {
		t.Fatal(err)
	}
	if len(transcript.order) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(transcript.order))
	}
	if len(transcript.pending) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(transcript.pending))
	}

	if !reflect.DeepEqual(transcriptMessageID13{sender: transcriptClient13, seq: 3}, transcript.order[0].id) {
		t.Errorf("expected %v, got %v", transcriptMessageID13{sender: transcriptClient13, seq: 3}, transcript.order[0].id)
	}
	if handshake.TypeClientHello != transcript.order[0].typ {
		t.Errorf("expected %v, got %v", handshake.TypeClientHello, transcript.order[0].typ)
	}
	if !reflect.DeepEqual(expected, transcript.pending[0]) {
		t.Errorf("expected %v, got %v", expected, transcript.pending[0])
	}
	if !reflect.DeepEqual(expected, transcript.transcript) {
		t.Errorf("expected %v, got %v", expected, transcript.transcript)
	}
}

func TestAppendOutboundHandshakeFlight13DuplicateNoop(t *testing.T) {
	transcript := newHandshakeTranscript13()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 0)

	if appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{pkt}) != nil {
		t.Fatal(appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{pkt}))
	}
	before := append([]byte(nil), transcript.transcript...)

	if appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{pkt}) != nil {
		t.Fatal(appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{pkt}))
	}
	if !reflect.DeepEqual(before, transcript.transcript) {
		t.Errorf("expected %v, got %v", before, transcript.transcript)
	}
	if len(transcript.order) != 1 {
		t.Errorf("expected len %d, got %d", 1, len(transcript.order))
	}
}

func TestAppendOutboundHandshakeFlight13ChangedSameSequenceFails(t *testing.T) {
	transcript := newHandshakeTranscript13()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	changedPkt := transcriptTestClientHelloPacket13([]byte{0x02}, 0)

	if appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{pkt}) != nil {
		t.Fatal(appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{pkt}))
	}
	err := appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{changedPkt})

	if !errors.Is(err, dtlserrors.ErrHandshakeTranscriptMessageChanged) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrHandshakeTranscriptMessageChanged, err)
	}
}

func TestAppendOutboundHandshakeFlight13HelloRetryRequest(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cipherSuite := cfg.LocalCipherSuites[0]
	transcript := newHandshakeTranscript13()
	clientHello := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	helloRetryRequest := transcriptTestHelloRetryRequestPacket13(t, cipherSuite, 0)

	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello)
	helloRetryRequestCanonical := canonicalPacketHandshake13(t, helloRetryRequest)

	if appendOutboundHandshakeFlight13(transcript, true, cipherSuite, []*dtlsflight.Packet{clientHello}) != nil {
		t.Fatal(appendOutboundHandshakeFlight13(transcript, true, cipherSuite, []*dtlsflight.Packet{clientHello}))
	}
	if appendOutboundHandshakeFlight13(
		transcript, false, cipherSuite, []*dtlsflight.Packet{helloRetryRequest},
	) != nil {
		t.Fatal(appendOutboundHandshakeFlight13(
			transcript, false, cipherSuite, []*dtlsflight.Packet{helloRetryRequest},
		))
	}

	clientHelloHash := hashTranscript13(clientHelloCanonical)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHelloHash)
	expectedTranscript := append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...)
	if !reflect.DeepEqual(expectedTranscript, transcript.transcript) {
		t.Errorf("expected %v, got %v", expectedTranscript, transcript.transcript)
	}

	sum, err := transcript.sum()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hashTranscript13(messageHash, helloRetryRequestCanonical), sum) {
		t.Errorf("expected %v, got %v", hashTranscript13(messageHash, helloRetryRequestCanonical), sum)
	}
	if len(transcript.order) != 2 {
		t.Fatalf("expected len %d, got %d", 2, len(transcript.order))
	}
	if handshake.TypeClientHello != transcript.order[0].typ {
		t.Errorf("expected %v, got %v", handshake.TypeClientHello, transcript.order[0].typ)
	}
	if handshake.TypeServerHello != transcript.order[1].typ {
		t.Errorf("expected %v, got %v", handshake.TypeServerHello, transcript.order[1].typ)
	}

	before := append([]byte(nil), transcript.transcript...)
	if appendOutboundHandshakeFlight13(
		transcript, false, cipherSuite, []*dtlsflight.Packet{helloRetryRequest},
	) != nil {
		t.Fatal(appendOutboundHandshakeFlight13(
			transcript, false, cipherSuite, []*dtlsflight.Packet{helloRetryRequest},
		))
	}
	if !reflect.DeepEqual(before, transcript.transcript) {
		t.Errorf("expected %v, got %v", before, transcript.transcript)
	}
	if len(transcript.order) != 2 {
		t.Errorf("expected len %d, got %d", 2, len(transcript.order))
	}
}

func transcriptTestClientHelloPacket13(sessionID []byte, seq uint16) *dtlsflight.Packet {
	return &dtlsflight.Packet{
		Record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Header: handshake.Header{MessageSequence: seq},
				Message: &handshake.MessageClientHello{
					Version:            protocol.Version1_2,
					SessionID:          sessionID,
					CipherSuiteIDs:     []uint16{uint16(TLS_PSK_WITH_CHACHA20_POLY1305_SHA256)},
					CompressionMethods: defaultCompressionMethods(),
				},
			},
		},
	}
}

func transcriptTestHelloRetryRequestPacket13(tb testing.TB, cipherSuite CipherSuite, seq uint16) *dtlsflight.Packet {
	tb.Helper()

	random := handshake.Random{}
	random.UnmarshalFixed([32]byte(handshake.HelloRetryRequestRandom()))
	cipherSuiteID := uint16(cipherSuite.ID())

	return &dtlsflight.Packet{
		Record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Header: handshake.Header{MessageSequence: seq},
				Message: &handshake.MessageServerHello{
					Version:           protocol.Version1_2,
					Random:            random,
					CipherSuiteID:     &cipherSuiteID,
					CompressionMethod: defaultCompressionMethods()[0],
					Extensions: []extension.Extension{
						&extension.SupportedVersions{
							Versions:        []protocol.Version{protocol.Version1_3},
							SelectedVersion: true,
						},
					},
				},
			},
		},
	}
}
