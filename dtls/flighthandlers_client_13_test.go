// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

type rawExtension struct {
	typeValue extension.TypeValue
	raw       []byte
}

func (e rawExtension) Marshal() ([]byte, error) {
	return append([]byte(nil), e.raw...), nil
}

func (e rawExtension) Unmarshal([]byte) error {
	return nil
}

func (e rawExtension) TypeValue() extension.TypeValue {
	return e.typeValue
}

func marshalHelloRetryRequestServerHello(
	t *testing.T,
	cfg *handshakeConfig,
	extensions []extension.Extension,
) []byte {
	t.Helper()

	var hrrRandomFixed [handshake.RandomLength]byte
	copy(hrrRandomFixed[:], handshake.HelloRetryRequestRandom())
	var hrrRandom handshake.Random
	hrrRandom.UnmarshalFixed(hrrRandomFixed)

	return marshalServerHello(t, cfg, hrrRandom, extensions)
}

func marshalServerHello(
	t *testing.T,
	cfg *handshakeConfig,
	random handshake.Random,
	extensions []extension.Extension,
) []byte {
	t.Helper()

	return marshalServerHelloWithSequence(t, cfg, random, extensions, 0)
}

func marshalServerHelloWithSequence(
	t *testing.T,
	cfg *handshakeConfig,
	random handshake.Random,
	extensions []extension.Extension,
	seq uint16,
) []byte {
	t.Helper()

	cipherSuiteID := uint16(cfg.LocalCipherSuites[0].ID())
	serverHello := &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            random,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
		Extensions:        extensions,
	}
	rawServerHello, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: seq},
		Message: serverHello,
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	return rawServerHello
}

func generateFlight13_1ClientHello(t *testing.T, cfg *handshakeConfig) *handshake.MessageClientHello {
	t.Helper()

	state := &dtlsstate.State{}

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state: state,
		cfg:   cfg,
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

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	raw, err := hand.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var parsed handshake.Handshake
	if err := parsed.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	if !ok {
		t.Fatal("expected true")
	}

	return clientHello
}

func TestFlight13_1GenerateClientHelloUsesSupportedVersionsVector(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state: state,
		cfg:   cfg,
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

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	raw, err := hand.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var parsed handshake.Handshake
	if err := parsed.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	if !ok {
		t.Fatal("expected true")
	}

	var supportedVersions *extension.SupportedVersions
	for _, ext := range clientHello.Extensions {
		if sv, ok := ext.(*extension.SupportedVersions); ok {
			supportedVersions = sv

			break
		}
	}
	if supportedVersions == nil {
		t.Fatal("expected non-nil")
	}
	expectedSlice := []protocol.Version{protocol.Version1_3}
	if !reflect.DeepEqual(expectedSlice, supportedVersions.Versions) {
		// The condition now correctly evaluates to a boolean
		t.Errorf("Expected version list to match standard supported versions.\nExpected: %#v\nGot: %#v", expectedSlice, supportedVersions.Versions)
	}

	selected := supportedVersions.IsSelectedVersion()
	if !selected {
		t.Error("expected true")
	}
}

func TestFlight13_1GenerateClientHelloIncludesSignatureAlgorithms(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.LocalCertSignatureSchemes = cfg.LocalSignatureSchemes[:1]

	clientHello := generateFlight13_1ClientHello(t, cfg)

	var signatureAlgorithms *extension.SupportedSignatureAlgorithms
	var signatureAlgorithmsCert *extension.SignatureAlgorithmsCert
	for _, ext := range clientHello.Extensions {
		switch typed := ext.(type) {
		case *extension.SupportedSignatureAlgorithms:
			signatureAlgorithms = typed
		case *extension.SignatureAlgorithmsCert:
			signatureAlgorithmsCert = typed
		}
	}

	if signatureAlgorithms == nil {
		t.Fatal("expected non-nil")
	}
	if !reflect.DeepEqual(cfg.LocalSignatureSchemes, signatureAlgorithms.SignatureHashAlgorithms) {
		t.Errorf("expected %v, got %v", cfg.LocalSignatureSchemes, signatureAlgorithms.SignatureHashAlgorithms)
	}
	if signatureAlgorithmsCert == nil {
		t.Fatal("expected non-nil")
	}
	if !reflect.DeepEqual(cfg.LocalCertSignatureSchemes, signatureAlgorithmsCert.SignatureHashAlgorithms) {
		t.Errorf("expected %v, got %v", cfg.LocalCertSignatureSchemes, signatureAlgorithmsCert.SignatureHashAlgorithms)
	}
}

func TestFlight13_1GenerateClientHelloIncludesSupportedGroups(t *testing.T) {
	cfg := testHandshakeConfig13(t)

	clientHello := generateFlight13_1ClientHello(t, cfg)

	var supportedGroups *extension.SupportedEllipticCurves
	for _, ext := range clientHello.Extensions {
		if typed, ok := ext.(*extension.SupportedEllipticCurves); ok {
			supportedGroups = typed

			break
		}
	}

	if supportedGroups == nil {
		t.Fatal("expected non-nil")
	}
	if !reflect.DeepEqual(cfg.EllipticCurves, supportedGroups.EllipticCurves) {
		t.Errorf("expected %v, got %v", cfg.EllipticCurves, supportedGroups.EllipticCurves)
	}
}

func TestFlight13_1GenerateRetainsPrivateKeysForAdvertisedShares(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state: state,
		cfg:   cfg,
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

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	raw, err := hand.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var parsed handshake.Handshake
	if parsed.Unmarshal(raw) != nil {
		t.Fatal(parsed.Unmarshal(raw))
	}
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	if !ok {
		t.Fatal("expected true")
	}

	var keyShare *extension.KeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			keyShare = ks

			break
		}
	}
	if keyShare == nil {
		t.Fatal("expected non-nil")
	}
	if len(keyShare.ClientShares) != len(cfg.EllipticCurves) {
		t.Fatalf("wrong length: got %d, want %d", len(keyShare.ClientShares), len(cfg.EllipticCurves))
	}
	if len(state.LocalKeyEntries) != len(keyShare.ClientShares) {
		t.Fatalf("wrong length: got %d, want %d", len(state.LocalKeyEntries), len(keyShare.ClientShares))
	}
	if len(state.LocalKeypairs) != len(keyShare.ClientShares) {
		t.Fatalf("wrong length: got %d, want %d", len(state.LocalKeypairs), len(keyShare.ClientShares))
	}

	for _, entry := range keyShare.ClientShares {
		t.Run(entry.Group.String(), func(t *testing.T) {
			localKeypair, ok := state.LocalKeypairs[entry.Group]
			if !ok {
				t.Fatal("expected true")
			}
			if !bytes.Equal(entry.KeyExchange, localKeypair.PublicKey) {
				t.Fatalf("expected %v, got %v", entry.KeyExchange, localKeypair.PublicKey)
			}

			peerKeypair, err := elliptic.GenerateKeypair(entry.Group)
			if err != nil {
				t.Fatal(err)
			}

			localSecret, err := prf.PreMasterSecret(peerKeypair.PublicKey, localKeypair.PrivateKey, entry.Group)
			if err != nil {
				t.Fatal(err)
			}

			peerSecret, err := prf.PreMasterSecret(localKeypair.PublicKey, peerKeypair.PrivateKey, entry.Group)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(peerSecret, localSecret) {
				t.Errorf("expected %v, got %v", peerSecret, localSecret)
			}
		})
	}
}

func TestFlight13_1GenerateClientHelloIncludesX25519MLKEM768KeyShare(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768}
	state := &dtlsstate.State{}

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state: state,
		cfg:   cfg,
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

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	raw, err := hand.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var parsed handshake.Handshake
	if err = parsed.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	if !ok {
		t.Fatal("expected true")
	}

	var keyShare *extension.KeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			keyShare = ks

			break
		}
	}
	if keyShare == nil {
		t.Fatal("expected non-nil")
	}
	if len(keyShare.ClientShares) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(keyShare.ClientShares))
	}
	if elliptic.X25519MLKEM768 != keyShare.ClientShares[0].Group {
		t.Errorf("expected %v, got %v", elliptic.X25519MLKEM768, keyShare.ClientShares[0].Group)
	}
	if len(keyShare.ClientShares[0].KeyExchange) != elliptic.X25519MLKEM768ClientPublicKeySize {
		t.Errorf("wrong length: got %d, want %d", len(keyShare.ClientShares[0].KeyExchange), elliptic.X25519MLKEM768ClientPublicKeySize)
	}

	localKeypair := state.LocalKeypairs[elliptic.X25519MLKEM768]
	if localKeypair == nil {
		t.Fatal("expected non-nil")
	}
	serverKeypair, err := elliptic.GenerateKeypairForPeer(elliptic.X25519MLKEM768, localKeypair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(serverKeypair.PublicKey) != elliptic.X25519MLKEM768ServerPublicKeySize {
		t.Errorf("wrong length: got %d, want %d", len(serverKeypair.PublicKey), elliptic.X25519MLKEM768ServerPublicKeySize)
	}

	clientSecret, err := prf.PreMasterSecret(
		serverKeypair.PublicKey,
		localKeypair.PrivateKey,
		elliptic.X25519MLKEM768,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverSecret, err := prf.PreMasterSecret(
		localKeypair.PublicKey,
		serverKeypair.PrivateKey,
		elliptic.X25519MLKEM768,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(serverSecret, clientSecret) {
		t.Errorf("expected %v, got %v", serverSecret, clientSecret)
	}
	if len(clientSecret) != elliptic.X25519MLKEM768SharedSecretSize {
		t.Errorf("wrong length: got %d, want %d", len(clientSecret), elliptic.X25519MLKEM768SharedSecretSize)
	}
}

func TestFlight13_1ParseStoresHelloRetryRequestSelectedGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			&extension.SupportedVersions{
				Versions:        []protocol.Version{protocol.Version1_3},
				SelectedVersion: true,
			},
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := &dtlsstate.State{}
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight1, context.Background(), &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	if err != nil {
		t.Fatal(err)
	}
	if dtlsAlert != nil {
		t.Fatalf("expected nil, got %v", dtlsAlert)
	}
	if dtlsflight13.Flight3 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight3, nextFlight)
	}
	entries := *state.RemoteKeyEntries
	if len(entries) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(entries))
	}
	if selectedGroup != entries[0].Group {
		t.Errorf("expected %v, got %v", selectedGroup, entries[0].Group)
	}
	if len(entries[0].KeyExchange) != 0 {
		t.Error("expected empty")
	}
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithoutSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := &dtlsstate.State{}
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight1, context.Background(), &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	if !errors.Is(err, dtlserrors.ErrInvalidHelloRetryRequest) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidHelloRetryRequest, err)
	}
	if dtlsAlert == nil {
		t.Fatal("expected non-nil")
	}
	if alert.Fatal != dtlsAlert.Level {
		t.Errorf("expected %v, got %v", alert.Fatal, dtlsAlert.Level)
	}
	if alert.IllegalParameter != dtlsAlert.Description {
		t.Errorf("expected %v, got %v", alert.IllegalParameter, dtlsAlert.Description)
	}
	if nextFlight != 0 {
		t.Errorf("expected zero")
	}
	if state.RemoteKeyEntries != nil {
		t.Errorf("expected nil, got %v", state.RemoteKeyEntries)
	}
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithWrongSelectedVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			&extension.SupportedVersions{
				Versions:        []protocol.Version{protocol.Version1_2},
				SelectedVersion: true,
			},
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := &dtlsstate.State{}
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight1, context.Background(), &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	if !errors.Is(err, dtlserrors.ErrUnsupportedProtocolVersion) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrUnsupportedProtocolVersion, err)
	}
	if dtlsAlert == nil {
		t.Fatal("expected non-nil")
	}
	if alert.Fatal != dtlsAlert.Level {
		t.Errorf("expected %v, got %v", alert.Fatal, dtlsAlert.Level)
	}
	if alert.ProtocolVersion != dtlsAlert.Description {
		t.Errorf("expected %v, got %v", alert.ProtocolVersion, dtlsAlert.Description)
	}
	if nextFlight != 0 {
		t.Errorf("expected zero")
	}
	if state.RemoteKeyEntries != nil {
		t.Errorf("expected nil, got %v", state.RemoteKeyEntries)
	}
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithClientHelloSupportedVersionsEncoding(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			rawExtension{
				typeValue: extension.SupportedVersionsTypeValue,
				raw: []byte{
					0x00, 0x2b, // supported_versions
					0x00, 0x03, // extension_data length
					0x02,       // ClientHello vector length
					0xfe, 0xfc, // DTLS v1.3
				},
			},
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := &dtlsstate.State{}
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight1, context.Background(), &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	if !errors.Is(err, dtlserrors.ErrInvalidHelloRetryRequest) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidHelloRetryRequest, err)
	}
	if dtlsAlert == nil {
		t.Fatal("expected non-nil")
	}
	if alert.Fatal != dtlsAlert.Level {
		t.Errorf("expected %v, got %v", alert.Fatal, dtlsAlert.Level)
	}
	if alert.IllegalParameter != dtlsAlert.Description {
		t.Errorf("expected %v, got %v", alert.IllegalParameter, dtlsAlert.Description)
	}
	if nextFlight != 0 {
		t.Errorf("expected zero")
	}
	if state.RemoteKeyEntries != nil {
		t.Errorf("expected nil, got %v", state.RemoteKeyEntries)
	}
}

func TestPickVersionFromServerResponseRejectsHelloRetryRequestWithoutSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.MinVersion = protocol.Version1_2
	cfg.MaxVersion = protocol.Version1_3
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	conn := &Conn{
		handshakeCache:  dtlsflight.NewCache(),
		handshakeConfig: cfg,
	}
	conn.handshakeCache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	ok, err := conn.pickVersionFromServerResponse()

	if !errors.Is(err, dtlserrors.ErrInvalidHelloRetryRequest) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidHelloRetryRequest, err)
	}
	if ok {
		t.Error("expected false")
	}
	if (protocol.Version{}) != conn.state.LocalVersion {
		t.Errorf("expected %v, got %v", protocol.Version{}, conn.state.LocalVersion)
	}
}

func TestPickVersionFromServerResponseRejectsServerHelloWithClientHelloSupportedVersionsEncoding(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.MinVersion = protocol.Version1_2
	cfg.MaxVersion = protocol.Version1_3
	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}

	rawServerHello := marshalServerHello(
		t,
		cfg,
		random,
		[]extension.Extension{
			rawExtension{
				typeValue: extension.SupportedVersionsTypeValue,
				raw: []byte{
					0x00, 0x2b, // supported_versions
					0x00, 0x03, // extension_data length
					0x02,       // ClientHello vector length
					0xfe, 0xfc, // DTLS v1.3
				},
			},
		},
	)

	conn := &Conn{
		handshakeCache:  dtlsflight.NewCache(),
		handshakeConfig: cfg,
	}
	conn.handshakeCache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	ok, err := conn.pickVersionFromServerResponse()

	if !errors.Is(err, dtlserrors.ErrInvalidServerHello) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidServerHello, err)
	}
	if ok {
		t.Error("expected false")
	}
	if (protocol.Version{}) != conn.state.LocalVersion {
		t.Errorf("expected %v, got %v", protocol.Version{}, conn.state.LocalVersion)
	}
}

func TestFlight13_3GenerateRejectsWithoutCommonVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	result := state.LocalRandom.Populate()
	if result == nil { // Check if the returned value is nil
		t.Fatal("state.LocalRandom.Populate() returned nil")
	}

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight3, &handshakeContext13{
		state: state,
		cfg:   cfg,
	})

	if !errors.Is(err, dtlserrors.ErrNoCommonProtocolVersion) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrNoCommonProtocolVersion, err)
	}
	if dtlsAlert != nil {
		t.Fatalf("expected nil, got %v", dtlsAlert)
	}
	if pkts != nil {
		t.Fatalf("expected nil, got %v", pkts)
	}
}

func TestFlight13_3GenerateIncludesCookieAndSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{
		Cookie:         []byte{0x01, 0x02, 0x03, 0x04},
		RemoteVersions: []protocol.Version{protocol.Version1_3},
	}
	result := state.LocalRandom.Populate()
	if result == nil { // Check if the returned value is nil
		t.Fatal("state.LocalRandom.Populate() returned nil")
	}

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight3, &handshakeContext13{
		state: state,
		cfg:   cfg,
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

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	raw, err := hand.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var parsed handshake.Handshake
	if parsed.Unmarshal(raw) != nil {
		t.Fatal(parsed.Unmarshal(raw))
	}
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	if !ok {
		t.Fatal("expected true")
	}

	var supportedVersions *extension.SupportedVersions
	for _, ext := range clientHello.Extensions {
		if sv, ok := ext.(*extension.SupportedVersions); ok {
			supportedVersions = sv

			break
		}
	}
	if supportedVersions == nil {
		t.Fatal("expected non-nil")
	}
	if !reflect.DeepEqual([]protocol.Version{protocol.Version1_3}, supportedVersions.Versions) {
		t.Errorf("expected %v, got %v", []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)
	}
	if supportedVersions.IsSelectedVersion() {
		t.Error("expected false")
	}

	var signatureAlgorithms *extension.SupportedSignatureAlgorithms
	for _, ext := range clientHello.Extensions {
		if sigAlgs, ok := ext.(*extension.SupportedSignatureAlgorithms); ok {
			signatureAlgorithms = sigAlgs

			break
		}
	}
	if signatureAlgorithms == nil {
		t.Fatal("expected non-nil")
	}
	if !reflect.DeepEqual(cfg.LocalSignatureSchemes, signatureAlgorithms.SignatureHashAlgorithms) {
		t.Errorf("expected %v, got %v", cfg.LocalSignatureSchemes, signatureAlgorithms.SignatureHashAlgorithms)
	}

	var cookieExt *extension.CookieExt
	for _, ext := range clientHello.Extensions {
		if c, ok := ext.(*extension.CookieExt); ok {
			cookieExt = c

			break
		}
	}
	if cookieExt == nil {
		t.Fatal("expected non-nil")
	}
	if !bytes.Equal(state.Cookie, cookieExt.Cookie) {
		t.Errorf("expected %v, got %v", state.Cookie, cookieExt.Cookie)
	}
}

func TestFlight13_3GeneratePrioritizesHelloRetryRequestSelectedGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	originalKeypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	if err != nil {
		t.Fatal(err)
	}
	state := &dtlsstate.State{
		RemoteVersions: []protocol.Version{protocol.Version1_3},
		LocalKeyEntries: []extension.KeyShareEntry{
			{Group: originalKeypair.Curve, KeyExchange: originalKeypair.PublicKey},
		},
		RemoteKeyEntries: &[]extension.KeyShareEntry{{Group: selectedGroup}},
	}
	if err := state.LocalRandom.Populate(); err != nil {
		t.Fatal(err) // Correctly passes the single error object to t.Fatal
	}

	if cfg.LocalCipherSuites[0].ID() != state.CipherSuite.ID() { // FIX APPLIED HERE
		t.Errorf("expected %v, got %v", cfg.LocalCipherSuites[0].ID(), state.CipherSuite.ID())
	}
	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight3, &handshakeContext13{
		state: state,
		cfg:   cfg,
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

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	raw, err := hand.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var parsed handshake.Handshake
	if err := parsed.Unmarshal(raw); err != nil {
		t.Fatalf("Expected successful unmarshaling, but got error: %v", err)
	}
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	if !ok {
		t.Fatal("expected true")
	}

	var keyShare *extension.KeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			keyShare = ks

			break
		}
	}
	if keyShare == nil {
		t.Fatal("expected non-nil")
	}
	if len(keyShare.ClientShares) != 2 {
		t.Fatalf("expected len %d, got %d", 2, len(keyShare.ClientShares))
	}
	if selectedGroup != keyShare.ClientShares[0].Group {
		t.Errorf("expected %v, got %v", selectedGroup, keyShare.ClientShares[0].Group)
	}
	if len(keyShare.ClientShares[0].KeyExchange) == 0 {
		t.Errorf("expected non-empty")
	}
	if elliptic.X25519 != keyShare.ClientShares[1].Group {
		t.Errorf("expected %v, got %v", elliptic.X25519, keyShare.ClientShares[1].Group)
	}

	selectedKeypair := state.LocalKeypairs[selectedGroup]
	if selectedKeypair == nil {
		t.Fatal("expected non-nil")
	}
	if !bytes.Equal(keyShare.ClientShares[0].KeyExchange, selectedKeypair.PublicKey) {
		t.Errorf("expected %v, got %v", keyShare.ClientShares[0].KeyExchange, selectedKeypair.PublicKey)
	}
}

func TestFlight13_3GenerateDoesNotRegenerateAlreadyAdvertisedGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.X25519

	keypair, err := elliptic.GenerateKeypair(selectedGroup)
	if err != nil {
		t.Fatal(err)
	}
	state := &dtlsstate.State{
		RemoteVersions: []protocol.Version{protocol.Version1_3},
		LocalKeyEntries: []extension.KeyShareEntry{
			{Group: keypair.Curve, KeyExchange: keypair.PublicKey},
		},
		RemoteKeyEntries: &[]extension.KeyShareEntry{{Group: selectedGroup}},
	}
	if err := state.LocalRandom.Populate(); err != nil {
		t.Fatal(err)
	}

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight3, &handshakeContext13{
		state: state,
		cfg:   cfg,
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

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	raw, err := hand.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var parsed handshake.Handshake
	if err := parsed.Unmarshal(raw); err != nil {
		t.Fatalf("Expected successful unmarshaling, but got error: %v", err)
	}
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	if !ok {
		t.Fatal("expected true")
	}

	var keyShare *extension.KeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			keyShare = ks

			break
		}
	}
	if keyShare == nil {
		t.Fatal("expected non-nil")
	}
	if len(keyShare.ClientShares) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(keyShare.ClientShares))
	}
	if selectedGroup != keyShare.ClientShares[0].Group {
		t.Errorf("expected %v, got %v", selectedGroup, keyShare.ClientShares[0].Group)
	}
}

func TestFlight13_3ParseNegotiatesVersionCipherAndKeyShare(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	transcript := newHandshakeTranscript13()
	clientHello, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{state: state, cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}
	appended, err := appendClientHelloInitialFlights13(transcript, clientHello)
	if err != nil {
		t.Fatal(err)
	}
	if !appended {
		t.Fatal("expected true")
	}
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello[0])

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	if err != nil {
		t.Fatal(err)
	}

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01, 0x02, 0x03}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})
	serverHelloCanonical, err := canonicalHandshake13(rawServerHello)
	if err != nil {
		t.Fatal(err)
	}

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cache.Push(rawEncryptedExtensions, cfg.InitialEpoch+1, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight3, context.Background(), &handshakeContext13{
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
	if dtlsflight13.Flight5 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight5, nextFlight)
	}

	if protocol.Version1_3 != state.LocalVersion {
		t.Errorf("expected %v, got %v", protocol.Version1_3, state.LocalVersion)
	}
	if !reflect.DeepEqual([]protocol.Version{protocol.Version1_3}, state.RemoteVersions) {
		t.Errorf("expected %v, got %v", []protocol.Version{protocol.Version1_3}, state.RemoteVersions)
	}
	if state.CipherSuite == nil {
		t.Fatal("expected non-nil")
	}
	if cfg.LocalCipherSuites[0].ID() != state.CipherSuite.ID() {
		t.Errorf("expected %v, got %v", cfg.LocalCipherSuites[0].ID(), state.CipherSuite.ID())
	}
	if group != state.NamedCurve {
		t.Errorf("expected %v, got %v", group, state.NamedCurve)
	}
	if random.RandomBytes != state.RemoteRandom.RandomBytes {
		t.Errorf("expected %v, got %v", random.RandomBytes, state.RemoteRandom.RandomBytes)
	}
	if state.RemoteKeyEntries == nil {
		t.Fatal("expected non-nil")
	}
	if len(*state.RemoteKeyEntries) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(*state.RemoteKeyEntries))
	}
	if group != (*state.RemoteKeyEntries)[0].Group {
		t.Errorf("expected %v, got %v", group, (*state.RemoteKeyEntries)[0].Group)
	}

	clientKeypair := state.LocalKeypairs[group]
	if clientKeypair == nil {
		t.Fatal("expected non-nil")
	}
	expected, err := prf.PreMasterSecret(clientKeypair.PublicKey, serverKeypair.PrivateKey, group)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, state.PreMasterSecret) {
		t.Errorf("expected %v, got %v", expected, state.PreMasterSecret)
	}
	if len(state.PreMasterSecret) == 0 {
		t.Errorf("expected non-empty")
	}
	transcriptHash := hashTranscript13(clientHelloCanonical, serverHelloCanonical)
	expectedSecrets, err := deriveHandshakeTrafficSecrets13(state.CipherSuite.HashFunc(), expected, transcriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expectedSecrets, state.HandshakeTrafficSecrets13) {
		t.Errorf("expected %v, got %v", expectedSecrets, state.HandshakeTrafficSecrets13)
	}
	if reflect.DeepEqual(state.HandshakeTrafficSecrets13.Client, state.HandshakeTrafficSecrets13.Server) {
		t.Errorf("should not equal %v", state.HandshakeTrafficSecrets13.Client)
	}
}

func TestFlight13ClientParseAppendsNoHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	transcript := newHandshakeTranscript13()

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state:      state,
		cfg:        cfg,
		transcript: transcript,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dtlsAlert != nil {
		t.Fatalf("expected nil, got %v", dtlsAlert)
	}
	appended, err := appendClientHelloInitialFlights13(transcript, pkts)
	if err != nil {
		t.Fatal(err)
	}
	if !appended {
		t.Fatal("expected true")
	}
	clientHelloCanonical := canonicalPacketHandshake13(t, pkts[0])

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	if err != nil {
		t.Fatal(err)
	}
	rawServerHello := marshalServerHello(t, cfg, handshake.Random{
		RandomBytes: [handshake.RandomBytesLength]byte{0x01},
	}, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})
	serverHelloCanonical, err := canonicalHandshake13(rawServerHello)
	if err != nil {
		t.Fatal(err)
	}

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cache.Push(rawEncryptedExtensions, cfg.InitialEpoch+1, 1, handshake.TypeEncryptedExtensions, false)
	encryptedExtensionsCanonical, err := canonicalHandshake13(rawEncryptedExtensions)
	if err != nil {
		t.Fatal(err)
	}
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight1, context.Background(), &handshakeContext13{
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
	if dtlsflight13.Flight5 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight5, nextFlight)
	}
	expectedMessages := []transcriptMessage13{
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 0}, typ: handshake.TypeServerHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 1}, typ: handshake.TypeEncryptedExtensions},
	}
	if !reflect.DeepEqual(expectedMessages, transcript.order) {
		t.Errorf("Expected message sequence to be different, got unexpected sequence.\nExpected: %#v\nGot: %#v", expectedMessages, transcript.order)
	}
	expectedTranscript := append(append(append([]byte(nil), clientHelloCanonical...), serverHelloCanonical...),
		encryptedExtensionsCanonical...)
	if !reflect.DeepEqual(expectedTranscript, transcript.transcript) {
		t.Errorf("expected %v, got %v", expectedTranscript, transcript.transcript)
	}
}

func TestFlight13ClientParseAppendsHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	transcript := newHandshakeTranscript13()

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state:      state,
		cfg:        cfg,
		transcript: transcript,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dtlsAlert != nil {
		t.Fatalf("expected nil, got %v", dtlsAlert)
	}
	appended, err := appendClientHelloInitialFlights13(transcript, pkts)
	if err != nil {
		t.Fatal(err)
	}
	if !appended {
		t.Fatal("expected true")
	}
	clientHello1Canonical := canonicalPacketHandshake13(t, pkts[0])

	group := cfg.EllipticCurves[0]
	rawHelloRetryRequest := marshalHelloRetryRequestServerHello(t, cfg, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{SelectedGroup: &group},
	})
	helloRetryRequestCanonical, err := canonicalHandshake13(rawHelloRetryRequest)
	if err != nil {
		t.Fatal(err)
	}

	cache := dtlsflight.NewCache()
	cache.Push(rawHelloRetryRequest, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight1, context.Background(), &handshakeContext13{
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
	if dtlsflight13.Flight3 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight3, nextFlight)
	}

	clientHello2, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight3, &handshakeContext13{
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
	if len(clientHello2) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(clientHello2))
	}
	clientHello2Handshake, ok := clientHello2[0].Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	clientHello2Handshake.Header.MessageSequence = 1
	if clientHello2 == nil {
		t.Fatal("ClientHello 2 packet list cannot be nil for this test case")
	}
	if appendOutboundHandshakeFlight13(transcript, true, state.CipherSuite, clientHello2) == nil {
		t.Fatal("Expected an error, but appendOutboundHandshakeFlight13 returned nil")
	}
	clientHello2Canonical := canonicalPacketHandshake13(t, clientHello2[0])

	serverKeypair, err := elliptic.GenerateKeypair(group)
	if err != nil {
		t.Fatal(err)
	}
	rawServerHello := marshalServerHelloWithSequence(
		t,
		cfg,
		handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x02}},
		[]extension.Extension{
			&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
			&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
		},
		1,
	)
	serverHelloCanonical, err := canonicalHandshake13(rawServerHello)
	if err != nil {
		t.Fatal(err)
	}
	cache.Push(rawServerHello, cfg.InitialEpoch, 1, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 2},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cache.Push(rawEncryptedExtensions, cfg.InitialEpoch+1, 2, handshake.TypeEncryptedExtensions, false)
	encryptedExtensionsCanonical, err := canonicalHandshake13(rawEncryptedExtensions)
	if err != nil {
		t.Fatal(err)
	}

	nextFlight, dtlsAlert, err = flight13ParseForTest(t, dtlsflight13.Flight3, context.Background(), &handshakeContext13{
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
	if dtlsflight13.Flight5 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight5, nextFlight)
	}

	clientHello1Hash := hashTranscript13(clientHello1Canonical)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	expectedTranscript := append(append(append(append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...),
		clientHello2Canonical...), serverHelloCanonical...), encryptedExtensionsCanonical...)
	expectedMessages := []transcriptMessage13{
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 0}, typ: handshake.TypeServerHello},
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 1}, typ: handshake.TypeClientHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 1}, typ: handshake.TypeServerHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 2}, typ: handshake.TypeEncryptedExtensions},
	}
	if !reflect.DeepEqual(expectedMessages, transcript.order) {
		t.Errorf("expected %v, got %v", expectedMessages, transcript.order)
	}
	if !reflect.DeepEqual(expectedTranscript, transcript.transcript) {
		t.Errorf("expected %v, got %v", expectedTranscript, transcript.transcript)
	}
}

func TestFlight13_3ParseKeepsReadingWithoutServerHello(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight3, context.Background(), &handshakeContext13{
		state: state,
		cache: dtlsflight.NewCache(),
		cfg:   cfg,
	})

	if err != nil {
		t.Fatal(err)
	}
	if dtlsAlert != nil {
		t.Fatalf("expected nil, got %v", dtlsAlert)
	}
	if nextFlight != 0 {
		t.Errorf("expected zero")
	}
}

func TestFlight13_3ParseRejectsSecondHelloRetryRequest(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	_, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{state: state, cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}

	rawServerHello := marshalHelloRetryRequestServerHello(t, cfg, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cache.Push(rawEncryptedExtensions, cfg.InitialEpoch+1, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight3, context.Background(), &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	if !errors.Is(err, dtlserrors.ErrUnexpectedSecondHelloRetryRequest) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrUnexpectedSecondHelloRetryRequest, err)
	}
	if dtlsAlert == nil {
		t.Fatal("expected non-nil")
	}
	if alert.Fatal != dtlsAlert.Level {
		t.Errorf("expected %v, got %v", alert.Fatal, dtlsAlert.Level)
	}
	if alert.UnexpectedMessage != dtlsAlert.Description {
		t.Errorf("expected %v, got %v", alert.UnexpectedMessage, dtlsAlert.Description)
	}
	if nextFlight != 0 {
		t.Errorf("expected zero")
	}
}

func TestFlight13_3ParseRejectsWrongLegacyVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	_, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{state: state, cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	if err != nil {
		t.Fatal(err)
	}

	cipherSuiteID := uint16(cfg.LocalCipherSuites[0].ID())
	serverHello := &handshake.MessageServerHello{
		Version:           protocol.Version1_0,
		Random:            handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
		Extensions: []extension.Extension{
			&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
			&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
		},
	}
	rawServerHello, err := (&handshake.Handshake{Message: serverHello}).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cache.Push(rawEncryptedExtensions, cfg.InitialEpoch+1, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight3, context.Background(), &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	if !errors.Is(err, dtlserrors.ErrUnsupportedProtocolVersion) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrUnsupportedProtocolVersion, err)
	}
	if dtlsAlert == nil {
		t.Fatal("expected non-nil")
	}
	if alert.ProtocolVersion != dtlsAlert.Description {
		t.Errorf("expected %v, got %v", alert.ProtocolVersion, dtlsAlert.Description)
	}
	if nextFlight != 0 {
		t.Errorf("expected zero")
	}
}

func TestFlight13_3ParseRejectsMissingSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	_, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{state: state, cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	if err != nil {
		t.Fatal(err)
	}

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cache.Push(rawEncryptedExtensions, cfg.InitialEpoch+1, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight3, context.Background(), &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	if !errors.Is(err, dtlserrors.ErrUnsupportedProtocolVersion) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrUnsupportedProtocolVersion, err)
	}
	if dtlsAlert == nil {
		t.Fatal("expected non-nil")
	}
	if alert.ProtocolVersion != dtlsAlert.Description {
		t.Errorf("expected %v, got %v", alert.ProtocolVersion, dtlsAlert.Description)
	}
	if nextFlight != 0 {
		t.Errorf("expected zero")
	}
}

func TestFlight13_3ParseRejectsMissingKeyShare(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	_, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{state: state, cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cache.Push(rawEncryptedExtensions, cfg.InitialEpoch+1, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight3, context.Background(), &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	if !errors.Is(err, dtlserrors.ErrServerKeyShareMissing) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrServerKeyShareMissing, err)
	}
	if dtlsAlert == nil {
		t.Fatal("expected non-nil")
	}
	if alert.IllegalParameter != dtlsAlert.Description {
		t.Errorf("expected %v, got %v", alert.IllegalParameter, dtlsAlert.Description)
	}
	if nextFlight != 0 {
		t.Errorf("expected zero")
	}
}

func TestFlight13_3ParseRejectsUnofferedKeyShareGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	if err != nil {
		t.Fatal(err)
	}

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cache.Push(rawEncryptedExtensions, cfg.InitialEpoch+1, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight3, context.Background(), &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	if !errors.Is(err, dtlserrors.ErrServerKeyShareUnknownGroup) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrServerKeyShareUnknownGroup, err)
	}
	if dtlsAlert == nil {
		t.Fatal("expected non-nil")
	}
	if alert.IllegalParameter != dtlsAlert.Description {
		t.Errorf("expected %v, got %v", alert.IllegalParameter, dtlsAlert.Description)
	}
	if nextFlight != 0 {
		t.Errorf("expected zero")
	}
}
