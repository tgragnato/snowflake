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

func TestFlight13_0ParseSelectsNegotiatedGroupWithoutGeneratingKeypair(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.P384, elliptic.P256}

	clientKeypair, err := elliptic.GenerateKeypair(elliptic.P384)
	if err != nil {
		t.Fatal(err)
	}
	staleServerKeypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	if err != nil {
		t.Fatal(err)
	}

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: defaultCompressionMethods(),
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.P384},
			},
			&extension.KeyShare{
				ClientShares: []extension.KeyShareEntry{
					{Group: elliptic.P384, KeyExchange: clientKeypair.PublicKey},
				},
			},
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
		},
	}
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		NamedCurve:   elliptic.X25519,
		LocalKeypair: staleServerKeypair,
	}
	cache := dtlsflight.NewCache()
	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
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
	if dtlsflight13.Flight2 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight2, nextFlight)
	}
	if elliptic.P384 != state.NamedCurve {
		t.Errorf("expected %v, got %v", elliptic.P384, state.NamedCurve)
	}
	if staleServerKeypair != state.LocalKeypair {
		t.Errorf("expected same pointer")
	}
	if len(state.PreMasterSecret) != 0 {
		t.Error("expected empty")
	}
}

func TestFlight13_0ParseSelectsX25519MLKEM768WithoutGeneratingKeypair(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768}

	clientKeypair, err := elliptic.GenerateKeypair(elliptic.X25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: defaultCompressionMethods(),
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.X25519MLKEM768},
			},
			&extension.KeyShare{
				ClientShares: []extension.KeyShareEntry{
					{Group: elliptic.X25519MLKEM768, KeyExchange: clientKeypair.PublicKey},
				},
			},
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
		},
	}
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
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
	if dtlsflight13.Flight2 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight2, nextFlight)
	}
	if elliptic.X25519MLKEM768 != state.NamedCurve {
		t.Errorf("expected %v, got %v", elliptic.X25519MLKEM768, state.NamedCurve)
	}
	if state.LocalKeypair != nil {
		t.Errorf("expected nil, got %v", state.LocalKeypair)
	}
	if len(state.PreMasterSecret) != 0 {
		t.Error("expected empty")
	}
}

func TestFlight13_0ParseSelectsServerPreferredGroupFromClientShares(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768, elliptic.X25519}

	mlkemKeypair, err := elliptic.GenerateKeypair(elliptic.X25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	x25519Keypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	if err != nil {
		t.Fatal(err)
	}

	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	pushFlight13_0ClientHello(t, cache, cfg, []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
		},
		&extension.SupportedEllipticCurves{
			EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.X25519MLKEM768},
		},
		&extension.KeyShare{
			ClientShares: []extension.KeyShareEntry{
				{Group: elliptic.X25519, KeyExchange: x25519Keypair.PublicKey},
				{Group: elliptic.X25519MLKEM768, KeyExchange: mlkemKeypair.PublicKey},
			},
		},
		&extension.SupportedVersions{
			Versions: []protocol.Version{protocol.Version1_3},
		},
	})

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
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
	if dtlsflight13.Flight2 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight2, nextFlight)
	}
	if elliptic.X25519MLKEM768 != state.NamedCurve {
		t.Errorf("expected %v, got %v", elliptic.X25519MLKEM768, state.NamedCurve)
	}
	if state.LocalKeypair != nil {
		t.Errorf("expected nil, got %v", state.LocalKeypair)
	}
	if len(state.PreMasterSecret) != 0 {
		t.Error("expected empty")
	}
}

func TestFlight13_0ParseRequestsPreferredGroupWhenShareMissing(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768, elliptic.X25519}

	x25519Keypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	if err != nil {
		t.Fatal(err)
	}

	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	pushFlight13_0ClientHello(t, cache, cfg, []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
		},
		&extension.SupportedEllipticCurves{
			EllipticCurves: cfg.EllipticCurves,
		},
		&extension.KeyShare{
			ClientShares: []extension.KeyShareEntry{
				{Group: elliptic.X25519, KeyExchange: x25519Keypair.PublicKey},
			},
		},
		&extension.SupportedVersions{
			Versions: []protocol.Version{protocol.Version1_3},
		},
	})

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
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
	if dtlsflight13.Flight2 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight2, nextFlight)
	}
	if elliptic.X25519MLKEM768 != state.NamedCurve {
		t.Errorf("expected %v, got %v", elliptic.X25519MLKEM768, state.NamedCurve)
	}

	serverHello := serverHelloFromFlight13_2(t, state, cfg)
	keyShare, ok := findKeyShare(serverHello.Extensions)
	if !ok {
		t.Fatal("expected true")
	}
	if keyShare.SelectedGroup == nil {
		t.Fatal("expected non-nil")
	}
	if elliptic.X25519MLKEM768 != *keyShare.SelectedGroup {
		t.Errorf("expected %v, got %v", elliptic.X25519MLKEM768, *keyShare.SelectedGroup)
	}
}

func TestFlight13_0ParseRejectsClientHelloWithSelectedSupportedVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: defaultCompressionMethods(),
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions:        []protocol.Version{protocol.Version1_3},
				SelectedVersion: true,
			},
		},
	}
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	if !errors.Is(err, dtlserrors.ErrInvalidClientHello) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrInvalidClientHello, err)
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
	if len(state.RemoteVersions) != 0 {
		t.Error("expected empty")
	}
}

func pushFlight13_0ClientHello(
	t *testing.T,
	cache *dtlsflight.Cache,
	cfg *handshakeConfig,
	exts []extension.Extension,
) []byte {
	t.Helper()

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: defaultCompressionMethods(),
		Extensions:         exts,
	}
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	return rawClientHello
}

func requiredClientHello13Extensions(t *testing.T, cfg *handshakeConfig) []extension.Extension {
	t.Helper()

	clientKeypair, err := elliptic.GenerateKeypair(cfg.EllipticCurves[0])
	if err != nil {
		t.Fatal(err)
	}

	return []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
		},
		&extension.SupportedEllipticCurves{
			EllipticCurves: cfg.EllipticCurves,
		},
		&extension.KeyShare{
			ClientShares: []extension.KeyShareEntry{
				{Group: clientKeypair.Curve, KeyExchange: clientKeypair.PublicKey},
			},
		},
		&extension.SupportedVersions{
			Versions: []protocol.Version{protocol.Version1_3},
		},
	}
}

func TestFlight13_0ParseRequiresCertificateAuthClientHelloExtensions(t *testing.T) {
	t.Run("AcceptsSignatureAlgorithmsAndSupportedGroups", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cache := dtlsflight.NewCache()
		pushFlight13_0ClientHello(t, cache, cfg, requiredClientHello13Extensions(t, cfg))

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
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
		if dtlsflight13.Flight2 != nextFlight {
			t.Errorf("expected %v, got %v", dtlsflight13.Flight2, nextFlight)
		}
		if !reflect.DeepEqual(cfg.LocalSignatureSchemes, state.RemoteSignatureSchemes) {
			t.Errorf("expected %v, got %v", cfg.LocalSignatureSchemes, state.RemoteSignatureSchemes)
		}
		if !reflect.DeepEqual(cfg.EllipticCurves, state.RemoteGroups) {
			t.Errorf("expected %v, got %v", cfg.EllipticCurves, state.RemoteGroups)
		}
	})

	t.Run("AllowsPreSharedKeyWithoutCertificateAuthExtensions", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cache := dtlsflight.NewCache()
		binder := make([]byte, 32)
		pushFlight13_0ClientHello(t, cache, cfg, []extension.Extension{
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
			&extension.PreSharedKey{
				Identities: []extension.PskIdentity{
					{Identity: []byte("psk"), ObfuscatedTicketAge: 0},
				},
				Binders: []extension.PskBinderEntry{binder},
			},
		})

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
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
		if dtlsflight13.Flight2 != nextFlight {
			t.Errorf("expected %v, got %v", dtlsflight13.Flight2, nextFlight)
		}
	})

	t.Run("RejectsMissingSignatureAlgorithms", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cache := dtlsflight.NewCache()
		exts := requiredClientHello13Extensions(t, cfg)[1:]
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		if !errors.Is(err, dtlserrors.ErrMissingClientHelloExtension) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrMissingClientHelloExtension, err)
		}
		if dtlsAlert == nil {
			t.Fatal("expected non-nil")
		}
		if dtlsAlert.Level != alert.Fatal || dtlsAlert.Description != alert.MissingExtension {
			t.Errorf("expected alert level %v and description '%v', got level %v and description '%v'", alert.Fatal, alert.MissingExtension, dtlsAlert.Level, dtlsAlert.Description)
		}
		if nextFlight != 0 {
			t.Errorf("expected zero")
		}
	})

	t.Run("RejectsSignatureAlgorithmsCertAsSubstitute", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cache := dtlsflight.NewCache()
		exts := requiredClientHello13Extensions(t, cfg)[1:]
		exts = append([]extension.Extension{
			&extension.SignatureAlgorithmsCert{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
		}, exts...)
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		if !errors.Is(err, dtlserrors.ErrMissingClientHelloExtension) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrMissingClientHelloExtension, err)
		}
		if dtlsAlert == nil {
			t.Fatal("expected non-nil")
		}
		if !reflect.DeepEqual(&alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert) {
			t.Errorf("expected %v, got %v", &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
		}
		if nextFlight != 0 {
			t.Errorf("expected zero")
		}
	})

	t.Run("RejectsMissingSupportedGroups", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cache := dtlsflight.NewCache()
		required := requiredClientHello13Extensions(t, cfg)
		exts := []extension.Extension{required[0], required[2], required[3]}
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		if !errors.Is(err, dtlserrors.ErrMissingClientHelloExtension) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrMissingClientHelloExtension, err)
		}
		if dtlsAlert == nil {
			t.Fatal("expected non-nil")
		}
		if !reflect.DeepEqual(&alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert) {
			t.Errorf("expected %v, got %v", &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
		}
		if nextFlight != 0 {
			t.Errorf("expected zero")
		}
	})
}

func TestFlight13ServerParseAppendsNoHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.InsecureSkipHelloVerify = true
	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	rawClientHello := pushFlight13_0ClientHello(t, cache, cfg, requiredClientHello13Extensions(t, cfg))
	clientHelloCanonical, err := canonicalHandshake13(rawClientHello)
	if err != nil {
		t.Fatal(err)
	}
	transcript := newHandshakeTranscript13()

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
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
	if dtlsflight13.Flight4 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight4, nextFlight)
	}
	if !reflect.DeepEqual([]transcriptMessage13{
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
	}, transcript.order) {
		t.Errorf("expected %v, got %v", []transcriptMessage13{
			{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
		}, transcript.order)
	}
	if !bytes.Equal(clientHelloCanonical, transcript.transcript) {
		t.Errorf("expected %v, got %v", clientHelloCanonical, transcript.transcript)
	}
}

func TestFlight13ServerParseAppendsHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cookie := []byte{0xde, 0xad, 0xbe, 0xef}
	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		Cookie:       cookie,
	}
	cache := dtlsflight.NewCache()
	rawClientHello1 := pushFlight13_0ClientHello(t, cache, cfg, requiredClientHello13Extensions(t, cfg))
	clientHello1Canonical, err := canonicalHandshake13(rawClientHello1)
	if err != nil {
		t.Fatal(err)
	}
	transcript := newHandshakeTranscript13()
	flightCtx := &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	}

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight0, context.Background(), flightCtx)
	if err != nil {
		t.Fatal(err)
	}
	if dtlsAlert != nil {
		t.Fatalf("expected nil, got %v", dtlsAlert)
	}
	if dtlsflight13.Flight2 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight2, nextFlight)
	}

	helloRetryRequest, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight2, flightCtx)
	if err != nil {
		t.Fatal(err)
	}
	if dtlsAlert != nil {
		t.Fatalf("expected nil, got %v", dtlsAlert)
	}
	if len(helloRetryRequest) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(helloRetryRequest))
	}
	if appendOutboundHandshakeFlight13(transcript, false, state.CipherSuite, helloRetryRequest) != nil {
		t.Fatal(appendOutboundHandshakeFlight13(transcript, false, state.CipherSuite, helloRetryRequest))
	}
	helloRetryRequestCanonical := canonicalPacketHandshake13(t, helloRetryRequest[0])

	exts := append(requiredClientHello13Extensions(t, cfg), &extension.CookieExt{Cookie: cookie})
	rawClientHello2 := pushClientHello13WithSequence(t, cache, protocol.Version1_2, 1, exts)
	clientHello2Canonical, err := canonicalHandshake13(rawClientHello2)
	if err != nil {
		t.Fatal(err)
	}

	nextFlight, dtlsAlert, err = flight13ParseForTest(t, dtlsflight13.Flight2, context.Background(), flightCtx)
	if err != nil {
		t.Fatal(err)
	}
	if dtlsAlert != nil {
		t.Fatalf("expected nil, got %v", dtlsAlert)
	}
	if dtlsflight13.Flight4 != nextFlight {
		t.Errorf("expected %v, got %v", dtlsflight13.Flight4, nextFlight)
	}

	clientHello1Hash := hashTranscript13(clientHello1Canonical)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	expectedTranscript := append(append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...),
		clientHello2Canonical...)
	if !reflect.DeepEqual([]transcriptMessage13{
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 0}, typ: handshake.TypeServerHello},
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 1}, typ: handshake.TypeClientHello},
	}, transcript.order) {
		t.Errorf("expected %v, got %v", []transcriptMessage13{
			{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
			{id: transcriptMessageID13{sender: transcriptServer13, seq: 0}, typ: handshake.TypeServerHello},
			{id: transcriptMessageID13{sender: transcriptClient13, seq: 1}, typ: handshake.TypeClientHello},
		}, transcript.order)
	}
	if !bytes.Equal(expectedTranscript, transcript.transcript) {
		t.Errorf("expected %v, got %v", expectedTranscript, transcript.transcript)
	}
}

func serverHelloFromFlight13_2(
	t *testing.T, state *dtlsstate.State, cfg *handshakeConfig,
) *handshake.MessageServerHello {
	t.Helper()

	if state.CipherSuite == nil {
		state.CipherSuite = cfg.LocalCipherSuites[0]
	}
	pkts, dtlsAlert, err := flight13GenerateForTest(
		t, dtlsflight13.Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
	)
	if err != nil {
		t.Fatal(err)
	}
	if dtlsAlert != nil {
		t.Fatalf("expected nil, got %v", dtlsAlert)
	}
	if len(pkts) != 1 {
		t.Fatalf("expected len %d, got %d", 1, len(pkts))
	}

	if pkts[0].Record == nil {
		t.Fatal("expected non-nil")
	}
	if protocol.Version1_2 != pkts[0].Record.Header.Version {
		t.Errorf("expected %v, got %v", protocol.Version1_2, pkts[0].Record.Header.Version)
	}

	content, ok := pkts[0].Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}

	serverHello, ok := content.Message.(*handshake.MessageServerHello)
	if !ok {
		t.Fatal("expected true")
	}

	return serverHello
}

func findSupportedVersions(exts []extension.Extension) (*extension.SupportedVersions, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension.SupportedVersions); ok {
			return typed, true
		}
	}

	return nil, false
}

func findKeyShare(exts []extension.Extension) (*extension.KeyShare, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension.KeyShare); ok {
			return typed, true
		}
	}

	return nil, false
}

func findCookie(exts []extension.Extension) (*extension.CookieExt, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension.CookieExt); ok {
			return typed, true
		}
	}

	return nil, false
}

func TestFlight13_2Generate(t *testing.T) {
	t.Run("ServerHelloIsHelloRetryRequest", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		if protocol.Version1_2 != serverHello.Version {
			t.Errorf("expected %v, got %v", protocol.Version1_2, serverHello.Version)
		}
		if !reflect.DeepEqual([32]byte(handshake.HelloRetryRequestRandom()), serverHello.Random.MarshalFixed()) {
			t.Errorf("expected %v, got %v", [32]byte(handshake.HelloRetryRequestRandom()), serverHello.Random.MarshalFixed())
		}
	})

	t.Run("ResetsHandshakeSendSequence", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{
			LocalVersion:          protocol.Version1_3,
			CipherSuite:           cfg.LocalCipherSuites[0],
			HandshakeSendSequence: 7,
		}

		_, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
		)
		if err != nil {
			t.Fatal(err)
		}
		if dtlsAlert != nil {
			t.Fatalf("expected nil, got %v", dtlsAlert)
		}

		if 0 != state.HandshakeSendSequence {
			t.Errorf("expected %v, got %v", 0, state.HandshakeSendSequence)
		}
	})

	t.Run("RejectsWithoutCipherSuite", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
		)
		if !errors.Is(err, dtlserrors.ErrCipherSuiteUnset) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrCipherSuiteUnset, err)
		}
		if dtlsAlert != nil {
			t.Fatalf("expected nil, got %v", dtlsAlert)
		}
		if pkts != nil {
			t.Fatalf("expected nil, got %v", pkts)
		}
	})

	t.Run("AlwaysIncludesSupportedVersions", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		if !ok {
			t.Fatal("SupportedVersions extension must always be present")
		}
		if !reflect.DeepEqual([]protocol.Version{protocol.Version1_3}, supportedVersions.Versions) {
			t.Errorf("expected %v, got %v", []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)
		}
		if !supportedVersions.IsSelectedVersion() {
			t.Error("expected true")
		}
	})

	t.Run("IncludesCipherSuiteAndCompressionMethod", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		if serverHello.CipherSuiteID == nil {
			t.Fatal("expected non-nil")
		}
		if uint16(cfg.LocalCipherSuites[0].ID()) != *serverHello.CipherSuiteID {
			t.Errorf("expected %v, got %v", uint16(cfg.LocalCipherSuites[0].ID()), *serverHello.CipherSuiteID)
		}
		if serverHello.CompressionMethod == nil {
			t.Fatal("expected non-nil")
		}
		if defaultCompressionMethods()[0] != serverHello.CompressionMethod {
			t.Errorf("expected %v, got %v", defaultCompressionMethods()[0], serverHello.CompressionMethod)
		}

		raw, err := (&handshake.Handshake{Message: serverHello}).Marshal()
		if err != nil {
			t.Fatal(err)
		}

		var parsed handshake.Handshake
		if parsed.Unmarshal(raw) != nil {
			t.Fatal(parsed.Unmarshal(raw))
		}
		parsedServerHello, ok := parsed.Message.(*handshake.MessageServerHello)
		if !ok {
			t.Fatal("expected true")
		}
		if parsedServerHello.CipherSuiteID == nil {
			t.Fatal("expected non-nil")
		}
		if *serverHello.CipherSuiteID != *parsedServerHello.CipherSuiteID {
			t.Errorf("expected %v, got %v", *serverHello.CipherSuiteID, *parsedServerHello.CipherSuiteID)
		}
	})

	t.Run("OmitsKeyShareAndCookieByDefault", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		_, hasKeyShare := findKeyShare(serverHello.Extensions)
		if hasKeyShare {
			t.Error("KeyShare must be omitted when no remote key entries were offered")
		}

		_, hasCookie := findCookie(serverHello.Extensions)
		if hasCookie {
			t.Error("Cookie must be omitted when no cookie is set")
		}

		if len(serverHello.Extensions) != 1 {
			t.Fatalf("expected len %d, got %d", 1, len(serverHello.Extensions))
		}
	})

	t.Run("IncludesKeyShareWhenRemoteKeyEntriesPresent", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, NamedCurve: elliptic.X25519}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		keyShare, ok := findKeyShare(serverHello.Extensions)
		if !ok {
			t.Fatal("KeyShare must be present when remote key entries were offered")
		}
		if keyShare.SelectedGroup == nil {
			t.Fatal("expected non-nil")
		}
		if elliptic.X25519 != *keyShare.SelectedGroup {
			t.Errorf("expected %v, got %v", elliptic.X25519, *keyShare.SelectedGroup)
		}
	})

	t.Run("IncludesCookieWhenSet", func(t *testing.T) {
		cookie := []byte{0x01, 0x02, 0x03, 0x04}
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		cookieExt, ok := findCookie(serverHello.Extensions)
		if !ok {
			t.Fatal("Cookie must be present when set on state")
		}
		if !reflect.DeepEqual(cookie, cookieExt.Cookie) {
			t.Errorf("expected %v, got %v", cookie, cookieExt.Cookie)
		}
	})

	t.Run("IncludesAllExtensionsTogether", func(t *testing.T) {
		cookie := []byte{0xaa, 0xbb}
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, NamedCurve: elliptic.P256, Cookie: cookie}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		if len(serverHello.Extensions) != 3 {
			t.Fatalf("expected len %d, got %d", 3, len(serverHello.Extensions))
		}

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		if !ok {
			t.Fatal("expected true")
		}
		if !reflect.DeepEqual(supportedVersionsRange(cfg.MinVersion, cfg.MaxVersion), supportedVersions.Versions) {
			t.Errorf("expected %v, got %v", supportedVersionsRange(cfg.MinVersion, cfg.MaxVersion), supportedVersions.Versions)
		}

		keyShare, ok := findKeyShare(serverHello.Extensions)
		if !ok {
			t.Fatal("expected true")
		}
		if keyShare.SelectedGroup == nil {
			t.Fatal("expected non-nil")
		}
		if elliptic.P256 != *keyShare.SelectedGroup {
			t.Errorf("expected %v, got %v", elliptic.P256, *keyShare.SelectedGroup)
		}

		cookieExt, ok := findCookie(serverHello.Extensions)
		if !ok {
			t.Fatal("expected true")
		}
		if !bytes.Equal(cookie, cookieExt.Cookie) {
			t.Errorf("expected %v, got %v", cookie, cookieExt.Cookie)
		}
	})
}

func TestFlight13_4Generate(t *testing.T) {
	t.Run("GeneratesServerHelloThenEncryptedExtensions", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		group := cfg.EllipticCurves[0]
		keypair, err := elliptic.GenerateKeypair(group)
		if err != nil {
			t.Fatal(err)
		}

		state := &dtlsstate.State{
			LocalVersion: protocol.Version1_3,
			CipherSuite:  cfg.LocalCipherSuites[0],
			LocalKeypair: keypair,
			LocalRandom:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01, 0x02, 0x03}},
		}

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight4, &handshakeContext13{state: state, cfg: cfg},
		)
		if err != nil {
			t.Fatal(err)
		}
		if dtlsAlert != nil {
			t.Fatalf("expected nil, got %v", dtlsAlert)
		}
		if len(pkts) != 2 {
			t.Fatalf("expected len %d, got %d", 2, len(pkts))
		}
		if uint16(0) != pkts[0].Record.Header.Epoch {
			t.Errorf("expected %v, got %v", uint16(0), pkts[0].Record.Header.Epoch)
		}
		if pkts[0].ShouldEncrypt {
			t.Error("expected false")
		}

		serverHelloHandshake, ok := pkts[0].Record.Content.(*handshake.Handshake)
		if !ok {
			t.Fatal("expected true")
		}
		serverHello, ok := serverHelloHandshake.Message.(*handshake.MessageServerHello)
		if !ok {
			t.Fatal("expected true")
		}
		if protocol.Version1_2 != serverHello.Version {
			t.Errorf("expected %v, got %v", protocol.Version1_2, serverHello.Version)
		}
		if state.LocalRandom != serverHello.Random {
			t.Errorf("expected %v, got %v", state.LocalRandom, serverHello.Random)
		}
		if serverHello.CipherSuiteID == nil {
			t.Fatal("expected non-nil")
		}
		if uint16(cfg.LocalCipherSuites[0].ID()) != *serverHello.CipherSuiteID {
			t.Errorf("expected %v, got %v", uint16(cfg.LocalCipherSuites[0].ID()), *serverHello.CipherSuiteID)
		}

		keyShare, ok := findKeyShare(serverHello.Extensions)
		if !ok {
			t.Fatal("expected true")
		}
		if keyShare.ServerShare == nil {
			t.Fatal("expected non-nil")
		}
		if group != keyShare.ServerShare.Group {
			t.Errorf("expected %v, got %v", group, keyShare.ServerShare.Group)
		}
		if !bytes.Equal(keypair.PublicKey, keyShare.ServerShare.KeyExchange) {
			t.Errorf("expected %v, got %v", keypair.PublicKey, keyShare.ServerShare.KeyExchange)
		}

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		if !ok {
			t.Fatal("expected true")
		}
		if !supportedVersions.IsSelectedVersion() {
			t.Error("expected true")
		}
		if !reflect.DeepEqual([]protocol.Version{protocol.Version1_3}, supportedVersions.Versions) {
			t.Errorf("expected %v, got %v", []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)
		}

		encryptedExtensionsHandshake, ok := pkts[1].Record.Content.(*handshake.Handshake)
		if !ok {
			t.Fatal("expected true")
		}
		if uint16(1) != pkts[1].Record.Header.Epoch {
			t.Errorf("expected %v, got %v", uint16(1), pkts[1].Record.Header.Epoch)
		}
		if !pkts[1].ShouldEncrypt {
			t.Error("expected true")
		}
		if !pkts[1].ResetLocalSequenceNumber {
			t.Error("expected true")
		}
		encryptedExtensions, ok := encryptedExtensionsHandshake.Message.(*handshake.MessageEncryptedExtensions)
		if !ok {
			t.Fatal("expected true")
		}
		if len(encryptedExtensions.Extensions) != 0 {
			t.Error("expected empty")
		}
	})

	t.Run("RejectsWithoutCipherSuite", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight4, &handshakeContext13{state: state, cfg: cfg},
		)
		if !errors.Is(err, dtlserrors.ErrCipherSuiteUnset) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrCipherSuiteUnset, err)
		}
		if dtlsAlert != nil {
			t.Fatalf("expected nil, got %v", dtlsAlert)
		}
		if pkts != nil {
			t.Fatalf("expected nil, got %v", pkts)
		}
	})

	t.Run("RejectsWithoutLocalKeypair", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{
			LocalVersion: protocol.Version1_3,
			CipherSuite:  cfg.LocalCipherSuites[0],
		}

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight4, &handshakeContext13{state: state, cfg: cfg},
		)
		if !errors.Is(err, dtlserrors.ErrServerKeyShareMissing) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrServerKeyShareMissing, err)
		}
		if dtlsAlert != nil {
			t.Fatalf("expected nil, got %v", dtlsAlert)
		}
		if pkts != nil {
			t.Fatalf("expected nil, got %v", pkts)
		}
	})
}

func pushClientHello13(
	t *testing.T,
	cache *dtlsflight.Cache,
	version protocol.Version,
	exts []extension.Extension,
) {
	t.Helper()

	pushClientHello13WithSequence(t, cache, version, 0, exts)
}

func pushClientHello13WithSequence(
	t *testing.T,
	cache *dtlsflight.Cache,
	version protocol.Version,
	seq uint16,
	exts []extension.Extension,
) []byte {
	t.Helper()

	content := &handshake.Handshake{
		Header: handshake.Header{MessageSequence: seq},
		Message: &handshake.MessageClientHello{
			Version:            version,
			Random:             handshake.Random{},
			CipherSuiteIDs:     []uint16{},
			CompressionMethods: defaultCompressionMethods(),
			Extensions:         exts,
		},
	}

	raw, err := content.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	cache.Push(raw, 0, seq, handshake.TypeClientHello, true)

	return raw
}

func flight13_2Context(state *dtlsstate.State, cache *dtlsflight.Cache, cfg *handshakeConfig) *handshakeContext13 {
	return &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: newHandshakeTranscript13(),
	}
}

func TestFlight13_2Parse(t *testing.T) {
	cookie := []byte{0xde, 0xad, 0xbe, 0xef}

	t.Run("AdvancesToFlight4OnMatchingCookie", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension.CookieExt{Cookie: cookie})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		if err != nil {
			t.Fatal(err)
		}
		if dtlsAlert != nil {
			t.Fatalf("expected nil, got %v", dtlsAlert)
		}
		if dtlsflight13.Flight4 != next {
			t.Errorf("expected %v, got %v", dtlsflight13.Flight4, next)
		}
		if 1 != state.HandshakeRecvSequence {
			t.Errorf("expected %v, got %v", 1, state.HandshakeRecvSequence)
		}
	})

	t.Run("GeneratesX25519MLKEM768KeypairAfterMatchingCookie", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768}
		clientKeypair, err := elliptic.GenerateKeypair(elliptic.X25519MLKEM768)
		if err != nil {
			t.Fatal(err)
		}

		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cache := dtlsflight.NewCache()
		pushClientHello13(t, cache, protocol.Version1_2, []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
			&extension.SupportedEllipticCurves{
				EllipticCurves: cfg.EllipticCurves,
			},
			&extension.KeyShare{
				ClientShares: []extension.KeyShareEntry{
					{Group: elliptic.X25519MLKEM768, KeyExchange: clientKeypair.PublicKey},
				},
			},
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		if err != nil {
			t.Fatal(err)
		}
		if dtlsAlert != nil {
			t.Fatalf("expected nil, got %v", dtlsAlert)
		}
		if dtlsflight13.Flight4 != next {
			t.Errorf("expected %v, got %v", dtlsflight13.Flight4, next)
		}
		if state.LocalKeypair == nil {
			t.Fatal("expected non-nil")
		}
		if elliptic.X25519MLKEM768 != state.NamedCurve {
			t.Errorf("expected %v, got %v", elliptic.X25519MLKEM768, state.NamedCurve)
		}
		if elliptic.X25519MLKEM768 != state.LocalKeypair.Curve {
			t.Errorf("expected %v, got %v", elliptic.X25519MLKEM768, state.LocalKeypair.Curve)
		}
		if len(state.LocalKeypair.PublicKey) != elliptic.X25519MLKEM768ServerPublicKeySize {
			t.Errorf("wrong length: got %d, want %d", len(state.LocalKeypair.PublicKey), elliptic.X25519MLKEM768ServerPublicKeySize)
		}

		clientSecret, err := prf.PreMasterSecret(
			state.LocalKeypair.PublicKey,
			clientKeypair.PrivateKey,
			elliptic.X25519MLKEM768,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(clientSecret, state.PreMasterSecret) {
			t.Errorf("expected %v, got %v", clientSecret, state.PreMasterSecret)
		}
		if len(state.PreMasterSecret) != elliptic.X25519MLKEM768SharedSecretSize {
			t.Errorf("wrong length: got %d, want %d", len(state.PreMasterSecret), elliptic.X25519MLKEM768SharedSecretSize)
		}
	})

	t.Run("RejectsUnsupportedSupportedGroupsAfterMatchingCookie", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		cfg.EllipticCurves = []elliptic.Curve{elliptic.P256}
		clientKeypair, err := elliptic.GenerateKeypair(elliptic.P384)
		if err != nil {
			t.Fatal(err)
		}

		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cache := dtlsflight.NewCache()
		pushClientHello13(t, cache, protocol.Version1_2, []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.P384},
			},
			&extension.KeyShare{
				ClientShares: []extension.KeyShareEntry{
					{Group: elliptic.P384, KeyExchange: clientKeypair.PublicKey},
				},
			},
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		if !errors.Is(err, dtlserrors.ErrNoSupportedEllipticCurves) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrNoSupportedEllipticCurves, err)
		}
		if dtlsflight13.Flight(0) != next {
			t.Errorf("expected %v, got %v", dtlsflight13.Flight(0), next)
		}
		if dtlsAlert == nil {
			t.Fatal("expected non-nil")
		}
		if !reflect.DeepEqual(&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlsAlert) {
			t.Errorf("expected %v, got %v", &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlsAlert)
		}
		if len(state.PreMasterSecret) != 0 {
			t.Error("expected empty")
		}
		if state.LocalKeypair != nil {
			t.Errorf("expected nil, got %v", state.LocalKeypair)
		}
		if state.NamedCurve != 0 {
			t.Errorf("expected zero")
		}
	})

	t.Run("KeepsWaitingWhenNoClientHelloCached", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		if err != nil {
			t.Fatal(err)
		}
		if dtlsAlert != nil {
			t.Fatalf("expected nil, got %v", dtlsAlert)
		}
		if dtlsflight13.Flight(0) != next {
			t.Errorf("expected %v, got %v", dtlsflight13.Flight(0), next)
		}
		if 0 != state.HandshakeRecvSequence {
			t.Errorf("expected %v, got %v", 0, state.HandshakeRecvSequence)
		}
	})

	t.Run("KeepsWaitingWhenCookieNotYetEchoed", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie, ServerName: "original.example"}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension.ServerName{ServerName: "poison.example"})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		if err != nil {
			t.Fatal(err)
		}
		if dtlsAlert != nil {
			t.Fatalf("expected nil, got %v", dtlsAlert)
		}
		if dtlsflight13.Flight(0) != next {
			t.Errorf("expected %v, got %v", dtlsflight13.Flight(0), next)
		}
		if 0 != state.HandshakeRecvSequence {
			t.Errorf("expected %v, got %v", 0, state.HandshakeRecvSequence)
		}
		if "original.example" != state.ServerName {
			t.Errorf("expected %v, got %v", "original.example", state.ServerName)
		}
		if len(state.RemoteSignatureSchemes) != 0 {
			t.Error("expected empty")
		}
		if len(state.RemoteGroups) != 0 {
			t.Error("expected empty")
		}
	})

	t.Run("RejectsCookieMismatch", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie, ServerName: "original.example"}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension.ServerName{ServerName: "poison.example"},
			&extension.CookieExt{Cookie: []byte{0x00, 0x01, 0x02, 0x03}})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		if !errors.Is(err, dtlserrors.ErrCookieMismatch) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrCookieMismatch, err)
		}
		if dtlsflight13.Flight(0) != next {
			t.Errorf("expected %v, got %v", dtlsflight13.Flight(0), next)
		}
		if dtlsAlert == nil {
			t.Fatal("expected non-nil")
		}
		if !reflect.DeepEqual(&alert.Alert{Level: alert.Fatal, Description: alert.AccessDenied}, dtlsAlert) {
			t.Errorf("expected %v, got %v", &alert.Alert{Level: alert.Fatal, Description: alert.AccessDenied}, dtlsAlert)
		}
		if 0 != state.HandshakeRecvSequence {
			t.Errorf("expected %v, got %v", 0, state.HandshakeRecvSequence)
		}
		if "original.example" != state.ServerName {
			t.Errorf("expected %v, got %v", "original.example", state.ServerName)
		}
		if len(state.RemoteSignatureSchemes) != 0 {
			t.Error("expected empty")
		}
		if len(state.RemoteGroups) != 0 {
			t.Error("expected empty")
		}
	})

	t.Run("RejectsUnsupportedVersion", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version{Major: 0xfe, Minor: 0xfd - 1}, []extension.Extension{
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		if !errors.Is(err, dtlserrors.ErrUnsupportedProtocolVersion) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrUnsupportedProtocolVersion, err)
		}
		if dtlsflight13.Flight(0) != next {
			t.Errorf("expected %v, got %v", dtlsflight13.Flight(0), next)
		}
		if dtlsAlert == nil {
			t.Fatal("expected non-nil")
		}
		if !reflect.DeepEqual(&alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlsAlert) {
			t.Errorf("expected %v, got %v", &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlsAlert)
		}
	})

	t.Run("RejectsMissingCertificateAuthExtensions", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version1_2, []extension.Extension{
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		if !errors.Is(err, dtlserrors.ErrMissingClientHelloExtension) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrMissingClientHelloExtension, err)
		}
		if dtlsflight13.Flight(0) != next {
			t.Errorf("expected %v, got %v", dtlsflight13.Flight(0), next)
		}
		if dtlsAlert == nil {
			t.Fatal("expected non-nil")
		}
		if !reflect.DeepEqual(&alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert) {
			t.Errorf("expected %v, got %v", &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
		}
	})
}
