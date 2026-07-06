// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"errors"
	"reflect"
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

func TestFlight12ClientHelloFiltersX25519MLKEM768(t *testing.T) {
	cfg := &dtlsconfig.HandshakeConfig{
		EllipticCurves: []elliptic.Curve{
			elliptic.X25519MLKEM768,
			elliptic.P256,
		},
		LocalCipherSuites: []dtlsconfig.CipherSuite{
			ciphersuite.ForID(ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, nil),
		},
	}
	state := &dtlsstate.State{}

	pkts, _, err := generateForTest(t, Flight1, nil, state, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if elliptic.P256 != state.NamedCurve {
		t.Fatalf("expected %v, got %v", elliptic.P256, state.NamedCurve)
	}

	content, ok := pkts[0].Record.Content.(*handshake.Handshake)
	if !ok {
		t.Fatal("expected true")
	}
	clientHello, ok := content.Message.(*handshake.MessageClientHello)
	if !ok {
		t.Fatal("expected true")
	}

	var supportedGroups *extension.SupportedEllipticCurves
	for _, ext := range clientHello.Extensions {
		if groups, ok := ext.(*extension.SupportedEllipticCurves); ok {
			supportedGroups = groups
		}
	}
	if supportedGroups == nil {
		t.Fatal("expected non-nil")
	}
	if !reflect.DeepEqual([]elliptic.Curve{elliptic.P256}, supportedGroups.EllipticCurves) {
		t.Fatalf("expected %v, got %v", []elliptic.Curve{elliptic.P256}, supportedGroups.EllipticCurves)
	}
}

func TestFlight12ServerSelectsClassicalCurveFromClientGroups(t *testing.T) {
	cfg := &dtlsconfig.HandshakeConfig{
		EllipticCurves: []elliptic.Curve{
			elliptic.X25519MLKEM768,
			elliptic.P256,
		},
	}

	selected, ok := selectDTLS12EllipticCurve(cfg.EllipticCurves, []elliptic.Curve{
		elliptic.X25519MLKEM768,
		elliptic.P256,
	})
	if !ok {
		t.Fatal("expected true")
	}
	if elliptic.P256 != selected {
		t.Fatalf("expected %v, got %v", elliptic.P256, selected)
	}

	_, ok = selectDTLS12EllipticCurve(cfg.EllipticCurves, []elliptic.Curve{
		elliptic.X25519MLKEM768,
	})
	if ok {
		t.Fatal("expected false")
	}
}

func TestFlight12RejectsX25519MLKEM768ServerKeyExchange(t *testing.T) {
	state := &dtlsstate.State{
		CipherSuite: ciphersuite.ForID(ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, nil),
	}

	dtlsAlert, err := handleServerKeyExchange(
		nil,
		state,
		&dtlsconfig.HandshakeConfig{},
		&handshake.MessageServerKeyExchange{NamedCurve: elliptic.X25519MLKEM768},
	)
	if !errors.Is(err, dtlserrors.ErrUnsupportedEllipticCurveVersion) {
		t.Fatalf("expected error %v, got %v", dtlserrors.ErrUnsupportedEllipticCurveVersion, err)
	}
	if !reflect.DeepEqual(&alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlsAlert) {
		t.Fatalf("expected %v, got %v", &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlsAlert)
	}
}
