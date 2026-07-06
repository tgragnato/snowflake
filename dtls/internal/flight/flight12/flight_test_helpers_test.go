// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"context"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

type helperTestingT interface {
	Helper()
	Fatal(args ...any)
}

func parseForTest(
	testingT helperTestingT,
	flight Flight,
	ctx context.Context,
	conn dtlsflight.Conn,
	state *dtlsstate.State,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (Flight, *alert.Alert, error) {
	testingT.Helper()

	nextFlight, dtlsAlert, err, ok := Parse(ctx, flight, conn, state, cache, cfg)
	if !ok {
		testingT.Fatal("expected true")
	}

	return nextFlight, dtlsAlert, err
}

func generateForTest(
	testingT helperTestingT,
	flight Flight,
	conn dtlsflight.Conn,
	state *dtlsstate.State,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	testingT.Helper()

	gen, _, ok := GetGenerator(flight)
	if !ok {
		testingT.Fatal("expected true")
	}

	return gen(conn, state, cache, cfg)
}
