package main

import (
	"bytes"
	"encoding/hex"
	"testing"

	"tgragnato.it/snowflake/common/bridgefingerprint"
)

const DefaultBridges = `{"displayName":"default", "webSocketAddress":"wss://snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80A72"}
`

const ImaginaryBridges = `{"displayName":"default", "webSocketAddress":"wss://snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80A72"}
{"displayName":"imaginary-1", "webSocketAddress":"wss://imaginary-1-snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80B00"}
{"displayName":"imaginary-2", "webSocketAddress":"wss://imaginary-2-snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80B01"}
{"displayName":"imaginary-3", "webSocketAddress":"wss://imaginary-3-snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80B02"}
{"displayName":"imaginary-4", "webSocketAddress":"wss://imaginary-4-snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80B03"}
{"displayName":"imaginary-5", "webSocketAddress":"wss://imaginary-5-snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80B04"}
{"displayName":"imaginary-6", "webSocketAddress":"wss://imaginary-6-snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80B05"}
{"displayName":"imaginary-7", "webSocketAddress":"wss://imaginary-7-snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80B06"}
{"displayName":"imaginary-8", "webSocketAddress":"wss://imaginary-8-snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80B07"}
{"displayName":"imaginary-9", "webSocketAddress":"wss://imaginary-9-snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80B08"}
{"displayName":"imaginary-10", "webSocketAddress":"wss://imaginary-10-snowflake.torproject.org", "fingerprint":"2B280B23E1107BB62ABFC40DDCC8824814F80B09"}
`

func TestBridgeLoad(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name             string
		list             string
		fingerprint      string
		wantDisplayName  string
		wantWebSocketURL string
	}{
		{
			name:             "default list",
			list:             DefaultBridges,
			fingerprint:      "2B280B23E1107BB62ABFC40DDCC8824814F80A72",
			wantDisplayName:  "default",
			wantWebSocketURL: "wss://snowflake.torproject.org",
		},
		{
			name:             "imaginary list",
			list:             ImaginaryBridges,
			fingerprint:      "2B280B23E1107BB62ABFC40DDCC8824814F80B07",
			wantDisplayName:  "imaginary-8",
			wantWebSocketURL: "wss://imaginary-8-snowflake.torproject.org",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bridgeList := NewBridgeListHolder()
			if err := bridgeList.LoadBridgeInfo(bytes.NewReader([]byte(tc.list))); err != nil {
				t.Fatalf("LoadBridgeInfo: %v", err)
			}

			bridgeFingerprint := [20]byte{}
			n, err := hex.Decode(bridgeFingerprint[:], []byte(tc.fingerprint))
			if err != nil {
				t.Fatalf("hex.Decode: %v", err)
			}
			if n != 20 {
				t.Fatalf("hex.Decode wrote %d bytes, want 20", n)
			}

			fingerprint, err := bridgefingerprint.FingerprintFromBytes(bridgeFingerprint[:])
			if err != nil {
				t.Fatalf("FingerprintFromBytes: %v", err)
			}
			bridgeInfo, err := bridgeList.GetBridgeInfo(fingerprint)
			if err != nil {
				t.Fatalf("GetBridgeInfo: %v", err)
			}
			if bridgeInfo.DisplayName != tc.wantDisplayName {
				t.Errorf("DisplayName = %q, want %q", bridgeInfo.DisplayName, tc.wantDisplayName)
			}
			if bridgeInfo.WebSocketAddress != tc.wantWebSocketURL {
				t.Errorf("WebSocketAddress = %q, want %q", bridgeInfo.WebSocketAddress, tc.wantWebSocketURL)
			}
		})
	}
}
