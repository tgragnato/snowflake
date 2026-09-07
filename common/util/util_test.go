package util

import (
	"net"
	"net/http"
	"slices"
	"testing"

	"github.com/pion/webrtc/v4"
)

func TestGetClientIp(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		want       string
	}{
		{
			name: "uses Forwarded header",
			headers: map[string]string{
				"X-Forwarded-For": "1.1.1.1, 2001:db8:cafe::99%eth0, 3.3.3.3, 192.168.1.1",
				"Forwarded":       `For=fe80::abcd;By=fe80::1234, Proto=https;For=::ffff:188.0.2.128, For="[2001:db8:cafe::17]:4848", For=fc00::1`,
			},
			remoteAddr: "192.168.1.2:8888",
			want:       "188.0.2.128",
		},
		{
			name: "uses X-Forwarded-For header",
			headers: map[string]string{
				"X-Forwarded-For": "1.1.1.1, 2001:db8:cafe::99%eth0, 3.3.3.3, 192.168.1.1",
			},
			remoteAddr: "192.168.1.2:8888",
			want:       "1.1.1.1",
		},
		{
			name:       "uses RemoteAddr",
			remoteAddr: "192.168.1.2:8888",
			want:       "192.168.1.2",
		},
		{
			name: "returns empty client IP",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "https://example.com", nil)
			if err != nil {
				t.Fatalf("http.NewRequest: %v", err)
			}
			for k, v := range tc.headers {
				req.Header.Add(k, v)
			}
			req.RemoteAddr = tc.remoteAddr
			if got := GetClientIp(req); got != tc.want {
				t.Errorf("GetClientIp() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGetCandidateAddrs(t *testing.T) {
	t.Parallel()

	// Should prioritize type in the following order: https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.2.2
	// Break ties using priority value
	const offerStart = "v=0\r\no=- 4358805017720277108 2 IN IP4 8.8.8.8\r\ns=-\r\nt=0 0\r\na=group:BUNDLE data\r\na=msid-semantic: WMS\r\nm=application 56688 DTLS/SCTP 5000\r\nc=IN IP4 8.8.8.8\r\n"
	const offerEnd = "a=ice-ufrag:aMAZ\r\na=ice-pwd:jcHb08Jjgrazp2dzjdrvPPvV\r\na=ice-options:trickle\r\na=fingerprint:sha-256 C8:88:EE:B9:E7:02:2E:21:37:ED:7A:D1:EB:2B:A3:15:A2:3B:5B:1C:3D:D4:D5:1F:06:CF:52:40:03:F8:DD:66\r\na=setup:actpass\r\na=mid:data\r\na=sctpmap:5000 webrtc-datachannel 1024\r\n"

	const sdp = offerStart + "a=candidate:3769337065 1 udp 2122260223 8.8.8.8 56688 typ prflx\r\n" +
		"a=candidate:3769337065 1 udp 2122260223 129.97.124.13 56688 typ relay\r\n" +
		"a=candidate:3769337065 1 udp 2122260223 129.97.124.14 56688 typ srflx\r\n" +
		"a=candidate:3769337065 1 udp 2122260223 129.97.124.15 56688 typ host\r\n" +
		"a=candidate:3769337065 1 udp 2122260224 129.97.124.16 56688 typ host\r\n" + offerEnd

	want := []net.IP{
		net.ParseIP("129.97.124.16"),
		net.ParseIP("129.97.124.15"),
		net.ParseIP("8.8.8.8"),
		net.ParseIP("129.97.124.14"),
		net.ParseIP("129.97.124.13"),
	}
	got := GetCandidateAddrs(sdp)
	if !slices.EqualFunc(got, want, func(a, b net.IP) bool { return a.Equal(b) }) {
		t.Errorf("GetCandidateAddrs() = %v, want %v", got, want)
	}
}

func TestSerializeSessionDescription(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		desc    *webrtc.SessionDescription
		wantErr bool
	}{
		{
			name: "offer",
			desc: &webrtc.SessionDescription{
				Type: webrtc.SDPTypeOffer,
				SDP:  "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n",
			},
			wantErr: false,
		},
		{
			name: "answer",
			desc: &webrtc.SessionDescription{
				Type: webrtc.SDPTypeAnswer,
				SDP:  "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n",
			},
			wantErr: false,
		},
		{
			name: "pranswer",
			desc: &webrtc.SessionDescription{
				Type: webrtc.SDPTypePranswer,
				SDP:  "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n",
			},
			wantErr: false,
		},
		{
			name: "rollback",
			desc: &webrtc.SessionDescription{
				Type: webrtc.SDPTypeRollback,
				SDP:  "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n",
			},
			wantErr: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SerializeSessionDescription(tc.desc)
			if tc.wantErr {
				if err == nil {
					t.Error("SerializeSessionDescription succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("SerializeSessionDescription: %v", err)
			}
			// Verify round-trip
			gotDesc, err := DeserializeSessionDescription(got)
			if err != nil {
				t.Fatalf("DeserializeSessionDescription: %v", err)
			}
			if gotDesc.Type != tc.desc.Type {
				t.Errorf("Type = %q, want %q", gotDesc.Type, tc.desc.Type)
			}
			if gotDesc.SDP != tc.desc.SDP {
				t.Errorf("SDP = %q, want %q", gotDesc.SDP, tc.desc.SDP)
			}
		})
	}
}

func TestDeserializeSessionDescription(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "bad JSON",
			input:   `{invalid}`,
			wantErr: true,
		},
		{
			name:    "missing type field",
			input:   `{"sdp":"test"}`,
			wantErr: true,
		},
		{
			name:    "missing sdp field",
			input:   `{"type":"offer"}`,
			wantErr: true,
		},
		{
			name:    "invalid type value",
			input:   `{"type":123,"sdp":"test"}`,
			wantErr: true,
		},
		{
			name:    "invalid sdp value",
			input:   `{"type":"offer","sdp":123}`,
			wantErr: true,
		},
		{
			name:    "unknown SDP type",
			input:   `{"type":"unknown","sdp":"test"}`,
			wantErr: true,
		},
		{
			name:    "valid offer",
			input:   `{"type":"offer","sdp":"v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"}`,
			wantErr: false,
		},
		{
			name:    "valid answer",
			input:   `{"type":"answer","sdp":"v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"}`,
			wantErr: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeserializeSessionDescription(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("DeserializeSessionDescription succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("DeserializeSessionDescription: %v", err)
			}
			if got.SDP == "" {
				t.Errorf("DeserializeSessionDescription returned empty SDP")
			}
		})
	}
}

func TestGetSnowflakeIp(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		hops       int
		want       string
	}{
		{
			name: "hops zero uses RemoteAddr",
			headers: map[string]string{
				"X-Forwarded-For": "1.2.3.4, 5.6.7.8",
			},
			remoteAddr: "9.10.11.12:8888",
			hops:       0,
			want:       "9.10.11.12",
		},
		{
			name: "hops one uses rightmost trusted",
			headers: map[string]string{
				"X-Forwarded-For": "1.2.3.4, 5.6.7.8",
			},
			remoteAddr: "9.10.11.12:8888",
			hops:       1,
			want:       "5.6.7.8",
		},
		{
			name: "hops two uses second from right",
			headers: map[string]string{
				"X-Forwarded-For": "1.2.3.4, 5.6.7.8, 9.10.11.12",
			},
			remoteAddr: "13.14.15.16:8888",
			hops:       2,
			want:       "5.6.7.8",
		},
		{
			name: "uses Forwarded header",
			headers: map[string]string{
				"Forwarded": "for=1.2.3.4, for=5.6.7.8",
			},
			remoteAddr: "9.10.11.12:8888",
			hops:       1,
			want:       "5.6.7.8",
		},
		{
			name:       "no headers uses RemoteAddr",
			remoteAddr: "1.2.3.4:8888",
			hops:       0,
			want:       "1.2.3.4",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "https://example.com", nil)
			if err != nil {
				t.Fatalf("http.NewRequest: %v", err)
			}
			for k, v := range tc.headers {
				req.Header.Add(k, v)
			}
			req.RemoteAddr = tc.remoteAddr
			if got := GetSnowflakeIp(req, tc.hops); got != tc.want {
				t.Errorf("GetSnowflakeIp() = %q, want %q", got, tc.want)
			}
		})
	}
}
