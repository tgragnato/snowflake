package util

import (
	"net"
	"net/http"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestUtil(t *testing.T) {
	Convey("Strip", t, func() {
		const offerStart = "v=0\r\no=- 4358805017720277108 2 IN IP4 8.8.8.8\r\ns=-\r\nt=0 0\r\na=group:BUNDLE data\r\na=msid-semantic: WMS\r\nm=application 56688 DTLS/SCTP 5000\r\nc=IN IP4 8.8.8.8\r\n"
		const goodCandidate = "a=candidate:3769337065 1 udp 2122260223 8.8.8.8 56688 typ host generation 0 network-id 1 network-cost 50\r\n"
		const offerEnd = "a=ice-ufrag:aMAZ\r\na=ice-pwd:jcHb08Jjgrazp2dzjdrvPPvV\r\na=ice-options:trickle\r\na=fingerprint:sha-256 C8:88:EE:B9:E7:02:2E:21:37:ED:7A:D1:EB:2B:A3:15:A2:3B:5B:1C:3D:D4:D5:1F:06:CF:52:40:03:F8:DD:66\r\na=setup:actpass\r\na=mid:data\r\na=sctpmap:5000 webrtc-datachannel 1024\r\n"

		offer := offerStart + goodCandidate +
			"a=candidate:3769337065 1 udp 2122260223 192.168.0.100 56688 typ host generation 0 network-id 1 network-cost 50\r\n" + // IsLocal IPv4
			"a=candidate:3769337065 1 udp 2122260223 100.127.50.5 56688 typ host generation 0 network-id 1 network-cost 50\r\n" + // IsLocal IPv4
			"a=candidate:3769337065 1 udp 2122260223 169.254.250.88 56688 typ host generation 0 network-id 1 network-cost 50\r\n" + // IsLocal IPv4
			"a=candidate:3769337065 1 udp 2122260223 fdf8:f53b:82e4::53 56688 typ host generation 0 network-id 1 network-cost 50\r\n" + // IsLocal IPv6
			"a=candidate:3769337065 1 udp 2122260223 0.0.0.0 56688 typ host generation 0 network-id 1 network-cost 50\r\n" + // IsUnspecified IPv4
			"a=candidate:3769337065 1 udp 2122260223 :: 56688 typ host generation 0 network-id 1 network-cost 50\r\n" + // IsUnspecified IPv6
			"a=candidate:3769337065 1 udp 2122260223 127.0.0.1 56688 typ host generation 0 network-id 1 network-cost 50\r\n" + // IsLoopback IPv4
			"a=candidate:3769337065 1 udp 2122260223 ::1 56688 typ host generation 0 network-id 1 network-cost 50\r\n" + // IsLoopback IPv6
			offerEnd

		So(StripLocalAddresses(offer), ShouldEqual, offerStart+goodCandidate+offerEnd)
	})

	Convey("GetClientIp", t, func() {
		// Should use Forwarded header
		req1, _ := http.NewRequest("GET", "https://example.com", nil)
		req1.Header.Add("X-Forwarded-For", "1.1.1.1, 2001:db8:cafe::99%eth0, 3.3.3.3, 192.168.1.1")
		req1.Header.Add("Forwarded", `For=fe80::abcd;By=fe80::1234, Proto=https;For=::ffff:188.0.2.128, For="[2001:db8:cafe::17]:4848", For=fc00::1`)
		req1.RemoteAddr = "192.168.1.2:8888"
		So(GetClientIp(req1), ShouldEqual, "188.0.2.128")

		// Should use X-Forwarded-For header
		req2, _ := http.NewRequest("GET", "https://example.com", nil)
		req2.Header.Add("X-Forwarded-For", "1.1.1.1, 2001:db8:cafe::99%eth0, 3.3.3.3, 192.168.1.1")
		req2.RemoteAddr = "192.168.1.2:8888"
		So(GetClientIp(req2), ShouldEqual, "1.1.1.1")

		// Should use RemoteAddr
		req3, _ := http.NewRequest("GET", "https://example.com", nil)
		req3.RemoteAddr = "192.168.1.2:8888"
		So(GetClientIp(req3), ShouldEqual, "192.168.1.2")

		// Should return empty client IP
		req4, _ := http.NewRequest("GET", "https://example.com", nil)
		So(GetClientIp(req4), ShouldEqual, "")
	})

	Convey("GetCandidateAddrs", t, func() {
		// Should prioritize type in the following order: https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.2.2
		// Break ties using priority value
		const offerStart = "v=0\r\no=- 4358805017720277108 2 IN IP4 8.8.8.8\r\ns=-\r\nt=0 0\r\na=group:BUNDLE data\r\na=msid-semantic: WMS\r\nm=application 56688 DTLS/SCTP 5000\r\nc=IN IP4 8.8.8.8\r\n"
		const offerEnd = "a=ice-ufrag:aMAZ\r\na=ice-pwd:jcHb08Jjgrazp2dzjdrvPPvV\r\na=ice-options:trickle\r\na=fingerprint:sha-256 C8:88:EE:B9:E7:02:2E:21:37:ED:7A:D1:EB:2B:A3:15:A2:3B:5B:1C:3D:D4:D5:1F:06:CF:52:40:03:F8:DD:66\r\na=setup:actpass\r\na=mid:data\r\na=sctpmap:5000 webrtc-datachannel 1024\r\n"

		const sdp = offerStart + "a=candidate:3769337065 1 udp 2122260223 8.8.8.8 56688 typ prflx\r\n" +
			"a=candidate:3769337065 1 udp 2122260223 129.97.124.13 56688 typ relay\r\n" +
			"a=candidate:3769337065 1 udp 2122260223 129.97.124.14 56688 typ srflx\r\n" +
			"a=candidate:3769337065 1 udp 2122260223 129.97.124.15 56688 typ host\r\n" +
			"a=candidate:3769337065 1 udp 2122260224 129.97.124.16 56688 typ host\r\n" + offerEnd

		So(GetCandidateAddrs(sdp), ShouldEqual, []net.IP{
			net.ParseIP("129.97.124.16"),
			net.ParseIP("129.97.124.15"),
			net.ParseIP("8.8.8.8"),
			net.ParseIP("129.97.124.14"),
			net.ParseIP("129.97.124.13"),
		})
	})
}
