module github.com/tgragnato/snowflake.git/v2

go 1.21

require (
	github.com/gorilla/websocket v1.5.1
	github.com/miekg/dns v1.1.57
	github.com/pion/ice/v2 v2.3.12
	github.com/pion/sdp/v3 v3.0.6
	github.com/pion/stun/v2 v2.0.0
	github.com/pion/transport/v2 v2.2.4
	github.com/pion/webrtc/v3 v3.2.24
	github.com/prometheus/client_golang v1.18.0
	github.com/prometheus/client_model v0.5.0
	github.com/refraction-networking/utls v1.6.1
	github.com/smartystreets/goconvey v1.8.1
	github.com/stretchr/testify v1.8.4
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
	github.com/xtaci/kcp-go/v5 v5.6.7
	github.com/xtaci/smux v1.5.24
	gitlab.torproject.org/tpo/anti-censorship/geoip v0.0.0-20210928150955-7ce4b3d98d01
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0
	golang.org/x/crypto v0.18.0
	golang.org/x/net v0.20.0
	golang.org/x/sys v0.16.0
	google.golang.org/protobuf v1.32.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/uuid v1.5.0 // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/klauspost/reedsolomon v1.12.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pion/datachannel v1.5.5 // indirect
	github.com/pion/dtls/v2 v2.2.9 // indirect
	github.com/pion/interceptor v0.1.25 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/mdns v0.0.9 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.13 // indirect
	github.com/pion/rtp v1.8.3 // indirect
	github.com/pion/sctp v1.8.9 // indirect
	github.com/pion/srtp/v2 v2.0.18 // indirect
	github.com/pion/stun v0.6.1 // indirect
	github.com/pion/transport/v3 v3.0.1 // indirect
	github.com/pion/turn/v2 v2.1.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/quic-go/quic-go v0.40.1 // indirect
	github.com/smarty/assertions v1.15.1 // indirect
	github.com/templexxx/cpu v0.1.0 // indirect
	github.com/templexxx/xorsimd v0.4.2 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/txthinking/runnergroup v0.0.0-20230325130830-408dc5853f86 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.16.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/pion/dtls/v2 => ./dtls
