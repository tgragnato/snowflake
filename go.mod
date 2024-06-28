module github.com/tgragnato/snowflake

go 1.21

require (
	github.com/aws/aws-sdk-go-v2 v1.30.0
	github.com/aws/aws-sdk-go-v2/config v1.27.21
	github.com/aws/aws-sdk-go-v2/credentials v1.17.22
	github.com/aws/aws-sdk-go-v2/service/sqs v1.34.0
	github.com/golang/mock v1.6.0
	github.com/miekg/dns v1.1.61
	github.com/pion/ice/v3 v3.0.7
	github.com/pion/sdp/v3 v3.0.9
	github.com/pion/stun/v2 v2.0.0
	github.com/pion/transport/v3 v3.0.2
	github.com/pion/webrtc/v4 v4.0.0-beta.21
	github.com/prometheus/client_golang v1.19.1
	github.com/realclientip/realclientip-go v1.0.0
	github.com/refraction-networking/utls v1.6.6
	github.com/smartystreets/goconvey v1.8.1
	github.com/stretchr/testify v1.9.0
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
	github.com/xtaci/kcp-go/v5 v5.6.8
	github.com/xtaci/smux v1.5.24
	gitlab.torproject.org/tpo/anti-censorship/geoip v0.0.0-20210928150955-7ce4b3d98d01
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0
	golang.org/x/crypto v0.24.0
	golang.org/x/net v0.26.0
	golang.org/x/sys v0.21.0
	nhooyr.io/websocket v1.8.11
)

require (
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.0 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.3.9 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/klauspost/reedsolomon v1.12.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pion/datachannel v1.5.6 // indirect
	github.com/pion/dtls/v2 v2.2.11 // indirect
	github.com/pion/interceptor v0.1.29 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/mdns/v2 v2.0.7 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.14 // indirect
	github.com/pion/rtp v1.8.6 // indirect
	github.com/pion/sctp v1.8.16 // indirect
	github.com/pion/srtp/v3 v3.0.1 // indirect
	github.com/pion/turn/v3 v3.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/smarty/assertions v1.16.0 // indirect
	github.com/templexxx/cpu v0.1.0 // indirect
	github.com/templexxx/xorsimd v0.4.2 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/txthinking/runnergroup v0.0.0-20230325130830-408dc5853f86 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/ptutil v0.0.0-20240509090240-b27cf78add95
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/pion/dtls/v2 => ./dtls
