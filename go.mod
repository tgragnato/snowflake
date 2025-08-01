module tgragnato.it/snowflake

go 1.24.2

require (
	github.com/aws/aws-sdk-go-v2 v1.37.1
	github.com/aws/aws-sdk-go-v2/config v1.30.2
	github.com/aws/aws-sdk-go-v2/credentials v1.18.2
	github.com/aws/aws-sdk-go-v2/service/sqs v1.39.1
	github.com/coder/websocket v1.8.13
	github.com/golang/mock v1.6.0
	github.com/miekg/dns v1.1.67
	github.com/pion/ice/v4 v4.0.10
	github.com/pion/sdp/v3 v3.0.15
	github.com/pion/stun/v3 v3.0.0
	github.com/pion/transport/v3 v3.0.7
	github.com/pion/webrtc/v4 v4.1.3
	github.com/prometheus/client_golang v1.23.0
	github.com/realclientip/realclientip-go v1.0.0
	github.com/refraction-networking/utls v1.8.0
	github.com/smartystreets/goconvey v1.8.1
	github.com/stretchr/testify v1.10.0
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
	github.com/xtaci/kcp-go/v5 v5.6.9
	github.com/xtaci/smux v1.5.33
	gitlab.torproject.org/tpo/anti-censorship/geoip v0.0.0-20210928150955-7ce4b3d98d01
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.6.0
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/ptutil v0.0.0-20250130151315-efaf4e0ec0d3
	golang.org/x/crypto v0.40.0
	golang.org/x/net v0.42.0
	golang.org/x/sys v0.34.0
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.26.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.31.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.35.1 // indirect
	github.com/aws/smithy-go v1.22.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.12.5 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pion/datachannel v1.5.10 // indirect
	github.com/pion/dtls/v3 v3.0.6 // indirect
	github.com/pion/interceptor v0.1.40 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.0.7 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.15 // indirect
	github.com/pion/rtp v1.8.21 // indirect
	github.com/pion/sctp v1.8.39 // indirect
	github.com/pion/srtp/v3 v3.0.6 // indirect
	github.com/pion/turn/v4 v4.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/smarty/assertions v1.16.0 // indirect
	github.com/templexxx/cpu v0.1.1 // indirect
	github.com/templexxx/xorsimd v0.4.3 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/txthinking/runnergroup v0.0.0-20241229123329-7b873ad00768 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2 v2.10.1 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	golang.org/x/tools v0.35.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/pion/dtls/v3 v3.0.6 => ./dtls
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2 v2.10.1 => .
)
