FROM cgr.dev/chainguard/go:latest AS builder
ENV CGO_ENABLED=0
WORKDIR /workspace
COPY go.mod .
COPY go.sum .
COPY . .
RUN go mod download && go build -o proxy/proxy ./proxy

FROM ghcr.io/anchore/syft:latest AS sbomgen
COPY --from=builder /workspace/proxy/proxy /usr/bin/proxy
RUN ["/syft", "--output", "spdx-json=/tmp/proxy.spdx.json", "/usr/bin/proxy"]

FROM cgr.dev/chainguard/static:latest
WORKDIR /tmp
COPY --from=builder /workspace/proxy/proxy /usr/bin/
COPY --from=sbomgen /tmp/proxy.spdx.json /var/lib/db/sbom/proxy.spdx.json
ENTRYPOINT ["/usr/bin/proxy"]
LABEL org.opencontainers.image.title="snowflake"
LABEL org.opencontainers.image.description="WebRTC Pluggable Transport"
LABEL org.opencontainers.image.url="https://tgragnato.it/snowflake/"
LABEL org.opencontainers.image.source="https://tgragnato.it/snowflake/"
LABEL license="BSD-3-Clause"
LABEL io.containers.autoupdate=registry
