FROM golang:alpine3.21 AS builder
ENV CGO_ENABLED=0
WORKDIR /workspace
COPY go.mod .
COPY go.sum .
COPY . .
RUN go mod download && go build -o proxy/proxy ./proxy

FROM alpine:3.21
WORKDIR /tmp
COPY --from=builder /workspace/proxy/proxy /usr/bin/
ENTRYPOINT ["/usr/bin/proxy"]
LABEL org.opencontainers.image.title="snowflake"
LABEL org.opencontainers.image.description="WebRTC Pluggable Transport"
LABEL org.opencontainers.image.url="https://tgragnato.it/snowflake/"
LABEL org.opencontainers.image.source="https://tgragnato.it/snowflake/"
LABEL license="BSD-3-Clause"
LABEL io.containers.autoupdate=registry
