FROM golang:alpine3.20 AS builder
ENV CGO_ENABLED=0
WORKDIR /workspace
COPY go.mod .
COPY go.sum .
COPY . .
RUN go mod download && go build -o proxy/proxy ./proxy

FROM alpine:3.20
WORKDIR /tmp
COPY --from=builder /workspace/proxy/proxy /usr/bin/
ENTRYPOINT ["/usr/bin/proxy"]
LABEL io.containers.autoupdate=registry
LABEL org.opencontainers.image.source=https://github.com/tgragnato/snowflake
