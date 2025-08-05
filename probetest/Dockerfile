FROM docker.io/library/golang:latest AS build


ADD . /app

WORKDIR /app/probetest
RUN go get
RUN CGO_ENABLED=0 go build -o probetest -ldflags '-extldflags "-static" -w -s'  .

FROM containers.torproject.org/tpo/tpa/base-images/debian:bookworm as debian-base

RUN apt-get update && apt-get install -y \
    curl \
    gpg \
    gpg-agent \
    ca-certificates \
    libcap2-bin \
    --no-install-recommends
    
FROM scratch

COPY --from=debian-base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=debian-base /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /app/probetest/probetest /bin/probetest

ENTRYPOINT [ "/bin/probetest" ]

LABEL org.opencontainers.image.authors="anti-censorship-team@lists.torproject.org"
