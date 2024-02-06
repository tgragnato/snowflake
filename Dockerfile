FROM docker.io/library/golang:1.21 AS build

LABEL io.containers.autoupdate=registry
LABEL org.opencontainers.image.authors="anti-censorship-team@lists.torproject.org"

ADD . /app

WORKDIR /app/proxy
RUN go get
RUN CGO_ENABLED=0 go build -o proxy -ldflags '-extldflags "-static" -w -s'  .

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /app/proxy/proxy /bin/proxy

ENTRYPOINT [ "/bin/proxy" ]
