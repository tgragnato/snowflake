FROM docker.io/library/golang:1.23 AS build

# Set some labels
# io.containers.autoupdate label will instruct podman to reach out to the corres
# corresponding registry to check if the image has been updated. If an image
# must be updated, Podman pulls it down and restarts the systemd unit executing
# the container. See podman-auto-update(1) for more details, or
# https://docs.podman.io/en/latest/markdown/podman-auto-update.1.html
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
