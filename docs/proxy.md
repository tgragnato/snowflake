**Table of Contents**

- [Dependencies](#dependencies)
- [Building the standalone Snowflake proxy](#building-the-standalone-snowflake-proxy)
- [Running a standalone Snowflake proxy](#running-a-standalone-snowflake-proxy)
- [Running as a systemd service](#running-as-a-systemd-service)
- [Running on OpenBSD](#running-on-openbsd)

This is the standalone (not browser-based) version of the Snowflake proxy. For the
browser-based proxy, see
[snowflake-webext](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake-webext).

### Dependencies

- Go 1.26 or later. See [development.md](development.md) for the toolchain and lint
  requirements that apply to the whole repository.
- [pion/webrtc](https://github.com/pion/webrtc), used for the WebRTC connection to
  Snowflake clients. It is declared in `go.mod` and downloaded automatically by
  `go build`; no separate step is required.

### Building the standalone Snowflake proxy

From the `proxy/` directory:

```bash
go build
```

### Running a standalone Snowflake proxy

The proxy accepts the following options.

<!-- Regenerate this block with `go run . --help` from the proxy/ directory. -->

```text
Usage of ./proxy:
  -allow-non-tls-relay
        allow this proxy to pass client's data to the relay in an unencrypted form.
        This is only useful if the relay doesn't support encryption, e.g. for testing / development purposes.
  -allow-proxying-to-private-addresses
        allow forwarding client connections to private IP addresses.
        Useful when a Snowflake server (relay) is hosted on the same private network as this proxy.
  -allowed-relay-hostname-pattern string
        this proxy will only be allowed to forward client connections to relays (servers) whose URL matches this pattern.
        Note that a pattern "example.com$" will match "subdomain.example.com" as well as "other-domain-example.com".
        In order to only match "example.com", prefix the pattern with "^": "^example.com$" (default "snowflake.torproject.net$")
  -broker URL
        The URL of the broker server that the proxy will be using to find clients (default "https://snowflake-broker.torproject.net/")
  -capacity uint
        maximum concurrent clients (default is to accept an unlimited number of clients)
  -disable-stats-logger
        disable the exposing mechanism for stats using logs
  -ephemeral-ports-range range
        Set the range of ports used for client connections (format:"<min>:<max>").
        Useful in conjunction with port forwarding, in order to make the proxy NAT type "unrestricted".
        If omitted, the ports will be chosen automatically from a wide range.
        When specifying the range, make sure it's at least 2x as wide as the amount of clients that you are hoping to serve concurrently (see the "capacity" flag).
  -geoip6db string
        path to correctly formatted geoip database mapping IPv6 address ranges to country codes (default "/usr/share/tor/geoip6")
  -geoipdb string
        path to correctly formatted geoip database mapping IPv4 address ranges to country codes (default "/usr/share/tor/geoip")
  -keep-local-addresses
        keep local LAN address ICE candidates.
        This is usually pointless because Snowflake clients don't usually reside on the same local network as the proxy.
  -log filename
        log filename. If not specified, logs will be output to stderr (console).
  -log-local-time
        Use local time for logging (default: UTC)
  -metrics
        enable the exposing mechanism for stats using metrics
  -metrics-address address
        set listen address for metrics service (default "localhost")
  -metrics-port int
        set port for the metrics service (default 9999)
  -nat-probe-server URL
        The URL of the server that this proxy will use to check its network NAT type.
        Determining NAT type helps to understand whether this proxy is compatible with certain clients' NAT (default "https://snowflake-broker.torproject.net:8443/probe")
  -nat-retest-interval duration
        the time interval between NAT type retests (see "nat-probe-server"). 0s disables retesting. Valid time units are "s", "m", "h". (default 24h0m0s)
  -nat-type-force-unrestricted
        force the NAT type as unrestricted
  -outbound-address address
        Prefer the given address as the outbound address for peer connections with clients.
        For bridges and relays running snowflake-proxy on the same device, an alternate IP address should be set for snowflake-proxy to mitigate its IP being censored when the bridge or relay IP is censored.
  -poll-interval duration
        a deprecated fallback value for how often to ask the broker for a new client. Proxies will dynamically change their poll interval based on broker recommendation. Minimum value is 2s. Valid time units are "ms", "s", "m", "h". (default 5s)
  -relay URL
        The default URL of the server (relay) that this proxy will forward client connections to, in case the broker itself did not specify the said URL (default "wss://snowflake.torproject.net/")
  -stun URL
        Comma-separated STUN server URLs that this proxy will use to determine its public IP address, among other things (default "stun:stun.tgragnato.it:3478,stun:stun.l.google.com:19302")
  -summary-interval duration
        the time interval between summary log outputs, 0s disables summaries. Valid time units are "s", "m", "h". (default 1h0m0s)
  -unsafe-logging
        keep IP addresses and other sensitive info in the logs
  -verbose
        increase log verbosity
  -version
        display version info to stderr and quit
```

`-unsafe-logging` disables the scrubbing of client IP addresses and other identifying
data. Use it only for local debugging, never in a deployment that serves real users.

For more on running a proxy in deployment, see the
[community documentation](https://community.torproject.org/relay/setup/snowflake/standalone/).

### Running as a systemd service

Save the following unit as `/etc/systemd/system/snowflake-proxy.service`, adjusting
`ExecStart` to the path of your binary:

```ini
[Unit]
Description=Snowflake Proxy Daemon
Wants=network-online.target
After=network.target network-online.target

[Service]
ExecStart=/usr/bin/snowflake
Restart=on-failure
User=proxy
Group=proxy
LimitNOFILE=32768

# Hardening
AmbientCapabilities=
CapabilityBoundingSet=
DevicePolicy=closed
IPAddressDeny=link-local multicast
LockPersonality=yes
MemoryDenyWriteExecute=yes
NoNewPrivileges=true
PrivateDevices=yes
PrivateTmp=yes
ProcSubset=pid
ProtectClock=yes
ProtectControlGroups=yes
ProtectHome=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectProc=invisible
ProtectSystem=strict
RemoveIPC=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@resources @privileged
UMask=077

[Install]
WantedBy=multi-user.target
```

Then reload systemd, enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now snowflake-proxy
sudo systemctl status snowflake-proxy
```

`ProtectSystem=strict` makes the whole filesystem read-only for the service, so if you
pass `-log`, grant write access to that path with `ReadWritePaths=`.

### Running on OpenBSD

On OpenBSD the proxy can be supervised by `rc.d`. Save the following script as
`/etc/rc.d/snowflake_proxy`:

```sh
#!/bin/ksh

daemon="/usr/local/bin/snowflake"
daemon_flags=""
daemon_logger="daemon.info"
daemon_user="nobody"

. /etc/rc.d/rc.subr

rc_bg=YES
rc_reload=NO

rc_cmd $1
```

Make it executable, then enable and start it:

```sh
chmod +x /etc/rc.d/snowflake_proxy
doas rcctl enable snowflake_proxy
doas rcctl start snowflake_proxy
```

To stop it:

```sh
doas rcctl stop snowflake_proxy
```

The script is named `snowflake_proxy` because `rc.d` script names cannot contain a
hyphen.
