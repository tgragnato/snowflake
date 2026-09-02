**Table of Contents**

- [Dependencies](#dependencies)
- [Building the standalone Snowflake proxy](#building-the-standalone-snowflake-proxy)
- [Running a standalone Snowflake proxy](#running-a-standalone-snowflake-proxy)

This is a standalone (not browser-based) version of the Snowflake proxy. For browser-based versions of the Snowflake proxy, see https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake-webext.

### Dependencies

- Go 1.26+
- We use the [pion/webrtc](https://github.com/pion/webrtc) library for WebRTC communication with Snowflake proxies. Note: running `go get` will fetch this dependency automatically during the build process.

### Building the standalone Snowflake proxy

To build the Snowflake proxy, make sure you are in the `proxy/` directory, and then run:

```
go get
go build
```

### Running a standalone Snowflake proxy

The Snowflake proxy can be run with the following options:

<!-- These are generated with `go run . --help` -->

```
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
        the time interval between NAT type is retests (see "nat-probe-server"). 0s disables retest. Valid time units are "s", "m", "h". (default 24h0m0s)
  -nat-type-force-unrestricted
        force the NAT type as unrestricted
  -outbound-address address
        Prefer the given address as the outbound address for peer connections with clients.
        For bridges and relays running snowflake-proxy on the same device, an alternate IP address should be set for snowflake-proxy to mitigate its IP being censored when the bridge or relay IP is censored.
  -poll-interval duration
        a deprecated fallback value for often to ask the broker for a new client. Proxies will dynamically change their poll interval based on broker recommendation. Minumum value is 2s. Valid time units are "ms", "s", "m", "h". (default 5s)
  -relay URL
        The default URL of the server (relay) that this proxy will forward client connections to, in case the broker itself did not specify the said URL (default "wss://snowflake.torproject.net/")
  -stun URL
        Comma-separated STUN server URLs that this proxy will use will use to, among some other things, determine its public IP address (default "stun:stun.tgragnato.it:3478,stun:stun.l.google.com:19302")
  -summary-interval duration
        the time interval between summary log outputs, 0s disables summaries. Valid time units are "s", "m", "h". (default 1h0m0s)
  -unsafe-logging
        keep IP addresses and other sensitive info in the logs
  -verbose
        increase log verbosity
  -version
        display version info to stderr and quit
```

For more information on how to run a Snowflake proxy in deployment, see our [community documentation](https://community.torproject.org/relay/setup/snowflake/standalone/).

## Systemd

The Snowflake proxy can be run as a systemd service. Here is an example unit file:

```
[Unit]
Description=Snowflake Proxy Daemon
Wants=network-online.target
After=network.target network-online.target

[Service]
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
ProtectClock=yes
ProtectKernelLogs=yes
RestrictAddressFamilies=AF_INET AF_INET6
ProtectProc=invisible
SystemCallArchitectures=native
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
UMask=777
ProtectHostname=yes
RestrictNamespaces=yes
ProcSubset=pid
CapabilityBoundingSet=
PrivateTmp=yes
RestrictSUIDSGID=true
NoNewPrivileges=true
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallFilter=~@resources @privileged
IPAddressDeny=link-local multicast
DevicePolicy=closed
User=proxy
Group=proxy
LimitNOFILE=32768
ExecStart=/usr/bin/snowflake -unsafe-logging
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

To enable and start the service:

```bash
sudo systemctl enable snowflake-proxy
sudo systemctl start snowflake-proxy
```

## OpenBSD

On OpenBSD, the Snowflake proxy can be managed using the `rc.d` system. Here is an example rc script:

```
#!/bin/ksh

daemon="/usr/local/bin/snowflake"
daemon_logger="daemon.info"
daemon_user="nobody"

. /etc/rc.d/rc.subr

rc_bg=YES
rc_reload=NO

rc_cmd $1
```

To use this script, save it as `/etc/rc.d/snowflake-proxy` and make it executable:

```bash
chmod +x /etc/rc.d/snowflake-proxy
```

To start the proxy:

```bash
sudo /etc/rc.d/snowflake-proxy start
```

To stop the proxy:

```bash
sudo /etc/rc.d/snowflake-proxy stop
```
