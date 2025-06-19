<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Dependencies](#dependencies)
- [Building the Snowflake client](#building-the-snowflake-client)
- [Running the Snowflake client with Tor](#running-the-snowflake-client-with-tor)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

This is the Tor client component of Snowflake.

It is based on the [goptlib](https://gitweb.torproject.org/pluggable-transports/goptlib.git/) pluggable transports library for Tor.


### Dependencies

- Go 1.15+
- We use the [pion/webrtc](https://github.com/pion/webrtc) library for WebRTC communication with Snowflake proxies. Note: running `go get` will fetch this dependency automatically during the build process.

### Building the Snowflake client

To build the Snowflake client, make sure you are in the `client/` directory, and then run:

```
go get
go build
```

### Running the Snowflake client with Tor

The Snowflake client can be configured with SOCKS options. We have a few example `torrc` files in this directory. We recommend the following `torrc` options by default:
```
UseBridges 1

ClientTransportPlugin snowflake exec ./client -log snowflake.log

# CDN77

Bridge snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn

# ampcache
#Bridge snowflake 192.0.2.5:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net/ ampcache=https://cdn.ampproject.org/ front=www.google.com ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
#Bridge snowflake 192.0.2.6:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://snowflake-broker.torproject.net/ ampcache=https://cdn.ampproject.org/ front=www.google.com ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn

# sqs
#Bridge snowflake 192.0.2.5:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 sqsqueue=https://sqs.us-east-1.amazonaws.com/893902434899/snowflake-broker sqscreds=eyJhd3MtYWNjZXNzLWtleS1pZCI6IkFLSUE1QUlGNFdKSlhTN1lIRUczIiwiYXdzLXNlY3JldC1rZXkiOiI3U0RNc0pBNHM1RitXZWJ1L3pMOHZrMFFXV0lsa1c2Y1dOZlVsQ0tRIn0= ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
#Bridge snowflake 192.0.2.6:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA sqsqueue=https://sqs.us-east-1.amazonaws.com/893902434899/snowflake-broker sqscreds=eyJhd3MtYWNjZXNzLWtleS1pZCI6IkFLSUE1QUlGNFdKSlhTN1lIRUczIiwiYXdzLXNlY3JldC1rZXkiOiI3U0RNc0pBNHM1RitXZWJ1L3pMOHZrMFFXV0lsa1c2Y1dOZlVsQ0tRIn0= ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
```

`fingerprint=` is the fingerprint of bridge that the client will ultimately be connecting to.

`url=` is the URL of a broker instance. If you would like to try out Snowflake with your own broker, simply provide the URL of your broker instance with this option.

`fronts=` is an optional, comma-seperated list front domains for the broker request.

`ice=` is a comma-separated list of ICE servers. These must be STUN (over UDP) servers with the form stun:<var>host</var>[:<var>port</var>]. We recommend using servers that have implemented NAT discovery. See our wiki page on [NAT traversal](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/wikis/NAT-matching) for more information.

`utls-imitate=` configuration instructs the client to use fingerprinting resistance when connecting when rendez-vous'ing with the broker.

To bootstrap Tor, run:
```
tor -f torrc
```
This should start the client plugin, bootstrapping to 100% using WebRTC.

### Registration methods

The Snowflake client supports a few different ways of communicating with the broker.
This initial step is sometimes called rendezvous.

#### Domain fronting HTTPS

For domain fronting rendezvous, use the `-url` and `-front` command-line options together.
[Domain fronting](https://www.bamsoftware.com/papers/fronting/)
hides the externally visible domain name from an external observer,
making it appear that the Snowflake client is communicating with some server
other than the Snowflake broker.

* `-url` is the HTTPS URL of a forwarder to the broker, on some service that supports domain fronting, such as a CDN.
* `-front` is the domain name to show externally. It must be another domain on the same service.

Example:
```
-url https://snowflake-broker.torproject.net.global.prod.fastly.net/ \
-front cdn.sstatic.net \
```

#### AMP cache

For AMP cache rendezvous, use the `-url`, `-ampcache`, and `-front` command-line options together.
[AMP](https://amp.dev/documentation/) is a standard for web pages for mobile computers.
An [AMP cache](https://amp.dev/documentation/guides-and-tutorials/learn/amp-caches-and-cors/how_amp_pages_are_cached/)
is a cache and proxy specialized for AMP pages.
The Snowflake broker has the ability to make its client registration responses look like AMP pages,
so it can be accessed through an AMP cache.
When you use AMP cache rendezvous, it appears to an observer that the Snowflake client
is accessing an AMP cache, or some other domain operated by the same organization.
You still need to use the `-front` command-line option, because the
[format of AMP cache URLs](https://amp.dev/documentation/guides-and-tutorials/learn/amp-caches-and-cors/amp-cache-urls/)
would otherwise reveal the domain name of the broker.

There is only one AMP cache that works with this option,
the Google AMP cache at https://cdn.ampproject.org/.

* `-url` is the HTTPS URL of the broker.
* `-ampcache` is `https://cdn.ampproject.org/`.
* `-front` is any Google domain, such as `www.google.com`.

Example:
```
-url https://snowflake-broker.torproject.net/ \
-ampcache https://cdn.ampproject.org/ \
-front www.google.com \
```

#### Direct access

It is also possible to access the broker directly using HTTPS, without domain fronting,
for testing purposes. This mode is not suitable for circumvention, because the
broker is easily blocked by its address.
