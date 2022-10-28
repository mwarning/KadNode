
# Implementation Details

## How does KadNode works

This is the progress for a domain lookup in the browser using TLS and a PKI.

1. A domain like example.com.p2p is entered in the web browser.
2. The request is filtered by KadNode on the system level via a local DNS proxy or NSS support.
3. The domain is hashed and a hash lookup on the DHT network is performed.
4. Zero to multiple IP Addresses are returned by the DHT.
5. To every IP address, a TLS session is established. If it succeeds, the IP is verified.
6. The verified IP addresses are based back from KadNode to the browser who establishes an HTTPS session to access a website.

## About Announcement

An announcement is done every 20 minutes. The lifetime of those entries on other peer is expected to be around 15 minutes.
Search results will be cached for about 20 minutes. If a lookup is done after 10 minutes after the search has been started, the search will be restarted and the cached results will be returned.

## Components

Crypto/TLS support is provided by [libmbedtls](https://github.com/ARMmbed/mbedtls/).
The library is also used by OpenWrt.

The [DHT](https://github.com/jech/dht) is identical to the one used in the Transmission Bittorrent
client and works on the Internet as well as on local networks.

## Features List

Most features are optional and can be left out to reduce the binary size.
To get a list of features the program is compiled with, call `kadnode --version`:

* cmd - Command line. Mostly useful for debugging.
* debug - Enabled debug output. For debugging.
* lpd - Local peer discovery. Finds local peers.
* tls - TLS authentication. Uses libmbedtls.
* bob - Raw secret/public key authentication. Uses libmbedtls.
* dns - DNS interface support.
* nss - Name Service Switch interface support.
* upnp - Universal Plug and Play support. For automatic port forwarding.
* natpmp - NAT Port Mapping support. For automatic port forwarding.

