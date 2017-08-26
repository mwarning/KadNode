# Implementation Details


## Components

Crypto/TLS support is provided by [libmbedtls](https://github.com/ARMmbed/mbedtls/). The libr
ary is also used by OpenWrt.

The [DHT](https://github.com/jech/dht) is identical to the one used in the Transmission Bitto
rrent client and works'on the Internet as well as on local networks.

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

