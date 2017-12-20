# KadNode

KadNode is a small decentralized DNS resolver that can use existing public key infrastructures. It utilizes the BitTorrent P2P network and mbedtls for TLS/crypto support.

KadNode can intercept .p2p domain queries on the systems level and resolve them using a decentralized network. [TLS](https://de.wikipedia.org/wiki/Transport_Layer_Security) authentication can be used to make sure the correct IP address was found, before it is passed to the browser or any other application.

Supported are also domains consisting of public keys represented as hexadecimal characters. :-)

## Features:

* IPv4/IPv6 support
* TLS support (CA chain for browsers, "Let's Encrypt" certs, ...)
* Public key links as <public-hex-key>.p2p
* UPnP/NAT-PMP support
* local peer discovery
* small size, ~85KB depending on features, ~35KB compressed
* command line interface (kadnode-ctl)
* NSS support through /etc/nsswitch.conf
* DNS interface and proxy support
* integrated simplified DNS server and proxy (handles A, AAAA, and SRV requests)
* packages for ArchLinux/Debian/FreeBSD/MacOSX/OpenWrt/Windows
* peer file import/export on startup/shutdown and every 24h
* uses sha256 hash method

## Documentation

- [Manual Page](misc/manpage.md)
- [Implementation Details](misc/implementation.md)
- [Usage examples](misc/examples.md)
- [FAQ](misc/faq.md)

## License

  MIT/X11

## Authors

  * KadNode: Moritz Warning (http://github.com/mwarning/KadNode)
  * Kademlia DHT: Juliusz Chroboczek (https://github.com/jech/dht)
