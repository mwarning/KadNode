# KadNode

KadNode is a small P2P DNS resolver to resolve and authenticate custom domains using the BitTorrent Peer-to-Peer network.

Domain queries for the .p2p TLD are intercepted on the systems level. This makes it possible to use it with programs like browsers or console tools.

Support for TLS allows authentication using existing Certificate Authorities (CA).
As an alternative, domains can consist of 32 Byte hexadecimal domains representing public keys.

## Features:

* IPv4/IPv6 support
* TLS support (e.g. can use browser CA chain)
* Public key links as <public-hex-key>.p2p
* UPnP/NAT-PMP support
* local peer discovery
* small size, ~85KB depending on features
* command line interface (kadnode-ctl)
* NSS support through /etc/nsswitch.conf
* integrated simplified DNS server and proxy (handles A, AAAA, and SRV requests)
* packages for ArchLinux/Debian/FreeBSD/MacOSX/LEDE/Windows
* peer file import/export on startup/shutdown and every 24h

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
