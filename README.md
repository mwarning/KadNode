# KadNode

KadNode finds the IP address of other instances on the Internet or local network based on names. It is used like DNS, but is based on the decentralized BitTorrent network.

KadNode intercepts .p2p domain queries on the systems level and resolve them using a decentralized [DHT](https://de.wikipedia.org/wiki/DHT) network. [TLS](https://de.wikipedia.org/wiki/Transport_Layer_Security) authentication can be used to make sure the correct IP address was found. If successful, the IP address is passed to the application making the request.

Supported are also domains consisting of public keys represented as characters. :-)

## Features:

* IPv4/IPv6 support
* Support for TLS authentication
  * Use CA browser chain and e.g. "Let's Encrypt" certificates for yourdomain.com(.p2p)
* Support for [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) public key links as \<public-hex-key\>.p2p
  * No need to exchange any keys between clients and servers
* UPnP/NAT-PMP support
* local peer discovery
* small size, ~85KB depending on features, ~35KB compressed
* command line control program
* NSS support through /etc/nsswitch.conf
* DNS server interface and DNS proxy
  * handles A, AAAA, and SRV requests
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
