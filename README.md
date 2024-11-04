# KadNode

KadNode finds the IP address of other instances on the Internet or local network.
It is used like DNS, but is based on the decentralized BitTorrent network.

KadNode intercepts .p2p domain queries on the systems level and resolves them using a decentralized [Kademlia DHT](https://en.wikipedia.org/wiki/Kademlia) network.
Additionally, [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) authentication can be used to make sure the correct IP address was found.
If successful, the IP address is passed to the application making the request.

## Features:

* Support for two kinds of domains:
  1. public key domains as `<public-key>.p2p`
     * No need to exchange any further keys/certificates
     * Uses secp256r1 [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) key pairs
  2. named domains like `yourdomain.com.p2p`
     * Needs pre-shared certificates (self-signed root certificates or e.g. "Let's Encrypt")
     * Uses TLS session handshake for authentication
* IPv4/IPv6 support
* UPnP/NAT-PMP support
* Local peer discovery
* Small size / ~100KB depending on features / ~50KB compressed
* Command line control program
* NSS support through /etc/nsswitch.conf
* DNS server interface and DNS proxy
  * Handles A, AAAA, and SRV requests
* Packages for ArchLinux, Debian, FreeBSD, MacOSX, OpenWrt, Windows
* Peer file import/export on startup/shutdown and every 24h
* Uses sha256 hash method

## Documentation

- [Manual Page](misc/manpage.md)
- [Implementation Details](misc/implementation.md)
- [Usage examples](misc/examples.md)
- [FAQ](misc/faq.md)
- [Video: KadNode decentralized DNS system - 34. Chaos Communication Congress](https://www.youtube.com/watch?v=DFFNEoEYItE)

## Installation
You can download the latest package from [releases page](https://github.com/mwarning/KadNode/releases/)

### OpenWrt
From official package repository:
`opkg install kadnode`

### Debian/Ubuntu
From PPA repository:
```
sudo add-apt-repository ppa:stokito/kadnode
sudo apt update
sudo apt install kadnode
```

Or install a downloaded package with `dpkg -i kadnode_*.deb`

### FreeBSD
From repository: `pkg install kadnode`
 
Or install a downloaded package with `pkg install kadnode-*.txz`

### ArchLinux
install a downloaded package with:  `pacman -U kadnode-*.pkg.tar.xz`

## Related Projects

* [pkdns](https://github.com/pubky/pkdns)
* [btlink](https://github.com/anacrolix/btlink)
* [DNSLink](https://dnslink.org/) Standard

## License

  MIT/X11

## Authors

  * KadNode: Moritz Warning (http://github.com/mwarning/KadNode)
  * Kademlia DHT: Juliusz Chroboczek (https://github.com/jech/dht)
