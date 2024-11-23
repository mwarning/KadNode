# KadNode - P2P DNS

KadNode finds the IP address of other instances on the Internet or local network.
It is used like DNS, but is based on the decentralized BitTorrent network.

KadNode intercepts `.p2p` domain queries on the systems level and resolves them using a decentralized [Kademlia DHT](https://en.wikipedia.org/wiki/Kademlia) network.
Additionally, [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) authentication can be used to make sure the correct IP address was found.
If successful, the IP address is passed to the application making the request.


## Features

* Support for two kinds of domains:
  1. public key domains as `<public-key>.p2p`
     * No need to exchange any further keys/certificates
     * Uses `secp256r1` [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) key pairs
  2. named domains like `yourdomain.com.p2p`
     * Needs pre-shared certificates (self-signed root certificates or e.g. `Let's Encrypt`)
     * Uses TLS session handshake for authentication
* IPv4/IPv6 support
* UPnP/NAT-PMP support
* Local peer discovery
* Small size / ~100KB depending on features / ~50KB compressed
* Command line control program
* NSS support through `/etc/nsswitch.conf`
* DNS server interface and DNS proxy
  * Handles `A` (IPv4 address),`AAAA` (IPv6), and `SRV` requests
* Packages for ArchLinux, Debian, FreeBSD, MacOSX, OpenWrt, Windows
* Peer file import/export on startup/shutdown and every 24h
* Uses `sha256` hash method


## Documentation

- [Manual Page](misc/manpage.md)
- [Implementation Details](misc/implementation.md)
- [Usage examples](misc/examples.md)
- [FAQ](misc/faq.md)
- [Wiki](https://github.com/mwarning/KadNode/wiki/)
- [Video: KadNode decentralized DNS system - 34. Chaos Communication Congress](https://www.youtube.com/watch?v=DFFNEoEYItE)


## Installation
You can download the latest package from [releases page](https://github.com/mwarning/KadNode/releases/latest/)


### OpenWrt
From official package repository:
`opkg install kadnode`


### Debian/Ubuntu
From PPA repository:
```sh
sudo add-apt-repository ppa:stokito/kadnode
sudo apt update
sudo apt install kadnode
```

Or install a downloaded package with `dpkg -i kadnode_*.deb`


### FreeBSD
From repository: `pkg install kadnode`

Or install a downloaded package with `pkg install kadnode-*.txz`


### ArchLinux
From repository: `yay -S kadnode`

Or install a downloaded package with `pacman -U kadnode-*.pkg.tar.xz`


## Build from sources
Install libraries and their headers. On Debian/Ubuntu use:
```sh
sudo apt install libmbedtls-dev, libnatpmp-dev, libminiupnpc-dev
```

Checkout code and compile KadNode:
```sh
git clone https://github.com/mwarning/KadNode.git
cd KadNode
# basic features and debug mode
FEATURES="bob tls cmd dns debug" make
# all features
FEATURES="bob tls cmd lpd dns nss natpmp upnp debug" make
```

Finally, start KadNode:

```sh
./build/kadnode
```

To install use:
```
sudo make install
```


## Related Projects

* [pkdns](https://github.com/pubky/pkdns) and [Pkarr](https://github.com/pubky/pkarr) ed25519 pubkey domains on Mainline DHT.
* [btlink](https://github.com/anacrolix/btlink) an HTTP addressing scheme for BitTorrent.
* [DNSLink Standard](https://dnslink.org/) a format used by IPFS for DNS TXT records to associate content and identifiers with a domain.
* [Tor Onion Services](https://en.wikipedia.org/wiki/.onion)
* [GNUnet Name System](https://gnunet.org/) secure and decentralized naming system
* [NameCoin](https://www.namecoin.org/) blockchain for DNS


## License

  MIT/X11


## Authors

  * KadNode: Moritz Warning (http://github.com/mwarning/KadNode)
  * Kademlia DHT: Juliusz Chroboczek (https://github.com/jech/dht)
