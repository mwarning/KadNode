## kadnode(1) - P2P name resolution daemon

## SYNOPSIS

`kadnode`  [--value-id identifier] [--port port] [--daemon] [...]

`kadnode-ctl`  [...]

## DESCRIPTION

**KadNode** is a small P2P DNS resolution daemon based on a Distributed Hash Table (DHT).
KadNode can intercept and resolve DNS request in the systems background.
Every instance can also announce any domain like e.g. myname.p2p. People on others
devices running KadNode can then enter myname.p2p into their browsers or console in order
to reach the announcing host. To avoid name clashes, cryptographic public/private key pairs can be used.
This makes it possible to have a personal and decentralized DynDNS service.
The [DHT](https://github.com/jech/dht) is identical to the one used in the Transmission Bittorrent client and works'on the Internet as well as on local networks.

Features:

* IPv4/IPv6 support
* TLS support (e.g. can use browser CA chain)
* Plain public key links as <public-hex-key>.p2p
* UPnP/NAT-PMP support
* local peer discovery
* small size, ~30KB compressed
* public/secret key authentication (based on [mbedtls](https://github.com/ARMmbed/mbedtls/))
* command line interface (kadnode-ctl)
* NSS support through /etc/nsswitch.conf
* integrated simplified DNS server and proxy (handles A, AAAA, and SRV requests)
* packages for ArchLinux/Debian/FreeBSD/MacOSX/LEDE/Windows
* peer file import/export on startup/shutdown and every 24h

Most features are optional and can be left out to reduce the binary size.


## JOIN THE SWARM

KadNode needs to know at least one active peer to join / bootstrap into the swarm.
There are three ways to archieve this:

1. Provide one or more peers to the command line arguments. These could be public BitTorrent trackers, or other KadNode instances:
```
kadnode --peer bttracker.debian.org --peer 192.168.1.1
```

2. Use the local peer discovery feature. Just start kadnode and it will try to discover other node in the local network.

3. Ping a node using the KadNode console if present:
```
kadnode-ctl ping bttracker.debian.org
```

Also provide a --peerfile argument to let KadNode storage its peerlist on shutdown and every 24h.
This ensures successful boostrapping on the next startup.


## AUTHENTICATION

KadNode provides two authentication schemes. One works via TLS. The other one uses raw secret/public keys and is hence called bob, because ... it is simple.

# Via TLS

# via BOB

```
$kadnode --auth-gen-keys
public key: <public-key>
secret key: <secret-key>
```

(The keys are not displayed here for convenience.)

### EXAMPLE 1

A typical use case would be to reach a computer (Node1) from another (Node2).
On Node 1 we announce an identifier (`sha1(myname)`):
```
$kadnode --value-id myname.p2p
```

On other computers running KadNode, we can use myname.p2p to resolve
the IP address of Node1 (e.g. in the web browser). It may take ~8 seconds on the first try.
The problem with this approach is that others could also announce the same identifier.
This would result in multiple IP addresses to be found and used.
To avoid this you can use secret/public key pairs. See the next examples.

### EXAMPLE 2

Now we want to reach a computer (Node1) from another (Node2) using cryptographic keys.
We tell KadNode on Node1 to *announce* its secret key.
```
$kadnode --value-id <secret-key>.p2p
```
What is actually announced is the SHA1 hash of the derived public key (`sha1(<public-key>)`),
not the secret key itself.

On Node2, we can now resolve `<public-key>.p2p`.

### EXAMPLE 3

Instead of using keys directly as in example 1, we can also use domains.

On Node1, well tell Kadnode to announce that we have node1.p2p using the secret key.
```
$kadnode --auth-add-skey "node1.p2p:<secret-key>" --value-id node1.p2p
```
The announced identifier here is `sha1(<public-key>+"node1")`.

On Node2, we tell the node to use the public key to verifiy requests for node1.p2p.
```
$kadnode --auth-add-pkey "node1.p2p:<public-key>"
```
The identifier that is searched for is `sha1(<public-key>+"node1")`.

On Node2, we now can enter node1.p2p into the browser or try to ping node1.p2p to see
if the address is resolved successfully. The authentication step uses the public key
to filter out all nodes that do not know the secret key.

### EXAMPLE 4

It is possible to associate a secret/public key to multiple domains using patterns:

Node1 will be reachable using node1.p2p and foobar.p2p.
```
$kadnode --auth-add-skey "*.p2p:<secret-key>" --value-id node1.p2p --value-id foobar.p2p
```

Node2 will be reachable using node2.p2p and foobar.p2p as well.
```
$kadnode --auth-add-skey "*.p2p:<secret-key>" --value-id node2.p2p --value-id foobar.p2p
```

On Node3, resolving "node1.p2p", "node2.p2p" and "foobar.p2p" to its IP address should now work.
```
$kadnode --auth-add-pkey "*.p2p:<public-key>"
```
Since foobar.p2p is used twice, KadNode will give both IP addresses.
But almost all programs will just use the first address they get,
which is the first that will be successfully verified.

Multiple --auth-add-key and multiple --value-id arguments are possible.
Pattern conflicts will result in an error message on startup.
Command line options can also be put inside a configuration file (see --config *file*).

## OPTIONS

  * `--announce` *name[:port]*  
    Announce a hostname. A domain as hostname is expected to authenticate by on port 443 (e.g. a webserver using HTTPS).
    This option may occur multiple times.

  * `--peerfile` *file-path*  
    Import peers for bootstrapping and write good peers  
	to this file every 24 hours and on shutdown.

  * `--user` *name*  
    Change the UUID after start.

  * `--port` *port*  
    Bind the DHT to this port (Default: 6881).  

  * `--config` *file*  
    Provide a configuration file with one command line  
    option on each line. Comments start after '#'.

  * `--ifname` *interface*  
    Bind to this specific interface.

  * `--fwd-disable`  
    Disable UPnP/NAT-PMP to forward router ports.

  * `--daemon`  
    Run in background.

  * `--query-tld` *domain*  
    Top level domain used to filter queries to be resolved by KadNode. (Default: ".p2p")

  * `--verbosity` *level*  
    Verbosity level: quiet, verbose or debug (Default: verbose).

  * `--pidfile` *file-path*  
    Write process pid to a file.

  * `--lpd-addr` *address*  
    Send LPD packets to this multicast address as long no peers were found.  
    Default: 239.192.152.143:6771 / [ff15::efc0:988f]:6771

  * `--lpd-disable`  
    Disable Local Peer Discovery (LPD).

  * `--cmd-disable-stdin`  
    Disable the local control interface.

  * `--cmd-port` *port*  
    Bind the remote control interface to this local port (Default: 1700).

  * `--dns-port` *port*  
    Bind the DNS server interface to this local port (Default: 3535).

  * `--dns-server` *address*  
    IP address of an external DNS server. Enables DNS proxy mode (Default: none).

  * `--dns-proxy-enable`  
    Enable DNS proxy mode. Reads /etc/resolv.conf by default.

  * `--dns-proxy-server` *ip-address*  
    Use IP address of an external DNS server instead of resolv.conf.

  * `--nss-port` *port*  
    Bind the "Name Service Switch" to this local port (Default: 4053).

  * `--tls-client-cert` *path*  
    Path to file or folder of CA root certificates.  
    This option may occur multiple times.

  * `--tls-server-cert` *tuple*  
    Add a comma separated tuple of server certificate file and key.  
    The certificates Common Name is announced.
    This option may occur multiple times.  
    Example: kadnode.crt,kadnode.key

  * `--bob-create-key` *file*  
    Bob  

  * `--bob-load-key` *file*  
    Bob  

  * `--ipv4, -4, --ipv6, -6`  
    Enable IPv4 or IPv6 only mode for the DHT (Default: IPv4+IPv6).

  * `-h`, `--help`  
    Print the list of accepted options.

  * `-v`, `--version`  
    Print program version and included features.

### KadNode Console Commands

When not started in background, KadNode accepts a variety of commands from standard input.

  * `status`  
    Print the node id, the number of known nodes / searches / stored hashes and more.

  * `lookup` *query*  
    Lookup the IP addresses of all nodes that claim to satisfy the query.  
	The first call will start the search.

  * `announce` [*query*[<i>:*port*</i>] [<i>*minutes*</i>]]  
    Announce that this instance is associated with a query  
    and an optional port. The default port is random (but not equal 0).  
    No *minutes* trigger a single announcement. Negative *minutes*  
    last for the entire runtime. Otherwise the lifetime is set *minutes* into the future.  
    No arguments will announce all identifiers at once.

  * `import` *addr*  
    Send a ping to another KadNode instance to establish a connection.

  * `export`  
    Print a few good nodes.

  * `list` [`blacklist`|`buckets`|`constants`|`forwardings`|`results`|`searches`|`storage`|`values`]  
    List various internal data structures.

  * `blacklist` *addr*  
    Blacklist a specifc IP address.

## KadNode External Console

KadNode allows a limited set of commands to be send from any user from other consoles.

`kadnode-ctl` [-p port] [status|lookup|announce|import|export|blacklist]

  * `-p` *port*  
    The port used to connect to the command shell of a local KadNode instance (Default: 1700).

  * `-h`  
    Print this help.

## PORT FORWARDINGS

If KadNode runs on a computer in a private network, it will try to establish a port forwarding for the DHT port.
Port forwarding only works if UPnP/NAT-PMP is compiled into KadNode and is supported by the gateway/router.
Also, ports attached to announcement values (e.g. `--value-id foo.p2p:80`) will result in additional port forwardings.
This is useful to make a local service (e.g. a web server) reachable from the Internet without the need to
configure port forwardings manually.

## NOTES

  * *.p2p* at the end of an identifier (or set by --query-tld) is ignored by KadNode. It is used to filter requests and divert them to KadNode.
  * The interfaces (NSS, DNS, command line) may return the localhost address if the node itself announced a value.

## LICENSE

  MIT/X11

## AUTHORS

  * KadNode: Moritz Warning (http://github.com/mwarning)
  * Kademlia: Juliusz Chroboczek
  * SHA-1: Steve Reid
