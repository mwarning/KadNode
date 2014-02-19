#kadnode(1) - P2P name resolution daemon

## SYNOPSIS

`kadnode`  [--value-id identifier] [--port port] [--daemon] [...]

`kadnode-ctl`  [...]

## DESCRIPTION

**KadNode** is a small P2P name/resource resolution daemon based
on the distributed hash table (DHT) identical to the one used in the
Transmission Bittorrent client. It can be used as a personal and
decentralized DynDNS service that intercepts and resolves DNS requests.

Features:

* IPv4/IPv6 support
* UPnP/NAT-PMP support
* local peer discovery
* small size 75KB-125KB
* public/secret key authentification
* command line interface (kadnode-ctl)
* NSS support through /etc/nsswitch.conf.
* buildin simplified DNS server
* packages for Debian/ArchLinux/OpenWrt

Most features are optional and can be left out to reduce the binary size.


##Join the a swarm

If KadNode cannot join a swarm (empty peerfile and no other peer on the local network)
you need to provide node address to boostrap from. To do this, insert bttracker.debian.org into an empty
file and provide it to KadNode:

```
kadnode --peerfile peers.txt
```

If boostrapping is successful then good peers will be written to the peer file on KadNode shutdown
and after at least 5 minutes of running time. This ensures successful boostrapping on the next startup.

##Authentification

You first need to create a secret/public key pair somewhere:

```
$kadnode --auth-genkey
public key: <public-key>
secret key: <secret-key>
```

The keys are not displayed here for convenience.

###Example 1

For a typical use case of reaching a computer (Node1) from another (Node2).

On Node1, well tell Kadnode to announce that we have node1.p2p
using the matching secret key.
```
$kadnode --auth-add-skey "node1.p2p:<secret-key>" --value-id node1.p2p
```

On Node2, we tell the node to use the public key to verfiy requests for node1.p2p.
```
$kadnode --auth-add-pkey "node1.p2p:<public-key>"
```

On Node2, we now can enter node1.p2p into the browser to reach Node1.
This may take ~8 seconds on the first try.

###Example 2

Instead of just one name, it is possible ot use wildcards in front of the patterns:

Node1 will be reachable using node1.p2p and foobar.p2p.
```
$kadnode --auth-add-skey "*.p2p:<secret-key>" --value-id node1.p2p --value-id foobar.p2p
```

Node2 can be reached by node2.p2p and foobar.p2p as well.
```
$kadnode --auth-add-skey "*.p2p:<secret-key>" --value-id node2.p2p --value-id foobar.p2p
```

On Node3, resolving "node1.p2p", "node2.p2p" and "foobar.p2p" to its IP address should now work.
```
$kadnode --auth-add-pkey "*.p2p:<public-key>"
</pre>
```
Since foobar.p2p is given twice, KadNode will give both IP addresses.
Almost all programs will just use the first address they get.

Multiple --auth-add-key and --value-id arguments are possible.
Pattern conflicts will result in an error message on startup.
Command line options can also be loaded from file (see --config <file>).

##Identifiers

Identifiers are what you use to lookup IP addresses (e.g. domain names).
They will reduced to 20 Byte hexadecimal representations (digest) that
will be used in the actual lookup process. KadNode allows four types of identifiers:

* Raw identifiers are 20 Byte hex strings that will be translated to the 20 Byte info hash used in the DHT.
* Raw public key identifiers are 32 Byte hex strings and will be interpreted as a public key.
  * The sha1 digest of the key string respresentation is used to locate nodes.
  * The public key is used to verify if the nodes found have the corresponding secret key.
* Plain identifiers are just strings that have no key associated to them.
  * The sha1 digest is used to find nodes.
* Plain identifiers that match a given pattern and have a public key assigned to them.
  * The sha1 digest of the string and public key is ued to find nodes.
  * The public key is used to verify if the nodes found have the corresponding secret key.

All identifiers are converted to lowercase and therefore case insensitive.
A ".p2p" at the end of every identifier is ignored because it is used to direct requests to KadNode.


## OPTIONS
  * `--node-id` *id*  
    Set the node identifier. This option is rarely needed.  
	By default the node id is random.

  * `--value-id` *id[:port]*  
    Add a value identifier and optional port to be announced every 30 minutes.  
    The announcement will associate this nodes IP address with this identifier.  
    This option can occur multiple times.

  * `--peerfile` *file-path*  
    Import peers for bootstrapping and write good peers to this file on shutdown.

  * `--user` *name*  
    Change the UUID after start.

  * `--port` *port*  
    Bind the DHT to this port.  
    Default: 6881

  * `--config` *file*  
    Provide a configuration file with one command line  
    option on each line. Comments start after '#'.

  * `--ifce` *interface*  
    Bind to this specific interface.

  * `--mcast-addr` *address*  
    Send pings to this multicast address as long no nodes were found.  
    Default: 239.192.202.7:6771 / [ff08:ca:07::]:6771

  * `--disable-forwarding`  
    Disable UPnP/NAT-PMP to forward router ports.

  * `--disable-multicast`  
    Disable multicast to discover local nodes.

  * `--daemon`  
    Run in background.

  * `--verbosity` *level*  
    Verbosity level: quiet, verbose or debug (Default: verbose).

  * `--pidfile` *file-path*  
    Write process pid to a file.

  * `--cmd-port` *port*  
    Bind the remote control interface to this local port (Default: 1700).

  * `--dns-port` *port*  
    Bind the DNS server to this local port (Default: 5353).

  * `--nss-port` *port*  
    Bind the "Network Service Switch" to this local port (Default: 4053).

  * `--web-port` *port*  
    Bind the web server to this local port (Default: 8053).

  * `--auth-gen-keys`  
    Generate a secret/public key pair.

  * `--auth-add-pkey` *[<pat>:]<pkey>*  
    Associate a public key with any value id that matches the pattern.
    Used to verify that the other side has the secret key.
    This option can occur multiple times.

  * `--auth-add-skey` *[<pat>:]<skey>*  
    Associate a secret key with any value id that matches the pattern.
    Used to prove the ownership of the domain.
    This option can occur multiple times.

  * `--mode` *protocol*  
    Enable IPv4 or IPv6 mode for the DHT (Default: ipv4).

  * `-h`, `--help`  
    Print the list of accepted options.

  * `-v`, `--version`  
    Print program version and included features.

## kadnode-ctl

**kadnode-ctl** allows to control KadNode from the command line.

  * `-p` *port*  
    The port used to connect to the command line of a local KadNode instance (Default: 1700).

  * `-h`  
    Print this help.

### KadNode Console Commands

  * `status`  
    Print the node id, the number of known nodes / searches / stored hashes and more.

  * `lookup` *id*  
    Lookup the IP addresses of all nodes that claim to satisfy the identifier.  
	The first call will start the search.

  * `announce` *id*[<i>:*port*</i>] [<i>*minutes*</i>]  
    Announce that this instance is associated with identifier  
    and an optional port. The default port is random (but not equal 0).  
    The announcement will happen only once unless a time  
    in minutes is given or -1 minutes for the entire runtime.

  * `import` *addr*  
    Send a ping to another KadNode instance to establish a connection.

  * `export`  
    Print a few good nodes.

  * `list` [`blacklist`|`buckets`|`constants`|`forwardings`|`results`|`searches`|`storage`|`values`]  
    List various internal data structures.

  * `blacklist` *addr*  
    Blacklist a specifc IP address.

## Web Interface

The optional web interface allows queries of these forms:

  * `http://localhost:8053/lookup?foo.p2p`
  * `http://localhost:8053/announce?foobar`
  * `http://localhost:8053/blacklist?1.2.3.4`

If the interface cannot be reached then the interface might be disabled (port set to 0)
or not compiled in (check `kadnode --version`).
In case the IPv6 entry for localhost is not used or missing, try `[::1]` instead of `localhost`.

## NOTES

  * .p2p at the end of a identifier is ignored by KadNode. It is used to filter requests and divert them to KadNode.
  * At least one other Node is needed to resolve any, even own, announced values.

## LICENSE

  MIT/X11

## AUTHORS

  * KadNode: Moritz Warning (http://github.com/mwarning)
  * Kademlia: Juliusz Chroboczek
  * SHA1: Steve Reid
