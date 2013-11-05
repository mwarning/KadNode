kadnode(1) -- P2P name resolution daemon
=======================================

## SYNOPSIS

`kadnode`  [--id hostname] [--port port] [--daemon] [...]

`kadnode-ctl`  [...]

## DESCRIPTION

**KadNode** is a small P2P name/resource resolution daemon for IPv4/IPv6 based
on a distributed hash table (DHT). The implementation is identical to the one used
for the Transmission Bittorrent client.

KadNode enables the user to announce any kind of resource by an identifier.
This can be used e.g. to resolve a hostname to an IP address.
It is also small in size (~75KB) and uses only one thread to save resources.
Join any existing swarm to be able to find your node globally.

By default, KadNode tries to send a ping to a multicast address on the local network
to find nodes to bootstrap from. This is done every five minutes when no other nodes are known.
The interactive remote shell `kadnode-ctl` let the user import and export nodes, issue queries for
identifiers and send announcements.

As an usage example start `kadnode` and enter `import bttracker.debian.org`
to help KadNode to bootstrap into an existing network. The `status` command
will let you see the rising number of known nodes.
To let KadNode announce to the network that the identifier 'myname.p2p' should resolve to your
IP address, use `announce myname.p2p -1`.
The second argument "-1" is a special value and will cause Kadnode to keep the announcement
alive for the entire runtime. The same can be achieved using the `--value-id` argument at startup.
Any announcement will be dropped by other Kademlia DHT instances (such as Transmission)
after 32 minutes and therefore need to be refreshed by KadNode around every 30 minutes.

Values like `myname.p2p ` can be resolved by using the command `lookup myname.p2p`.
The NSS (Network Service Switch) support on many Posix systems (e.g. Ubuntu) can intercept
requests for the .p2p top level domain and allows the value to be used e.g. in the web browser.

Please be aware that other people might use the same identifier.
It is strongly advised to do additional identification/authentication
when an address is used that has been resolved by KadNode.
The DNS/NSS interfaces are only able to return one of these addresses.
In contrast, the web and console interface are able to return all known
IP addresses associated with an identifier.

Every entered identifier (e.g. `myname.p2p`) will have everything after and including the last dot ignored.
This is because the top level domain is often used to differentiate from classical domain names
and to redirect requests to KadNode.
The rest of the string is converted to an 20 byte identifier using the SHA1 hashing algorithm.
As an alternative, the hash can be entered directly as a 40 character hexadecimal string.
The string `myname.p2p` is therefore eqivalent to `d13b93ea42804188d277c20f7d6e5be2732148b8`
which is the result of SHA1('myname'). The use of the build-in hashing algorithm can be entirely
circumvented this way.


## INTERFACES

  * An interactive shell to issue queries and manage the DHT. Useful for shell scripts:
  `kadnode-ctl lookup myname.p2p`
  * Name Service Switch (NSS) support through /etc/nsswitch.conf.
  * A simple DNS server interface that can be used like a local upstream DNS server.
  * A simple web server interface to resolve queries: `http://localhost:8053/lookup?foo.p2p`

All these interfaces listen only for connections from localhost.

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
    Generate a secret/public key pair. Use the public key
    to resolve the node announcing the secret key.

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
    and an optional port. The default port is 1 (0 is for announces).  
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

  * `shutdown`  
    Shutdown the daemon.

## Authentication

KadNode allows optional node authentication. This means that you can lookup nodes using
a public key and verify that those nodes are in posession of the corresponding secret key.
To generate a new key pair use `kadnode --auth-gen-keys`.
Announce the secret key on a node e.g. via `kadnode --value-id <secret-key>` and then
lookup the nodes IP address on another computer using `<public-key>.p2p` in your browser
or `kadnode-ctl lookup <public-key>`.

## Web Interface

The optional web interface allows queries of these forms:

  * `http://localhost:8053/lookup?foo.p2p`
  * `http://localhost:8053/announce?foobar`
  * `http://localhost:8053/blacklist?1.2.3.4`

If the interface cannot be reached then the interface might be disabled (port set to 0)
or not compiled in (check `kadnode --version`).
In case the IPv6 entry for localhost is not used or missing, try `[::1]` instead of `localhost`.

## NOTES

  * This is not about traditional DNS. Everybody can announce everything. You need to decide which  
  of the resolved IP addresses you trust. Be random about the identifiers you announce. When retrieved  
  IP addresses do not deliver/verify for you, then you should blacklist those IP addresses.

  * Blacklisted addresses are stored in a LRU cache of maximal 10 entries.

## LICENSE

  MIT/X11

## AUTHORS

  * KadNode: Moritz Warning (http://github.com/mwarning)
  * Kademlia: Juliusz Chroboczek
  * SHA1: Steve Reid
