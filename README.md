kadnode(1) -- P2P name resolution daemon
=======================================

## SYNOPSIS

`kadnode`  [--id hostname] [--port port] [--daemon] [...]

`kadnode-ctl`  [...]

## DESCRIPTION

**KadNode** is a small P2P name/resource resolution daemon for IPv4/IPv6 based on the Kademlia
implementation of a distributed hash table (DHT).

KadNode enables the user to announce any kind of resource by an identifier.
This can be used e.g. to resolve a hostname to an IP address.

By default, KadNode tries to send a ping to a multicast address on the local network
to find nodes to bootstrap from. This is done every five minutes when no other nodes are known.
The interactive remote shell `kadnode-ctl` let the user import and export nodes, issue queries for
identifiers and send announcements.

As an usage example one would start `kadnode --value-id myname.p2p` to let KadNode
announce every 30 minutes, that the IP address of the running KadNode instance
is associated with the identifier 'myname.p2p'.
A call like `kadnode-ctl import example.com` can be used to help KadNode to bootstrap
into an existing network.
To announce an identifier just once, use `kadnode-ctl announce myname`.
Any announcement will be dropped by other KadNode instances after 32 minutes and
therefore need to be refreshed around every 30 minutes.

Please be aware that other people might use the same identifier.
It is strongly advised to do additional identification/authentification
when an address is used that has been resolved by KadNode.

Every entered identifier (e.g. `myname.p2p`) will have everything after the last dot ignored as a top level domain like
is often used only to redirect queries to KadNode.
The rest of the string is converted to an 20 byte identifier using the sha1 hashing algorithm.
As an alternative, the hash can be entered directly as a 40 character hexadecimal string.
The string `myname.p2p` is therefore eqivalent to `d13b93ea42804188d277c20f7d6e5be2732148b8`
which is the result of sha1('myname'). This is true for every entered identifier that involves KadNode.

## INTERFACES

  * An interactive shell to issue queries and manage the DHT. Useful for shell scripts:
  `kadnode-ctl search myname.p2p`
  * Name Service Switch (NSS) support through /etc/nsswitch.conf.
  * A simple DNS server interface that can be used like a local upstream DNS server.
  * A simple web server interface to resolve queries: `http://localhost:8053/foo.p2p`

All these interfaces listen only for connections from localhost.

## DOWNLOADS

  * https://sourceforge.net/projects/kadnode/files/

## OPTIONS
  * `--node-id` *id*  
    Set the node identifier. This option is rarely needed.  
	By default the node id is random.

  * `--value-id` *id[:port]*  
    Add a value identifier and optional port to be announced every 30 minutes.  
    The announcement will associate this nodes IP address with this identifier.  
    This option can occur multiple times.

  * `--user` *name*  
    Change the UUID after start.

  * `--port` *port*  
    Bind the DHT to this port.  
    Default: 8337

  * `--ifce` *interface*  
    Bind to this specific interface.

  * `--mcast-addr` *address*  
    Send pings to this multicast address as long no nodes were found.  
    Default: 239.192.202.7 / ff08:ca:07::

  * `--disable-mcast`  
   Disable multicast.

  * `--daemon`  
    Run in background.

  * `--verbosity`  
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

  * `--mode` *protocol*  
    Enable IPv4 or IPv6 mode for the DHT (Default: ipv4).

  * `-h`, `--help`  
    Print this help.

  * `-v`, `--version`  
    Print program version.

### kadnode-ctl

**kadnode-ctl** allows to control KadNode from the command line.

  * `-p` *port*  
    Connect to the local KadNode console on this interface (Default: 1700):

  * `-h`  
    Print this help.

#### KadNode Console Commands

  * `status`  
    Print the node id, the number of known nodes / searches / stored hashes and more.

  * `search` *id*  
    Start a search for nodes closest to the given identifier id.

  * `lookup` *id*  
    Lookup the IP addresses of all nodes that claim to satisfy the identifier.  
	The lookup is performed on the current search results.

  * `lookup_node` *id*  
    Lookup the IP address of a node that has identifier id.  
	The lookup is performed on the current search results.

  * `announce` *id* [*port*]  
    Announce that this instance is associated with identifier.  
    The announcement will happen only once and instantly.

  * `import` *addr*  
    Send a ping to another KadNode instance to establish a connection.

  * `export`  
    Print a few good nodes. The argument allows to select only IPv6 or IPv4 addresses.

  * `blacklist` *addr*  
    Blacklist a specifc IP address.

  * `shutdown`  
    Shutdown the daemon.

## LIMITATIONS

  * KadNode cannot resolve its own node id without other nodes present.
  * No NAT-traversal was implemented yet.
  * Kademlia drops announcements after 30 minutes. Those need to be refreshed.
  * Blacklisted addreses are stored in a LRU cache of maximal 10 entries.

## LICENSE

  MIT/X11

## AUTHORS

  * KadNode: Moritz Warning (http://github.com/mwarning)
  * Kademlia: Juliusz Chroboczek
  * SHA1: Steve Reid
