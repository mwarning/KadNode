kadnode(1) -- P2P name resolution daemon
=======================================

## SYNOPSIS

`kadnode`  [--id hostname] [--port port] [--daemon] [...]

`kadnode-ctl`  [...]

## DESCRIPTION

**KadNode** is a small P2P name resolution daemon for IPv4 and IPv6 based on the Kademlia
implementation of a distributed hash table (DHT).
By default, KadNode tries to send a ping to a multicast address on the local network
to find nodes to bootstrap from. This is done every five minutes when no other nodes are known.
The interactive remote shell `kadnode-ctl` let the user import and export nodes, issues queries for
hash identifiers and send announcements.

As an usage example one would call `kadnode --id myname.p2p` and call `kadnode-ctl import some-dht-tracker.com:4242`
to help KadNode to bootstrap into an existing network network of at least one other node.
On another computer that runs KadNode and that is connected to any nodes of the same network,
myname.p2p can be entered in the browser and will now resolve to the ip address of the computer the first
other KadNode instance is running.
The domain name query is passed from the browser to the operating system to the NSS interface of KadNode.
This way a domain can be resolved in a browser or any program on the computer.

KadNode/Kademlia is about two types of (20 Byte long) identifiers, node ids and value ids.
Every Kademlia instance has one node id and can be used to also announce/resolve
multiple value ids. DNS requests will be only mapped to node ids.
Value ids have to be announced to other nodes using the *kadnode-ctl announce <id> <port>* command
and will tell other nodes that a resource identified by the given id can be satisfied by this node on the given port.
This could refer to a file hash or any other type of resource. Every KadNode forgets received announcements
after 32 minutes, so these have to be refreshed regulary. Multiple nodes can announce the same value id.

Identifiers entered in domain name syntax like `myname.p2p` will have the top level domain ignored
and the rest converted to an id using the sha1 hash.
As an alternative, the hash can be used directly as a 40 character hex string.
The string `myname.p2p` is therefore eqivalent to `fd0bef09a735b3cef767fb2c62b6bd365346bee5`
which is the result of sha1('myname'). This is true for every entered identifier involving KadNode.

## INTERFACES

  * An interactive shell to issue queries and manage the DHT. Useful for shell scripts:
  `kadnode-ctl myname.p2p`
  * Name Service Switch (NSS) support through /etc/nsswitch.conf.
  * A simple DNS server interface that can be used like a local upstream DNS server.
  * A simple web server interface to resolve queries: `http://localhost:8080/foo.p2p`

## DOWNLOADS

  * https://sourceforge.net/projects/kadnode/files/0.1/

## OPTIONS
  * `--id` *identifier*:
    Set the node identifier. Either a 20 Byte hexadecimal string or a different string whose sha1 hash will be used. 
	A random id will be computed if this option is not used.

  * `--user` *name*
    Change the UUID after start.

  * `--port` *port*:
    Bind the DHT to this port.
    Default: 8337

  * `--ifce` *interface*:
	Bind to this interface (Default: &lt;all&gt;).

  * `--mcast-addr4` *address*:
    Send pings to this multicast address as long no nodes were found.
    Default: 239.0.0.1

  * `--mcast-addr6` *address*:
    Send pings to this multicast address/port as long no nodes were found.
    Default: ff0e::1

  * `--daemon`:
    Run in background.

  * `--verbosity`:
    Verbosity level: quiet, verbose or debug (Default: verbose).

  * `--pidfile` *file-path*
    Write process pid to a file.

  * `--cmd-port` *port*:
    Bind the remote control interface to this local port (Default: 1704).

  * `--dns-port` *port*:
    Bind the DNS server to this local port (Default: 3444).

  * `--nss-port` *port*
    Bind the "Network Service Switch" to this local port (Default: 5555).

  * `--web-port` *port*
    Bind the web server to this local port (Default: 8080).

  * `--ipv4-only, --ipv6-only`:
    Support only IPv4 or IPv6 for the DHT.

  * `-h, --help`:
    Print this help.

  * `-v, --version`:
    Print program version.

## kadnode-ctl

**kadnode-ctl** allows to control KadNode from the command line.

  * `-p` *port*:
    Connect to the local KadNode console on this interface (Default: 1704):

  * `-h`:
    Print this help.

#### KadNode Console Commands

  * `status`
    Print the node id, the number of known nodes / searches / stored hashes and more.

  * `import` <addr>
    Send a ping to another KadNode instance to establish a connection.

  * `lookup_node` <id>
    Lookup the IP address of a node that has identifier id.
	The lookup is performed on the current search results.

  * `lookup_values` <id>
    Lookup the IP addresses of all nodes that claim to satisfy the identifier.
	The lookup is performed on the current search results.

  * `search` <id>
    Start a search for nodes closest to the given identifier id.

  * `announce` <id> <port>
    Announce that this instance can satisfy the identifier id.

  * `blacklist` <addr>
    Blacklist a specifc IP address.

  * `export` [v4|v6]
    Print a few good nodes. The argument allows to select only IPv6 or IPv4 addresses.

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
