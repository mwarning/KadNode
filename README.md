kadnode(1) -- P2P name resolution daemon
=======================================

## SYNOPSIS

`kadnode`  [--id hostname] [--port port] [--daemon] [...]

`kadnode-ctl`  [...]

## DESCRIPTION

**KadNode** is a small P2P name resolution daemon for IPv4 and IPv6 based on the Kademlia
implementation of a distributed hash table (DHT) for Posix systems (e.g. GNU/Linux).
By default, KadNode tries to send pings to a multicast address on the local network
to find nodes to bootstrap from. This is done as long no other nodes are known.
An interactive remote shell called `kadnode-ctl` let the user import and export nodes, issues queries for
hash identifiers and send announcements.

As an usage example one would call `kadnode --id myname.p2p` and call `kadnode-ctl import some-dht-tracker.com:4242`
to help KadNode to bootstrap into the network.
These imported node can also be the ones being exported last time before KadNode has been shut down.
On another computer that runs KadNode and that is connected to any nodes of the same network,
myname.p2p can be entered in the browser and will now resolve to the ip address of the computer the first
other KadNode instance is running.
The domain name query is passed from the browser to the operating system to the NSS interface of KadNode.

Identifiers can be entered as a string like `myname.p2p`. KadNode will ignore the top level domain
(.p2p in this case) and apply sha1 hashing to the rest.
As an alternative, the hash can be used directly as a 40 character hex string.
The domain `myname.p2p` is therefore eqivalent to `fd0bef09a735b3cef767fb2c62b6bd365346bee5`
which is the result of sha1('myname'). This is true for every query using KadNode.

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

**kadnode-ctl** allows to control a running KadNode instance from the console or scripts.

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

## NOTES

  * Kademlia drops announcements after 30 minutes. Those need to be refreshed.
  * Blacklisted addreses are stored in a LRU cache of maximal 10 entries.

## LIMITATIONS / BUGS

  * KadNode cannot resolve its own node id without other nodes present.
  * No NAT-traversal was implemented yet.

## LICENSE

  MIT/X11

## AUTHORS

  * KadNode: Moritz Warning (http://github.com/mwarning)
  * Kademlia: Juliusz Chroboczek
  * SHA1: Steve Reid
