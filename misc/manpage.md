kadnode(1) - P2P name resolver daemon
====================================

## SYNOPSIS

`kadnode`  [--announce \<domain\>] [--daemon] [...]

`kadnode-ctl`  [...]

## DESCRIPTION

**KadNode** is a small P2P DNS resolver. It supports authentication based on x509 certificates and hexadecimal public key queries.

## JOIN THE SWARM

KadNode needs to know at least one active peer to join / bootstrap into the swarm.
There are three ways to archieve this:

1. Provide one or more peers to the command line arguments. These could be public BitTorrent trackers, or other KadNode instances:
```
kadnode --peer bttracker.debian.org --peer 192.168.1.1
```

2. Ping a node using the KadNode console if present:
```
kadnode-ctl ping bttracker.debian.org
```

3. Use the local peer discovery feature. Just start KadNode and it will try to discover other KadNode nodes in the local network.


Also provide a --peerfile argument to let KadNode backup its peerlist on shutdown and every 24h.
This ensures successful bootstrapping on next startup.


## AUTHENTICATION

KadNode provides two authentication schemes. One works via x509 certificates and TLS. The other one uses raw secret/public keys and is hence called bob.

### Via TLS

Typically there are two KadNode instances involved.

One node announces a domain, e.g. mynode.p2p. The other node looks for the IP address of the announcing node. Authentication happens via TLS, which in turn uses X509 certificates.

```
kadnode --announce mynode.p2p --tls-server-cert mynode.crt,mynode.key
```

As an alternative, ownerhip can be proven using a HTTPS server running on the same host.
In this case, KadNode itself does not need certificates, but needs to announce the HTTPS port:

```
kadnode --announce mynode.p2p:443
```

The other node doing the lookup for mynode.p2p needs to have access to the root certificate that has been used to sign mynode.crt. These can be a common web browsers certificates:

```
kadnode --tls-client-cert /usr/share/ca-certificates/mozilla
```

Own certificates authorities can be created and used, of course.

Note: --announce is optional in many cases as domains from certificate and key files are announced automatically.

### Via BOB

First create an elliptic curve secret key file:

```
kadnode --bob-create-key mysecretkey.pem
Generating secp256r1 key pair...
Public key: c492192ac20144ed2a43d57e7239f5ef5f6bb418a51600980e55ff565cc916a4
Wrote secret key to mysecretkey.pem
```

Now make the secret key load on KadNode startup:
```
kadnode --bob-load-key mysecretkey.pem
```

Any reachable node can now resolve c492192ac20144ed2a43d57e7239f5ef5f6bb418a51600980e55ff565cc916a4.p2p to the IP address of the announcing host. There is no need to share any more information beforehand.

## No Authentication

KadNode also allows one to just lookup a hexdecimal string and to get IP addresses as return.
This is the plain use of the DHT. The hexadecimal string will be cut down or filled up with zeros internally to fit the size the DHT uses (currently 20 bytes).

## OPTIONS

  * `--announce` *domain[:port]*  
    Announce a domain and an optional port via the DHT.  
    This option may occur multiple times.

  * `--peerfile` *file*  
    Import peers for bootstrapping and write good peers  
    to this file every 24 hours and on shutdown.

  * `--user` *name*  
    Change the UUID after start.

  * `--port` *port*  
    Bind the DHT to this port.  
    Default: `6881`

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
    Top level domain used to filter queries to be resolved by KadNode.  
    Set to empty string to match all.  
    Default: `.p2p`

  * `--verbosity` *level*  
    Verbosity level quiet, verbose or debug.  
    Default: `verbose`

  * `--pidfile` *file-path*  
    Write process pid to a file.

  * `--lpd-disable`  
    Disable Local Peer Discovery (LPD).

  * `--cmd-disable-stdin`  
    Disable the local control interface.

  * `--cmd-path` *path*  
    Bind the remote control interface to a unix socket.  
    Default: `/tmp/kadnode/kadnode_cmd.sock`

  * `--dns-port` *port*  
    Bind the DNS server interface to this local port.  
    Default: `3535`

  * `--dns-server` *address*  
    IP address of an external DNS server. Enables DNS proxy mode.  
    Default: disabled

  * `--dns-proxy-enable`  
    Enable DNS proxy mode. Uses /etc/resolv.conf by default.

  * `--dns-proxy-server` *ip-address*  
    Use IP address of an external DNS server instead of /etc/resolv.conf.

  * `--nss-path` *path*  
    Bind the "Name Service Switch" to a unix socket.  
    Default: `/tmp/kadnode/kadnode_nss.sock`

  * `--tls-client-cert` *path*  
    Path to file or folder of CA root certificates.  
    This option may occur multiple times.

  * `--tls-server-cert` *path*,*path*  
    Add a comma separated server certificate file path and key file path.  
    This option may occur multiple times.  
    Example: `kadnode.crt,kadnode.key`

  * `--bob-create-key` *file*  
    Write a new secp256r1 secret key in PEM format to the file.  
    The public key will be printed to the terminal before exit.

  * `--bob-load-key` *file*  
    Read a secret key in PEM format and announce the public key.  
    This option may occur multiple times.

  * `--ipv4, -4, --ipv6, -6`  
    Enable IPv4 or IPv6 only mode for the DHT.  
    Default: IPv4+IPv6

  * `-h`, `--help`  
    Print the list of accepted options.

  * `-v`, `--version`  
    Print program version and included features.

### KadNode Console Commands

When not started in background, KadNode accepts a variety of commands from standard input.

  * `status`  
    Print the node id, the number of known nodes / searches / stored hashes and more.

  * `lookup` *domain*  
    Lookup the IP addresses of all nodes that claim to satisfy the domain.  
    The first call will start the search.

  * `announce` [*domain*[<i>:*port*</i>] [<i>*minutes*</i>]]  
    Announce that this instance is associated with a domain  
    and an optional port. The default port is random (but not equal 0).  
    A missing *minutes* argument trigger a single announcement. Negative *minutes*  
    last for the entire runtime. Otherwise the lifetime is set *minutes* into the future.  
    No arguments will announce all identifiers at once.

  * `import` *addr*  
    Send a ping to another KadNode instance to establish a connection.

  * `export`  
    Print a few good nodes.

  * `list` [`blacklist`|`buckets`|`constants`|`forwardings`|`results`|`searches`|`storage`|`values`]  
    List various internal data structures.

  * `blacklist` *addr*  
    Blacklist a specific IP address.

## KadNode External Console

KadNode allows a limited set of commands to be send from any user from other consoles.

`kadnode-ctl` [-p path] [status|lookup|announce|import|export|blacklist]

  * `-p` *path*  
    Unix socket used to connect to the command shell of a local KadNode instance (Default: /tmp/kadnode.sock).

  * `-h`  
    Print this help.

## Name Service Switch (NSS)

Kadnode can intercept system wide DNS lookups via NSS. This is need to be able to use kadnode links in the web browser or for command line tools like ssh. For this, `/etc/nsswitch.conf` need to be configured:

  * Copy libnss_kadnode.so.2 to /lib/. Other libnss_*.so files are likely to be there as well.
  * Edit `/etc/nsswitch.conf` to include `kadnode` in the `hosts:` line before entry `dns`:
    * `hosts: kadnode dns`

## Automatic Port Forwarding

If KadNode runs on a computer in a private network, it will try to establish a port forwarding for the DHT port and ports used for announcements.
Port forwarding only works if UPnP/NAT-PMP is compiled into KadNode and is supported by the gateway/router.
This is useful to make a local service (e.g. a web server) reachable from the Internet without the need to
configure port forwardings manually.

## LICENSE

  MIT/X11
