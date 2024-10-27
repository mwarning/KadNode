kadnode(1) - P2P name resolver daemon
=====================================

## SYNOPSIS

`kadnode`  [--announce \<domain\>] [--daemon] [...]

`kadnode-ctl`  [...]

## DESCRIPTION

**KadNode** is a small P2P DNS resolver. It supports authentication based on x509 certificates and public key queries as base32 and hexadecimal strings.

## JOIN THE SWARM

KadNode needs to know at least one active peer to join / bootstrap into the swarm.
There are three ways to achieve this:

1. Provide one or more peers to the command line arguments. These could be public BitTorrent trackers, or other KadNode instances:
```
kadnode --peer bttracker.debian.org --peer 192.168.1.1
```

2. Ping a peer using the KadNode console if present:
```
kadnode-ctl ping bttracker.debian.org
```

3. Use the local peer discovery feature. Just start KadNode and it will try to discover other KadNode nodes in the local network.


Also provide a `--peerfile` argument to let KadNode load its peerlist on startup and store on every 24h and shutdown.
This ensures successful bootstrapping on next startup.


## AUTHENTICATION

KadNode provides two authentication schemes. One works via x509 certificates and TLS. The other one uses raw secret/public keys and is hence called bob.

### Via TLS

Typically there are two KadNode instances involved.

One node announces a domain, e.g. mynode.p2p. The other node looks for the IP address of the announcing node. Authentication happens via TLS, which in turn uses X509 certificates.

```
kadnode --announce mynode.p2p --tls-server-cert mynode.crt,mynode.key
```

As an alternative, ownership can be proven using an HTTPS server running on the same host.
In this case, KadNode itself does not need certificates, but needs to announce the HTTPS port:

```
kadnode --announce mynode.p2p:443
```

The other node doing the lookup for mynode.p2p needs to have access to the root certificate that has been used to sign mynode.crt. These can be a common web browsers certificates:

```
kadnode --tls-client-cert /usr/share/ca-certificates/mozilla
```

Own certificates authorities can be created and used, of course.

Note: `--announce` is optional in many cases as domains from certificate and key files are announced automatically.

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

Any reachable node can now resolve `c492192ac20144ed2a43d57e7239f5ef5f6bb418a51600980e55ff565cc916a4.p2p` to the IP address of the announcing host. There is no need to share any additional information beforehand.

## No Authentication

KadNode also allows to just lookup a hexadecimal string and to get IP addresses as return.
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
    Default: `p2p`

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
    Print various status information. This includes DHT identifier,  
    uptime, traffic, number of searches and announcements.

  * `lookup` *query*  
    Lookup a domain, base16 or base32 string.  
    The .p2p TLD is optional.

  * `announce-start` *query*[<i>:*port*</i>]  
    Start to announce a query.

  * `announce-stop` *query*  
    Remove an announcement.

  * `announcements`  
    List all announcements.

  * `searches`  
    List all searches.

  * `bob-keys`  
    List bob keys.

  * `help`  
    Print detailed help.

Internal commands:

  * `port-forwardings`  
    List the port forwardings

  * `constants`  
    List internal constants.

DHT specific commands:

  * `dht-ping` *ip-address*[<i>:*port*</i>]  
    Ping another DHT peer. Can be used to bootstrap.

  * `dht-blocklist`  
    List blocked IP addresses.

  * `dht-peers`  
    Print IP addresses of all peers.

  * `dht-buckets`|`dht-searches`|`dht-storage`  
    Print various DHT internal data structures.

## KadNode External Console

KadNode allows a limited set of commands to be sent from any user from other consoles.

`kadnode-ctl` [-p path] [status|lookup|...]

  * `-p` *path*  
    Unix socket used to connect to the command shell of a local KadNode instance (Default: /tmp/kadnode.sock).

  * `-h`  
    Print this help.

## Name Service Switch (NSS)

Kadnode can intercept system-wide DNS lookups via NSS. This is need to be able to use kadnode links in the web browser or for command line tools like ssh. For this, `/etc/nsswitch.conf` need to be configured:

  * Copy libnss_kadnode.so.2 to /lib/. Other libnss_*.so files are likely to be there as well.
  * Edit `/etc/nsswitch.conf` to include `kadnode` in the `hosts:` line before entry `dns`:
    * `hosts: kadnode dns`

## Automatic Port Forwarding

If KadNode runs on a computer in a private network, it will try to establish a port forwarding for the DHT port and ports used for announcements.
Port forwarding only works if UPnP/NAT-PMP is compiled into KadNode (features "natpmp" and "upnp") and it is enabled by the gateway/router.
This is useful to make a local service (e.g. a web server) reachable from the Internet without the need to
configure port forwardings manually.

## LICENSE

  MIT/X11
