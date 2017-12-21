## FAQ
* **What is KadNode?**  
    In short, KadNode is the Transmissions DHT with interfaces and packaging.  
    Slightly longer; KadNode is a tool that resolves names to IP addresses using the BitTorrent DHT network.
    KadNode runs in background and intercepts and answers name request for the .p2p domain.
    It has a very low resource consumption. The main task is to just return IP addresses for identifiers, not necessarly traditional DNS.
* **Is the .p2p TLS mandatory?**  
    No, it is only used to intercept requests and then stripped for the entire lookup process.
* **How does KadNode intercept DNS reqests?**  
    On some systems the Name Service Switch (NSS) support (see /etc/nsswitch.conf) is used. For other systems KadNode includes a basic DNS server that listens on the local host (Supported are A, AAAA and SRV requests - to transmit the port). It can also act as a simple DNS proxy.
* **Can annoucements be made for other nodes? Can I announce the IP address of e.g. google.de?**  
    No, the IP address of the sender of an announcement is used. This can be seen as a pro and cons.
* **How long does it take to resolve an address?**  
    An estimate would be 8 seconds. Unless the address has been cached.
* **So, it's all about DNS?**  
    No, KadNode is not traditional DNS. It just maps and 20 byte identifiers (or sha1(some-string)) to IP addresses. Everybody can announce identifiers. Use verification like HTTPS or other cryptography mechanisms.
* **Are wildcard certificates supported?**  
    Yes, but all used domains have to be given explicitly via --announce. Wildcard support has not been tested yet.
* **Can KadNode be used as a DNS server?**  
    KadNode is not a DNS server, it does not forward domains and its copabilities are quite simplistic.  
    It is meant to be an interface to a real DNS-Server (bind, dnsmasq etc.)
* **How much traffic does KadNode generate?**  
    See this small [Benchmark](https://github.com/mwarning/KadNode/wiki/traffic-consumption).
* **Does KadNode offer authentication/verification?**  
    Yes, KadNode has an extension (called 'auth') to create a public/secret key pair and to lookup nodes
using the public key as you would use a domain name. The resolved IP addresses are those of nodes that have the corresponding secret key. Keep in mind that this approach is not very secure!
* **How are public keys distributed?**  
    This is not in the scope of KadNode. So it is your task to enter the keys into the configuration files. KadNode does not intend to solve the task of key distribution.
* **Is the authentication/verification secure?**  
    No. The current mechanism is vulnerable to man-in-the-middle attacks!
* **How to compile KadNode without UPNP, NAT-PMP or authentication (mbedtls) support?**  
    Edit the FEATURES variable in Makefile and remove 'upnp', 'natpmp' or 'bob' and 'tls'. You can check the binary using `kadnode -v`.
* **Local Peer Discover (LPD) does not work on bridged devices..**  
    Try to disable the multicast_snooping or multicast_querier option, this is needed for OpenWrt: echo 0 > /sys/devices/virtual/net/br-lan/bridge/multicast_snooping
* **How does the authentication work?**  
    Please consult the [Authentication Details](https://github.com/mwarning/KadNode/wiki/Cryptography-Details).
* **What about Namecoin and others?**  
    Namecoin tries to imitate traditional DNS where a domain is globally unique. KadNode merely maps identifiers to IP addresses without more thought. The authentication extension for KadNode is more of an experiment for a more specific application.
* **Lookup is slow? What is going on?**  
    KadNode may need a few seconds to resolve an identifier. If it takes considerably longer than 10 seconds, then your node might no properly bootstrapped. Let me now if you have reason to assume otherwise. There has been added a [branch](/mwarning/KadNode/commits/big_buckets) for speed enhancements.
* **What are the compile dependencies?**  
    When you try to compile KadNode, then you need to have [mbedtls](https://github.com/ARMmbed/mbedtls/) installed.
* **Why use the secp256r1 elliptic curve instead of ed25519?**  
    ed25519 would be preferable, but mbedtls does not support ed25519 yet.
* **Why do not use the nodes ID to find a node? They do not need to be announced in comparison to value IDs ?**  
    Value IDs might not be free to choose in the future as some BitTorrent security features propose. You can also have only one.
* **When are peers exported?**  
    When a peer file is given (--peerfile), good peers are written to it every 24 hours and on proper shutdown (but only after at least 5min runtime).
* **Where does the name *KadNode* come from?**  
    It is a short form Kademlia Node; Kademlia is the name of the DHT design used for BitTorrent.
* **Multicast Discovery does not seem to work.** 
    If there is no error message, then the multicast packet might leave the computer on the wrong network port.  
    The peer discovery packets follow the default network route that probably points to the Internet.  
    This behavior can be changed for IPv4 with this command (route through eth0):  
    `route add -net 224.0.0.0 netmask 240.0.0.0 eth0`
