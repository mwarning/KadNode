# Usage examples

## Use KadNode with Let's Encrypt certificates

You might want to use KadNode with certificates from [Let's Encrypt](https://letsencrypt.org/).
In this example we assume to have certificates for `mydomain.com`.

A server running KadNode will be provided with the certificates for `mydomain.com` and will announce it to the P2P network.

When someone else enters `mydomain.com.p2p` in the browser,
then a running KadNode instance will intercept that request and look up the IP address.
KadNode use the hosts CA chain (e.g. those of the browser) to verify the certificate behind the IP address.
If the verification is successful, the browser will receive the IP address and can load the web page.

Server configuration:
```sh
./build/kadnode --tls-server-cert /etc/letsencrypt/live/mydomain.com/fullchain.pem,/etc/letsencrypt/live/mydomain.com/privkey.pem
```

Client configuration:
```sh
./build/kadnode --tls-client-cert /usr/share/ca-certificates/mozilla/
```

Now you should be able to do `ping mydomain.com.p2p`.
The `.p2p` extension causes it do be resolved via KadNode.
Since the default BitTorrent network is huge, it may take a few tries / a few seconds to resolve.


## Use existing HTTPS server for authentication

Instead of KadNode, an HTTPS server (e.g. Apache, Nginx) on the same host can provide the authentication.
In this case KadNode only does the announcements:

Server configuration:
```sh
./build/kadnode --announce mydomain.com:443
```

> [!NOTE]
> You cannot announce a domain for a different peer.
> Peers take the IP address of a domain from the sender of the announcement.


## Create your own Certificate Authority and Certificates

You can use a [script](create-cert.sh) to create your own root certificates:

```sh
./misc/create-cert.sh mydomain.com
```

This will create the following files:

| File               | Description                        |
|--------------------|------------------------------------|
| `rootCA.key`       | Private key for root certificate   |
| `rootCA.pem`       | Self signed root certificate       |
| `mydomain.com.key` | Private key                        |
| `mydomain.com.pem` | Public key                         |
| `mydomain.com.crt` | Certificate signed by `rootCA.key` |

Server configuration:
```sh
./build/kadnode --tls-server-cert mydomain.com.crt,mydomain.com.key
```

Client configuration:
```sh
./build/kadnode --tls-client-cert rootCA.pem
```

> [!NOTE]
> `rootCA.key` can be reused to sign several other certificates for other domains.


## Use a raw public key

A base64 encoded public key is a simple way to find a nodes IP address without any certificates.
First, a key pair needs to be created:

```
kadnode --bob-create-key secret.pem
Generating secp256r1 key pair...
Public key: 6qjky0k1n1gzymsywn4hwd37pzgntr0b2q9r20veen8be3xz6dvg.p2p
Wrote secret key to secret.pem
```

The node we want to find on the network needs the secret key file:

```sh
kadnode --bob-load-key secret.pem
```

On another node, assuming KadNode runs in the background, the public key can be used to find the node.

```sh
ping 6qjky0k1n1gzymsywn4hwd37pzgntr0b2q9r20veen8be3xz6dvg.p2p
```

You can also use the domain in your browser or any other program.

KadNode also has an optional console tool to do lookups:

```sh
kadnode-ctl lookup 6qjky0k1n1gzymsywn4hwd37pzgntr0b2q9r20veen8be3xz6dvg
```

> [!NOTE]
> The first lookup will initiate the search.
> Only subsequent lookups can be expected to return a result.


## Lookup using a key string

KadNode can do simple lookups on the DHT, without any authentication/crypto.
Any key in base16 or base32 that represents a DHT hash (20 Bytes) is used for simple DHT lookups.
