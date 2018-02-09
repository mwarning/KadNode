# Examples

## Use KadNode with Let's Encrypt certificates

You might want to use KadNode with certificates from [Let's Encrypt](https://letsencrypt.org/). In this example we assume to have certificates for mydomain.com.

A server running KadNode will be provided with the certificates for mydomain.com and will announce it to the P2P network.

When someone else enters mydomain.com.p2p in the browser, then a running KadNode instance will intercept that request and look up the IP address. KadNode use the hosts CA chain (e.g. those of the browser) to verifiy the certificate behind the IP address. If the verification is successful, the browser will receive the IP address and can load the web page.

Server configuration:
```  
./build/kadnode --tls-server-cert /etc/letsencrypt/live/mydomain.com/fullchain.pem,/etc/letsencrypt/live/mydomain.com/privkey.pem
```

Client configuration:
```  
./build/kadnode --tls-client-cert /usr/share/ca-certificates/mozilla/
```

## Use existing HTTPS server for authentication

Instead of KadNode, a HTTPS server (e.g. apache, nginx) on the same host can provide the authentication. In this case KadNode only does the announcements:

Server configuration:
```  
./build/kadnode --announce mydomain.com:443
```

Note: You cannot announce a domain for a different peer. Peers take the IP address of a domain from the sender of the announcement.

## Create your own Certificate Authority and Certificates

You can use a [script](create-cert.sh) to create your own root certifactes:

```
./misc/create-cert.sh mydomain.com
```

This will create the following files:

File             | Description
-----------------|---------------------------------
rootCA.key       | Private key for root certificate
rootCA.pem       | Self signed root certificate
mydomain.com.key | Private key
mydomain.com.pem | Public key
mydomain.com.crt | Certificate signed by rootCA.key

Server configuration:
```
./build/kadnode --tls-server-cert mydomain.com.crt,mydomain.com.key
```

Client configuration:
```  
./build/kadnode --tls-client-cert rootCA.pem
```

Note: rootCA.key can be reused to sign several other certificates for other domains.

## Use a public hexadecimal key

A hexadecimal key is a simple way to find a nodes IP address without any certificates.
First, a key pair needs to be created:

```
kadnode --bob-create-key secret.pem
Generating secp256r1 key pair...
Public key: ob73a4ltgfio35mqh5hcj1b09gpcse9pjlk6m09m57dl45sqksdg.p2p
Wrote secret key to secret.pem
```

The node we want to find on the network needs the secret key file:

```
kadnode --bob-load-key secret.pem
```

On another node, assuming KadNode runs in the background, the public key can be used to find the node.

```
ping ob73a4ltgfio35mqh5hcj1b09gpcse9pjlk6m09m57dl45sqksdg.p2p
```

You can also use the domain in your browser or any other program.

KadNode also has an optional console tool to do lookups:

```
kadnode-ctl lookup ob73a4ltgfio35mqh5hcj1b09gpcse9pjlk6m09m57dl45sqksdg
```

Note: The first lookup will initiate the search. Only subsequent lookups can be expected to return a result.

## Lookup using a hexadecimal string

KadNode can do simple lookups on the DHT, without any authentication/crypto. Any hexadecimal string that is not 32 Byte (64 characters) will be cut or padded to the native size of the DHT hash (20 Bytes) and used for lookups.
