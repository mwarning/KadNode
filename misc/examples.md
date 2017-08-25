# Use KadNode with Let's Encrypt certificates


You might want to use KadNode with certificates from Let's Encrypt. In this example we assume to have certificates for mydomain.com.

A server running KadNode will be provided with the certificates for mydomain.com and will announce it to the P2P network.

When someone enters mydomain.com.p2p in the browser, then KadNode will intercept that request and look up the IP address. KadNode use the hosts CA chain (e.g. those of the browser) to verifiy the certificate behind the IP address.
Ìf the verification is successful, the browser will receive the IP address.

Server configuration:
```  
./build/kadnode --tls-server-cert cert.pem,privkey.pem
```

Client configuration:
```  
./build/kadnode --tls-client-cert chain.pem
```
Note: You can also add a whole folder of CA root certificates.

# Use HTTPS server for server authentication

Instead of KadNode, a HTTPS server (e.g. apache, nginx) on the same host can provide the authentication. In this case KadNode only does the announcements:

Server configuration:
```  
./build/kadnode --announce mydomain.com:443
```

Other 

# Create your own Certificate Authority and Certificates

You can use a script to create your own root certifactes:

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
