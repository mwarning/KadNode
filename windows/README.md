# Building and Packaging KadNode on Microsoft Windows

KadNode can be built for Windows systems using the [Cygwin](https://www.cygwin.com) environment.

To build KadNode on Windows you need to download and execute the Cygwin installer.
The following packages and its dependencies need to be selected:

* All => Devel  => gcc-core
* All => Devel  => make
* All => Devel  => git
* All => Python => python2
* All => Python => python3
* All => Web    => wget

If you want to use auth extension (for public/private keys), you need to install [mbedtls](https://github.com/ARMmbed/mbedtls/).

```sh
wget https://codeload.github.com/ARMmbed/mbedtls/tar.gz/v2.23.0 -O mbedtls-2.23.0.tgz
tar -xvf mbedtls-2.23.0.tgz
cd mbedtls-2.23.0
make
make install
cd ..
```
(we compile it manually to be able to link mbedtls statically)

Now download and compile KadNode:

```sh
git clone https://github.com/mwarning/KadNode.git
cd KadNode
FEATURES="bob tls dns lpd" make
```

Finally, start KadNode:

```
./build/kadnode
```


## Packaging for Windows

To create a package, [Inno Setup](https://www.jrsoftware.org/isinfo.php) is used.
Install it and open `kadnode.iss`, press 'Run' to create a `kadnode_setup.exe` file.

The package will register KadNode as a Windows service that is started on system startup.
When KadNode starts, it will change the DNS settings for each interface to a public DNS server
and localhost for KadNode to receive DNS requests.
The DNS settings will be set to automatic when KadNode shuts down.
