##Compilation on Windows

KadNode can be build for Window systems using the [Cygwin](http://www.cygwin.com/) environment.
These instruction do not include packaging. That's work in progress for now.

To build KadNode on Windows you need to download an execute the Cygwin installer.
The following packages and its dependencies need to be selected:

* All => Devel => gcc-core
* All => Devel => make
* All => Devel => git
* All => Devel => wget

If you want to use auth extension (for public/private keys),
you need to download and install [libsodium](https://github.com/jedisct1/libsodium).
Open the Cygwin terminal and execute:

```
wget https://github.com/jedisct1/libsodium/releases/download/1.0.0/libsodium-1.0.0.tar.gz
tar -xvzf libsodium-1.0.0.tar.gz
cd libsodium-1.0.0
./configure
make
make install
cd ..
```

Now download and compile KadNode:

```
git clone https://github.com/mwarning/KadNode.git
cd KadNode
FEATURES="auth cmd dns lpd" make
```

Finally, start KadNode:

```
./build/kadnode
```

## Packaging for Windows

To create a package, [Inno Setup](http://www.jrsoftware.org/isinfo.php) is used.
Install it and open kadnode.iss, press 'Run' to create a kadnode_setup.exe file.

The package will register KadNode as a Windows service that is started on system startup.
When KadNode starts, it will change the DNS settings for each interface to a public DNS server
and localhost for KadNode to receive DNS requests.
The DNS settings will be set to automatic when KadNode shuts down.
