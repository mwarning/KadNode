KadNode can be build for Window systems using the [Cygwin](http://www.cygwin.com/) environment.

To build KadNode on Windows you need to download an execute the Cygwin installer.
The following packages and its dependencies need to be selected:

* All => Devel => gcc-core
* All => Devel => make
* All => Devel => git
* All => Devel => wget

Now start the Cygwin Terminal and install [libsodium](https://github.com/jedisct1/libsodium).
This step is only needed for the auth extension.

```
wget https://github.com/jedisct1/libsodium/releases/download/0.5.0/libsodium-0.5.0.tar.gz
tar -xvzf libsodium-0.5.0.tar.gz
cd libsodium-0.5.0
./configure
make
make install
cd ..
```

Now download and compile KadNode:

```
git clone https://github.com/mwarning/KadNode.git
cd KadNode
FEATURES="auth cmd dns " make
```

Finally, start KadNode:

```
./build/kadnode
```

Note:
* You need the file cygwin1.dll for running KadNode on systems without Cygwin.
* Cygwin does not support KadNodes Local Peer Discovery right now.
