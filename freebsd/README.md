## How to create FreeBSD a KadNode package

Install gmake, git and mbedtls:

```
pkg update
pkg install gmake
pkg install git
pkg install mbedtls
```

Make sure /usr/ports is populated:

```
portsnap fetch extract
```

To create a FreeBSD package (.txz file) execute:

```
git archive master --prefix kadnode/ -o freebsd/kadnode.tar.gz
cd freebsd
make makesum
make
```

The package can be found in freebsd/work/pkg/.
