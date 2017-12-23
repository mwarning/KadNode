# Packaging KadNode on FreeBSD

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

To create a [FreeBSD](https://www.freebsd.org) package (.txz file) execute:

```
git archive master --prefix kadnode/ -o freebsd/kadnode-2.0.2.tar.gz
cd freebsd
make makesum
make package
```

The package can be found in freebsd/work/pkg/.

Package installation:
```
pkg add kadnode-*.txz
```
