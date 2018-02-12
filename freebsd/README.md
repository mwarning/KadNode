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
gmake freebsd-pkg
```

The package can be found in freebsd/work/pkg/.

Package installation:
```
pkg add kadnode-*.txz
```

Start kadnode:
```
service kadnode start
```
