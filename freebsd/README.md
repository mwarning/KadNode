## How to create FreeBSD a KadNode package

Install mbedtls and gmake:

```
pkg update
pkg install mbedtls
pkg install gmake
```

To create a FreeBSD package (.txz file) execute:

```
cd freebsd
gmake package
```

The package can be found in kadnode/freebsd/work/pkg/.
