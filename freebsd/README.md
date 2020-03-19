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

Create a source tarball of the current repository:

```
git archive HEAD --prefix kadnode-head/ -o freebsd/kadnode-head.tar.gz
```

Edit `freebsd/Makefile` to build package locally:
```
# Comment out:
#USE_GITHUB=   yes

# Add:
DISTDIR=       ${PWD}
DISTNAME= kadnode-head
```

To create a [FreeBSD](https://www.freebsd.org) package (.txz file) execute:

```

cd freebsd
make clean
make makesum
make package
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

## Update FreeBSD Ports

Checkout the Ports repository:

```
svn checkout https://svn.FreeBSD.org/ports/head ports
```

Apply changes to `ports/dns/kadnode` and create a patch to submit:

```
cd ports/dns/kadnode
svn diff > ../`make -VPKGNAME`.diff
```
