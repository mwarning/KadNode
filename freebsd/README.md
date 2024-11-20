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
git clone https://git.freebsd.org/ports.git /usr/ports
```

Create a source tarball of the KadNode repository:

```
cd kadnode
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

Package installation:
```
pkg add work/pkg/kadnode-*.pkg
```

Start kadnode:
```
service kadnode start
```

## Update FreeBSD Ports

Checkout the Ports repository:

```
git clone https://git.freebsd.org/ports.git ports
```

Apply changes to `ports/dns/kadnode` and create a patch to submit:

```
cd ports/dns/kadnode
git diff > ../`make -VPKGNAME`.diff
```

List all files that the package has installed:
```
pkg info --list-files kadnode
```
