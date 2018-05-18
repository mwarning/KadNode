#!/bin/sh

VERSION="2.2.1"

#go to the projects root folder
cd ..

make clean
make FEATURES="bob tls lpd dns"
make strip

mkdir -p build/osx-root/private/etc/kadnode/
mkdir -p build/osx-root/usr/bin/
mkdir -p build/osx-root/Library/LaunchDaemons/
mkdir -p build/osx-root/usr/share/man/man1/

install -m 755 build/kadnode build/osx-root/usr/bin/
#install -m 755 build/kadnode-ctl build/osx-root/usr/bin/
install -m 644 misc/kadnode.conf build/osx-root/private/etc/kadnode/
install -m 644 misc/peers.txt build/osx-root/private/etc/kadnode/
install -m 644 misc/kadnode.1 build/osx-root/usr/share/man/man1/
install -m 755 macos/p2p.kadnode.plist build/osx-root/Library/LaunchDaemons/

mkdir -p build/pkg1

pkgbuild --root build/osx-root --identifier p2p.kadnode.daemon --version $VERSION --ownership recommended --scripts macos/scripts build/pkg1/output.pkg
productbuild --distribution macos/distribution.xml --resources macos/resources --package-path build/pkg1 --version $VERSION kadnode_$VERSION.pkg
