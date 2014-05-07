#!/bin/sh

VERSION="0.9"

#go to the projects root folder
cd ..

make clean
make FEATURES="auth cmd dns"
make strip

mkdir -p build/osx-root/private/etc/kadnode/
mkdir -p build/osx-root/usr/bin/
mkdir -p build/osx-root/Library/LaunchDaemons/
mkdir -p build/osx-root/usr/share/man/man1/

install -m 755 build/kadnode build/osx-root/usr/bin/
install -m 755 build/kadnode-ctl build/osx-root/usr/bin/
install -m 644 debian/kadnode.conf build/osx-root/private/etc/kadnode/
install -m 644 debian/peers.txt build/osx-root/private/etc/kadnode/
install -m 644 debian/docs/kadnode.1 build/osx-root/usr/share/man/man1/
install -m 755 macosx/p2p.kadnode.plist build/osx-root/Library/LaunchDaemons/

mkdir -p build/pkg1

pkgbuild --root build/osx-root --identifier p2p.kadnode.daemon --version $VERSION --ownership recommended --scripts macosx/scripts build/pkg1/output.pkg
productbuild --distribution macosx/distribution.xml --resources macosx/resources --package-path build/pkg1 --version $VERSION kadnode_$VERSION.pkg
