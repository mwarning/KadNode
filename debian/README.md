# Packaging KadNode on Debian Linux

To create a [Debian](https://www.debian.org) package of KadNode (a \*.deb file),
you first need to have installed the following programs and libraries:

```
apt install build-essential debhelper devscripts
apt install libmbedtls-dev libnatpmp-dev libminiupnpc-dev
```

Run this command in the repository root folder to create the package:

```
dpkg-buildpackage
```

The package will be created in the parent directory.


Use this command if you want to create an unsigned package:

```
dpkg-buildpackage -b -rfakeroot -us -uc
```

The .deb package can be found beneath the kadnode source folder.

Install the debian package:

```
dpkg -i kadnode_*.deb
```

# lintian

To check the package for errors and warnings, use lintian.

Install/Configuration:
```
sudo apt install lintian
echo -e "display-info=y\ndisplay-experimental=y\npedantic=y\ncolor=auto" > ~/.config/lintian/lintianrc
```

Usage:
```
lintian kadnode_*.deb
```
