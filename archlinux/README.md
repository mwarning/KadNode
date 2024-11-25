# Packaging KadNode on Arch Linux

To create an [Archlinux](https://www.archlinux.org) package of KadNode (a \*.pkg.tar.xz file).

Install dependencies:

```
sudo pacman -S gcc make fakeroot debugedit miniupnpc libnpupnp
```

Run these commands in the repository root folder to create the package:

```
cd archlinux
makepkg
```

The package `kadnode-git-*.pkg.tar.zst` will be created.

To install the package, use:

```
pacman -U kadnode-*.pkg.tar.zst
```

Now you can start Kadnode:

```
systemctl start kadnode
```

Or stop:
```
systemctl stop kadnode
```

To remove the package, use:

```
pacman -R kadnode
```
