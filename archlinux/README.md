# Packaging KadNode on Arch Linux

To create an [Archlinux](https://www.archlinux.org) package of KadNode (a \*.pkg.tar.xz file).

Run these commands in the repository root folder to create the package:

```
cd archlinux
makepkg
```

The package kadnode-git-\*.pkg.tar.xz will be created.

To install the package, use:

```
pacman -U kadnode-*.pkg.tar.xz 
```

To remove the package, use:

```
pacman -R kadnode
```
