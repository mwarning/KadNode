To create an Archlinux package of KadNode (a *.pkg.tar.xz file).

Run these commands in the repository root folder to create the package:

<pre>
cd archlinux
makepkg
</pre>

The package kadnode-git-*.pkg.tar.xz will be created.

To install the package, use:

<pre>
pacman -U kadnode-git-*.pkg.tar.xz 
</pre>

To remove the package, use:

<pre>
pacman -R kadnode-git
</pre>
