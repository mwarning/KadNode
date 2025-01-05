# Building and Packaging KadNode on OpenWrt

To inlcude KadNode into your [OpenWrt](https://openwrt.org) image or to create an .ipk package (equivalent to Debian Linux .deb files), you have to build a firmware image.
These steps were tested using OpenWrt:

For building OpenWrt on Debian Linux, you need to install these packages:
```
apt install git subversion g++ libncurses5-dev gawk zlib1g-dev build-essential
```

Now build OpenWrt:
```
git clone https://github.com/openwrt/openwrt
cd openwrt

./scripts/feeds update -a
./scripts/feeds install -a

git clone https://github.com/mwarning/KadNode.git
cp -rf KadNode/openwrt/kadnode package/
rm -rf KadNode/

make menuconfig
```

At this point select the appropiate "Target System" and "Target Profile"
depending on what target chipset/router you want to build for.
Also mark the KadNode package under "Network" => "IP Addresses and Names".

Now compile/build everything:

```
make
```

The images and all \*.apk or \*.ipk packages are now inside the bin/ folder.
You can install the kadnode package using `opkg install <kadnode-ipkg>` or `pkg add <kadnode-apk>` on the router.

For details please check the OpenWrt documentation.

## Build Notes

You might want to use your own source location and not the remote respository.
To do this you need to checkout the repository yourself and commit your changes locally:

```
git clone https://github.com/mwarning/KadNode.git
cd KadNode
... apply your changes
git commit -am "my change"
```

Now create a symbolic link in the kadnode package folder using the abolute path:

```
ln -s /my/own/project/folder/KadNode/.git openwrt/package/kadnode/git-src
```

Also make sure to enable

```
"Advanced configuration options (for developers)" => "Enable package source tree override"
```

In the menu when you do `make menuconfig` and use the "git add" command
to add your local changes. Then build the entire image or just the KadNode package:

```
make package/kadnode/{clean,compile} V=s
```

## Configuration Notes

The OpenWrt package enables CMD and DNS support. Name Service Switch (NSS) support is not available on OpenWrt.

To use the DNS interface you can hook up KadNode with the dnsmasq DNS server:

```
uci add_list dhcp.@dnsmasq[0].server='/p2p/::1#3535'
uci commit dhcp
```

This configures dnsmasq to forward the domain *p2p* (as for myname.p2p)
to KadNode to be resolved.
