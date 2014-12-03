To inlcude KadNode into your OpenWRT image or to create
an .ipk package (equivalent to Debians .deb files),
you have to build an OpenWRT image.
These steps were tested using OpenWRT-"Attitude Adjustment":

For building OpenWrt on Debian, you need to install these packages:
<pre>
apt-get install git subversion g++ libncurses5-dev gawk zlib1g-dev build-essential
</pre>

Now build OpenWrt:
<pre>
git clone git://git.openwrt.org/14.07/openwrt.git
cd openwrt

./scripts/feeds update -a
./scripts/feeds install -a

git clone https://github.com/mwarning/KadNode.git
cp -rf KadNode/openwrt/kadnode package/
rm -rf KadNode/

#Satisfy dependency in case authentication support is selected
git clone https://github.com/mwarning/libsodium-openwrt.git
cp -r libsodium-openwrt/libsodium package/
rm -rf libsodium-openwrt

make defconfig
make menuconfig
</pre>

At this point select the appropiate "Target System" and "Target Profile"
depending on what target chipset/router you want to build for.
Also mark the KadNode package under "Network" => "IP Addresses and Names".

Now compile/build everything:

<pre>
make
</pre>

The images and all *.ipk packages are now inside the bin/ folder.
You can install the kadnode .ipk using "opkg install &lt;ipkg-file&gt;" on the router.

For details please check the OpenWRT documentation.

### Note for developers

## Build Notes

You might want to use your own source location and not the remote respository.
To do this you need to checkout the repository yourself and commit your changes locally:

<pre>
git clone https://github.com/mwarning/KadNode.git
cd KadNode
... apply your changes
git commit -am "my change"
</pre>

Now create a symbolic link in the kadnode package folder using the abolute path:

<pre>
ln -s /my/own/project/folder/KadNode/.git openwrt/package/kadnode/git-src
</pre>

Also make sure to enable

<pre>
"Advanced configuration options" => "Enable package source tree override"
</pre>

in the menu when you do `make menuconfig` and use the "git add" command
to add your local changes. Then build the entire image or just the KadNode package:

<pre>
make package/kadnode/{clean,compile} V=s
</pre>

## Configuration Notes

The OpenWrt package enables CMD and DNS support. Name Service Switch (NSS)
is not available on OpenWrt.

To use the DNS interface you can hook up KadNode with the dnsmasq DNS server:

<pre>
uci add_list dhcp.@dnsmasq[0].server='/p2p/localhost#5353'
uci commit dhcp
</pre>

This configures dnsmasq to forward the domain *p2p* (as for myname.p2p)
to KadNode to be resolved.
