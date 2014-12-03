To create a Debian package of KadNode (a *.deb file),
you first need to have installed the following programs and libraries:

<pre>
apt-get install build-essential debhelper hardening-includes
apt-get install libnatpmp-dev libminiupnpc-dev libsodium-dev
</pre>

Run this command in the repository root folder to create the package:

<pre>
dpkg-buildpackage
</pre>

The package will be created in the parent directory.


Use this command if you want to create an unsigned package:

<pre>
dpkg-buildpackage -us -uc
</pre>
