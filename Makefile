
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wwrite-strings -pedantic
CFLAGS += -std=gnu99
POST_LINKING =
FEATURES ?= auth cmd nss natpmp upnp #dns debug web

OBJS = build/main.o build/results.o build/kad.o build/log.o \
	build/conf.o build/sha1.o build/unix.o build/net.o build/utils.o \
	build/values.o build/bootstrap.o

.PHONY: all clean strip install kadnode kadnode-ctl libnss_kadnode.so.2 \
	arch-pkg deb-pkg osx-pkg install uninstall

all: kadnode

ifeq ($(findstring auth,$(FEATURES)),auth)
  OBJS += build/ext-auth.o
  CFLAGS += -DAUTH
#  POST_LINKING += -lsodium
  POST_LINKING += /usr/local/lib/libsodium.a
endif

ifeq ($(findstring cmd,$(FEATURES)),cmd)
  OBJS += build/ext-cmd.o
  CFLAGS += -DCMD
  EXTRA += kadnode-ctl
endif

ifeq ($(findstring debug,$(FEATURES)),debug)
  CFLAGS += -g -DDEBUG
endif

ifeq ($(findstring dns,$(FEATURES)),dns)
  OBJS += build/ext-dns.o
  CFLAGS += -DDNS
endif

ifeq ($(findstring nss,$(FEATURES)),nss)
  OBJS += build/ext-nss.o
  CFLAGS += -DNSS
  EXTRA += libnss_kadnode.so.2
endif

ifeq ($(findstring web,$(FEATURES)),web)
  OBJS += build/ext-web.o
  CFLAGS += -DWEB
endif

ifeq ($(findstring upnp,$(FEATURES)),upnp)
  OBJS += build/upnp.o
  CFLAGS += -DFWD_UPNP
  POST_LINKING += -lminiupnpc
  ENABLE_FORWARDING = 1
endif

ifeq ($(findstring natpmp,$(FEATURES)),natpmp)
  OBJS += build/natpmp.o
  CFLAGS += -DFWD_NATPMP
  POST_LINKING += -lnatpmp
  ENABLE_FORWARDING = 1
endif

ifeq ($(ENABLE_FORWARDING),1)
	OBJS += build/forwardings.o
	CFLAGS += -DFWD
endif


build/%.o : src/%.c src/%.h
	$(CC) $(CFLAGS) -c -o $@ $<

libnss_kadnode.so.2:
	$(CC) $(CFLAGS) -fPIC -c -o build/ext-libnss.o src/ext-libnss.c
	$(CC) $(CFLAGS) -fPIC -shared -Wl,-soname,libnss_kadnode.so.2 -o build/libnss_kadnode.so.2 build/ext-libnss.o

kadnode-ctl:
	$(CC) $(CFLAGS) src/kadnode-ctl.c -o build/kadnode-ctl

kadnode: $(OBJS) $(EXTRA)
	$(CC) $(OBJS) -o build/kadnode $(POST_LINKING)

clean:
	rm -rf build/*

strip:
	strip build/kadnode
	-strip build/kadnode-ctl 2> /dev/null
	-strip build/libnss_kadnode.so.2 2> /dev/null

arch-pkg:
	cd archlinux && makepkg

deb-pkg:
	dpkg-buildpackage -us -uc

osx-pkg:
	cd macosx && ./build.sh

install:
	cp build/kadnode $(DESTDIR)/usr/bin/
	-cp build/kadnode-ctl $(DESTDIR)/usr/bin/
	-cp build/libnss_kadnode.so.2 $(DESTDIR)/lib/
	-sed -i -e 's/^hosts:\s*files \(kadnode\)\?\s*/hosts:          files kadnode /' $(DESTDIR)/etc/nsswitch.conf 2> /dev/null

uninstall:
	rm $(DESTDIR)/usr/bin/kadnode
	-rm $(DESTDIR)/usr/bin/kadnode-ctl
	-rm $(DESTDIR)/lib/libnss_kadnode.so.2
	-sed -i -e 's/^hosts:\s*files kadnode /hosts:          files /' $(DESTDIR)/etc/nsswitch.conf 2> /dev/null
