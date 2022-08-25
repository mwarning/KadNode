
CFLAGS ?= -Os -Wall -Wwrite-strings -pedantic
CFLAGS += -std=gnu99 -I/usr/local/include $(CPPFLAGS)
LDFLAGS += -L/usr/local/lib -lc
FEATURES ?= dns lpd tls bob cmd debug nss #natpmp upnp

OBJS = build/searches.o build/kad.o build/log.o \
	build/conf.o build/net.o build/utils.o \
	build/announces.o build/peerfile.o

ifeq ($(OS),Windows_NT)
  OBJS += build/unix.o build/windows.o
else
  OBJS += build/unix.o
endif

.PHONY: all clean strip install kadnode libkadnode.so libkanode.a \
	libnss_kadnode arch-pkg deb-pkg osx-pkg manpage install uninstall

all: kadnode


ifeq ($(findstring lpd,$(FEATURES)),lpd)
  OBJS += build/ext-lpd.o
  CFLAGS += -DLPD
endif

ifeq ($(findstring bob,$(FEATURES)),bob)
  OBJS += build/ext-bob.o build/ecc_point_compression.o
  CFLAGS += -DBOB
  LDFLAGS += -lmbedtls -lmbedx509 -lmbedcrypto
endif

ifeq ($(findstring cmd,$(FEATURES)),cmd)
  OBJS += build/ext-cmd.o
  CFLAGS += -DCMD
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
  EXTRA += libnss_kadnode
endif

ifeq ($(findstring tls,$(FEATURES)),tls)
  OBJS += build/ext-tls-client.o build/ext-tls-server.o
  CFLAGS += -DTLS
  LDFLAGS += -lmbedtls -lmbedx509 -lmbedcrypto
endif

ifeq ($(findstring upnp,$(FEATURES)),upnp)
  OBJS += build/upnp.o
  CFLAGS += -DFWD_UPNP
  LDFLAGS += -Wl,-Bdynamic -lminiupnpc
  ENABLE_FORWARDING = 1
endif

ifeq ($(findstring natpmp,$(FEATURES)),natpmp)
  OBJS += build/natpmp.o
  CFLAGS += -DFWD_NATPMP
  LDFLAGS += -Wl,-Bdynamic -lnatpmp
  ENABLE_FORWARDING = 1
endif

ifeq ($(ENABLE_FORWARDING),1)
  OBJS += build/ext-fwd.o
  CFLAGS += -DFWD
endif


build/%.o : src/%.c src/%.h
	$(CC) $(CFLAGS) -c -o $@ $<

libnss_kadnode:
	$(CC) $(CFLAGS) -fPIC -c -o build/ext-libnss.o src/ext-libnss.c
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -shared -Wl,-soname,libnss_kadnode.so.2 -o build/libnss_kadnode-2.0.so build/ext-libnss.o

libkadnode.a: build/libkadnode.o $(OBJS)
	ar rcs build/libkadnode.a build/libkadnode.o $(OBJS)

libkadnode.so: CFLAGS += -fpic
libkadnode.so: build/libkadnode.o $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $(OBJS) build/libkadnode.o -o build/libkadnode.so

kadnode: build/main.o $(OBJS) $(EXTRA)
	$(CC) $(CFLAGS) build/main.o $(OBJS) $(LDFLAGS) -o build/kadnode
	ln -s kadnode build/kadnode-ctl 2> /dev/null || true

clean:
	rm -rf build/*

manpage:
	ronn --roff --manual=Kadnode\ Manual --organization=mwarning --date=2018-01-01 misc/manpage.md
	mv misc/manpage.1 misc/manpage

install:
	cp build/kadnode $(DESTDIR)/usr/bin/ 2> /dev/null || true
	ln -s kadnode $(DESTDIR)/usr/bin/kadnode-ctl || true
	cp build/libnss_kadnode-2.0.so $(DESTDIR)/lib/libnss_kadnode.so.2 2> /dev/null || true
	cp build/libkadnode.so $(DESTDIR)/lib/ 2> /dev/null || true
	sed -i -e '/kadnode/!s/^\(hosts:.*\)\s\{1,\}dns\(.*\)/\1 kadnode dns\2/' $(DESTDIR)/etc/nsswitch.conf 2> /dev/null || true

uninstall:
	rm $(DESTDIR)/usr/bin/kadnode 2> /dev/null || true
	rm $(DESTDIR)/usr/bin/kadnode-ctl 2> /dev/null || true
	rm $(DESTDIR)/lib/libnss_kadnode.so 2> /dev/null || true
	rm $(DESTDIR)/usr/lib/libkadnode.so 2> /dev/null || true
	sed -i -e 's/^\(hosts:.*\)kadnode \(.*\)/\1\2/' $(DESTDIR)/etc/nsswitch.conf 2> /dev/null || true
