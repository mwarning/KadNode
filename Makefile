
CC ?= gcc
CFLAGS = -O2 -Wall -Wwrite-strings -pedantic -std=gnu99
POST_LINKING = -lpthread
FEATURES ?= cmd dns nss web

OBJS_ = main.o dht_wrapper.o log.o conf.o sha1.o unix.o utils.o
OBJS = $(patsubst %,build/%,$(OBJS_))

.PHONY: all clean strip install kadnode kadnode-ctl libnss_kadnode.so.2

all: kadnode

ifeq ($(findstring cmd,$(FEATURES)),cmd)
  OBJS += build/ext-cmd.o
  CFLAGS += -DCMD
  EXTRA += kadnode-ctl
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

build/%.o : src/%.c src/%.h
	$(CC) $(CFLAGS) -c -o $@ $<

libnss_kadnode.so.2:
	$(CC) $(CFLAGS) -fPIC -c -o build/ext-libnss.o src/ext-libnss.c
	$(CC) $(CFLAGS) -fPIC -shared -Wl,-soname,libnss_kadnode.so.2 -o build/libnss_kadnode.so.2 build/ext-libnss.o

kadnode-ctl:
	$(CC) src/kadnode-ctl.c -o build/kadnode-ctl

kadnode: $(OBJS) $(EXTRA)
	$(CC) $(OBJS) -o build/kadnode $(POST_LINKING)

clean:
	rm -f build/*.o
	rm -f build/kadnode
	rm -f build/kadnode-ctl
	rm -f build/libnss_kadnode.so.2

strip:
	strip build/kadnode
	-strip build/kadnode-ctl
	-strip build/libnss_kadnode.so.2

#install:
#	cp build/kadnode /usr/bin/
#	cp build/kadnode-ctl /usr/bin/
#	cp build/libnss_kadnode.so.2 /lib/
#	cp -f /etc/nsswitch.conf /etc/nsswitch.conf.dpkg-old
#	sed -e 's/^hosts:\s*files kadnode /hosts:          files /' /etc/nsswitch.conf.dpkg-old > /etc/nsswitch.conf
