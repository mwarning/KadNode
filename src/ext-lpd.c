
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#include "ext-lpd.h"

/*
* Local Peer Discovery
*/

#ifdef __CYGWIN__
#ifndef AF_PACKET
#define AF_PACKET 17
#endif
#endif

enum {
	// Packets per minute to be handled
	PACKET_LIMIT_MAX = 20,
	// Limit multicast message to the same subnet
	TTL_SAME_SUBNET = 1
};

struct lpd_state {
	IP mcast_addr;
	time_t mcast_time;
	int packet_limit;
	int sock_send;
	int sock_listen;
};

struct lpd_state g_lpd4 = {
	.mcast_addr = {0},
	.mcast_time = 0,
	.packet_limit = PACKET_LIMIT_MAX,
	.sock_send = -1,
	.sock_listen = -1
};

struct lpd_state g_lpd6 = {
	.mcast_addr = {0},
	.mcast_time = 0,
	.packet_limit = PACKET_LIMIT_MAX,
	.sock_send = -1,
	.sock_listen = -1
};

static int is_valid_ifa(struct ifaddrs *ifa, int af)
{
	if ((ifa->ifa_addr == NULL)
			|| !(ifa->ifa_flags & IFF_RUNNING)
			|| (ifa->ifa_flags & IFF_LOOPBACK)
			|| (ifa->ifa_addr->sa_family != af)) {
		return 0;
	}

	// if DHT interface set, use only that interface (if it exists)
	if (gconf->dht_ifname && 0 != strcmp(gconf->dht_ifname, ifa->ifa_name)) {
		return 0;
	} else {
		return 1;
	}
}

static void join_mcast(const struct lpd_state* lpd, struct ifaddrs *ifa)
{
	for (; ifa != NULL; ifa = ifa->ifa_next) {
		if (is_valid_ifa(ifa, AF_PACKET)) {
			unsigned ifindex = if_nametoindex(ifa->ifa_name);

			if (lpd->mcast_addr.ss_family == AF_INET) {
				struct ip_mreq mcastReq;

				memset(&mcastReq, 0, sizeof(mcastReq));
				mcastReq.imr_multiaddr = ((IP4*) &lpd->mcast_addr)->sin_addr;
				mcastReq.imr_interface.s_addr = htonl(INADDR_ANY);

				// ignore error (we might already be subscribed)
				setsockopt(lpd->sock_listen, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void const*)&mcastReq, sizeof(mcastReq));
			} else {
				struct ipv6_mreq mreq6;

				memcpy(&mreq6.ipv6mr_multiaddr, &((IP6*) &lpd->mcast_addr)->sin6_addr, 16);
				mreq6.ipv6mr_interface = ifindex;

				// ignore error (we might already be subscribed)
				setsockopt(lpd->sock_listen, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6));
			}
		}
	}
}

static void send_mcasts(const struct lpd_state* lpd, struct ifaddrs *ifa)
{
	char message[16];

	log_debug("LPD: Send discovery message to %s", str_addr(&lpd->mcast_addr));
	sprintf(message, "DHT %d", gconf->dht_port);

	int family = lpd->mcast_addr.ss_family;
	for (; ifa != NULL; ifa = ifa->ifa_next) {
		if (family == AF_INET && is_valid_ifa(ifa, AF_INET)) {
			struct in_addr addr = ((struct sockaddr_in*) ifa->ifa_addr)->sin_addr;

			if (setsockopt(lpd->sock_send, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr)) < 0) {
				log_error("setsockopt(IP_MULTICAST_IF) %s", strerror(errno));
				continue;
			}
		} else if (family == AF_INET6 && is_valid_ifa(ifa, AF_PACKET)) {
			unsigned ifindex = if_nametoindex(ifa->ifa_name);

			if (setsockopt(lpd->sock_send, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
				log_error("setsockopt(IPV6_MULTICAST_IF) %s", strerror(errno));
				continue;
			}
		} else {
			continue;
		}
		sendto(lpd->sock_send, (void const*) message, strlen(message), 0,
				(struct sockaddr const*) &lpd->mcast_addr, addr_len(&lpd->mcast_addr));
	}
}

static void handle_mcast(int rc, struct lpd_state* lpd)
{
	struct ifaddrs *ifaddrs;
	socklen_t addrlen;
	char buf[16];
	uint16_t port;
	IP addr;

	if (lpd->mcast_time <= time_now_sec()) {
		if (getifaddrs(&ifaddrs) == 0) {
			// join multicast group (in case of new interfaces)
			join_mcast(lpd, ifaddrs);

			// No peers known, send multicast
			if (kad_count_nodes(false) == 0) {
				send_mcasts(lpd, ifaddrs);
			}
			freeifaddrs(ifaddrs);
		} else {
			log_error("getifaddrs() %s", strerror(errno));
		}

		// Cap number of received packets to 10 per minute
		lpd->packet_limit = 5 * PACKET_LIMIT_MAX;

		// Try again in ~5 minutes
		lpd->mcast_time = time_add_mins(5);
	}

	if (rc <= 0) {
		return;
	}

	// Receive multicast ping
	addrlen = sizeof(IP);
	rc = recvfrom(lpd->sock_listen, buf, sizeof(buf) - 1, 0, (struct sockaddr*) &addr, (socklen_t*) &addrlen);
	if (rc <= 0) {
		log_warning("LPD: Cannot receive multicast message: %s", strerror(errno));
		return;
	} else if (lpd->packet_limit < 0) {
		// Too much traffic
		return;
	} else {
		lpd->packet_limit -= 1;
	}

	buf[rc] = '\0';

	if (sscanf(buf, "DHT %hu", &port) == 1) {
		port_set(&addr, port);
		log_debug("LPD: Ping lonely peer at %s", str_addr(&addr));
		kad_ping(&addr);
	}
}

static void handle_mcast4(int rc, int sock)
{
	assert(sock == g_lpd4.sock_listen);
	handle_mcast(rc, &g_lpd4);
}

static void handle_mcast6(int rc, int sock)
{
	assert(sock == g_lpd6.sock_listen);
	handle_mcast(rc, &g_lpd6);
}

static int create_send_socket(int af)
{
	const int scope = TTL_SAME_SUBNET;
	const int opt_off = 0;
	in_addr_t iface = INADDR_ANY;
	int sock;

	if ((sock = net_socket("LPD", NULL, IPPROTO_IP, af)) < 0) {
		return -1;
	}

	if (af == AF_INET) {
		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void const*)&scope, sizeof(scope)) != 0) {
			goto fail;
		}

		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char*)&iface, sizeof(iface)) != 0) {
			goto fail;
		}

		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void const*)&opt_off, sizeof(opt_off)) != 0) {
			goto fail;
		}
	} else {
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char*)&scope, sizeof(scope)) != 0) {
			goto fail;
		}

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (void const*)&opt_off, sizeof(opt_off)) != 0) {
			goto fail;
		}
	}

	return sock;

fail:
	close(sock);

	log_warning("LPD: Cannot create send %s socket: %s",  str_af(af), strerror(errno));

	return -1;
}

static int create_receive_socket(const IP *mcast_addr)
{
	const int opt_off = 0;
	socklen_t addrlen;
	int sock;
	int af;

	addrlen = addr_len(mcast_addr);
	af = mcast_addr->ss_family;

	if ((sock = net_socket("LPD", NULL, IPPROTO_UDP, af)) < 0) {
		return -1;
	}

	if (af == AF_INET6) {
		int loop = 0;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&loop, sizeof(loop)) < 0) {
			goto fail;
		}
	} else {
		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void const*)&opt_off, sizeof(opt_off)) != 0) {
			goto fail;
		}
	}

	if (bind(sock, (struct sockaddr*)mcast_addr, addrlen) != 0) {
		goto fail;
	}

	return sock;

fail:

	close(sock);

	log_warning("LPD: Cannot create receive %s socket: %s", str_af(af), strerror(errno));

	return -1;
}

int lpd_setup(void)
{
	const char *ifname;
	int ready = 0;

	if (gconf->lpd_disable) {
		return EXIT_SUCCESS;
	}

	ifname = gconf->dht_ifname;

	if (ifname && (gconf->af == AF_UNSPEC || gconf->af == AF_INET)) {
		log_warning("LPD: ifname setting not supported for IPv4");
	}

	addr_parse(&g_lpd4.mcast_addr, LPD_ADDR4, STR(LPD_PORT), AF_INET);
	addr_parse(&g_lpd6.mcast_addr, LPD_ADDR6, STR(LPD_PORT), AF_INET6);

	// Setup IPv4 sockets
	g_lpd4.sock_listen = create_receive_socket(&g_lpd4.mcast_addr);
	g_lpd4.sock_send = create_send_socket(AF_INET);

	// Setup IPv6 sockets
	g_lpd6.sock_listen = create_receive_socket(&g_lpd6.mcast_addr);
	g_lpd6.sock_send = create_send_socket(AF_INET6);

	if (g_lpd4.sock_listen >= 0 && g_lpd4.sock_send >= 0) {
		net_add_handler(g_lpd4.sock_listen, &handle_mcast4);
		ready += 1;
	}

	if (g_lpd6.sock_listen >= 0 && g_lpd6.sock_send >= 0) {
		net_add_handler(g_lpd6.sock_listen, &handle_mcast6);
		ready += 1;
	}

	return ready ? EXIT_SUCCESS : EXIT_FAILURE;
}

void lpd_free(void)
{
	// Nothing to do
}
