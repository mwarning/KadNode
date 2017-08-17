
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

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#include "ext-lpd.h"


enum {
	// Packets per minute to be handled
	PACKET_LIMIT_MAX = 20,
	// Limit multicast message to the same subnet
	TTL_SAME_SUBNET = 1
};

struct LPD_STATE {
	IP mcast_addr;
	time_t mcast_time;
	int packet_limit;
	int sock_send;
	int sock_listen;
};

struct LPD_STATE g_lpd4 = {
	.mcast_addr = { 0 }, .mcast_time = 0,
	.packet_limit = PACKET_LIMIT_MAX,
	.sock_send = -1, .sock_listen = -1
};

struct LPD_STATE g_lpd6 = {
	.mcast_addr = { 0 }, .mcast_time = 0,
	.packet_limit = PACKET_LIMIT_MAX,
	.sock_send = -1, .sock_listen = -1
};

void handle_mcast( int rc, struct LPD_STATE* lpd ) {
	char buf[16];
	socklen_t addrlen;
	uint16_t port;
	IP addr;

	if( lpd->mcast_time <= time_now_sec() ) {
		// No peers known, send multicast
		if( kad_count_nodes( 0 ) == 0 ) {
			log_debug( "LPD: Try to send hello to %s", str_addr( &lpd->mcast_addr ) );
			sprintf( buf, "DHT %hu", gconf->dht_port );
			sendto( lpd->sock_send, (void const*) buf, strlen(buf), 0, (struct sockaddr const*) &lpd->mcast_addr, sizeof(IP) );
		}

		// Cap number of received packets to 10 per minute
		lpd->packet_limit = 5 * PACKET_LIMIT_MAX;

		// Try again in ~5 minutes
		lpd->mcast_time = time_add_mins( 5 );
	}

	if( rc <= 0 ) {
		return;
	}

	// Receive multicast ping
	addrlen = sizeof(IP);
	rc = recvfrom( lpd->sock_listen, buf, sizeof(buf) - 1, 0, (struct sockaddr*) &addr, (socklen_t*) &addrlen );
	if( rc <= 0 ) {
		log_warn( "LPD: Cannot receive multicast message: %s", strerror( errno ) );
		return;
	} else if( lpd->packet_limit < 0 ) {
		// Too much traffic
		return;
	} else {
		lpd->packet_limit -= 1;
	}

	buf[rc] = '\0';

	if( sscanf(buf, "DHT %hu", &port ) == 1 ) {
		port_set( &addr, port );
		log_debug( "LPD: Ping lonely peer at %s", str_addr( &addr ) );
		kad_ping( &addr );
	}
}

void handle_mcast4( int rc, int sock ) {
	assert( sock == g_lpd4.sock_listen );
	handle_mcast( rc, &g_lpd4 );
}

void handle_mcast6( int rc, int sock ) {
	assert( sock == g_lpd6.sock_listen );
	handle_mcast( rc, &g_lpd6 );
}

int create_send_socket( int af, const char ifname[] ) {
	const int scope = TTL_SAME_SUBNET;
	const int opt_off = 0;
	int sock;

	if( (sock = net_socket( "LPD", ifname, IPPROTO_IP, af ) ) < 0 ) {
		goto fail;
	}

	if( af == AF_INET ) {
		if( setsockopt( sock, IPPROTO_IP, IP_MULTICAST_TTL, (void const*)&scope, sizeof(scope) ) != 0 ) {
			goto fail;
		}

		in_addr_t iface = INADDR_ANY;
		if( setsockopt( sock, IPPROTO_IP, IP_MULTICAST_IF, (char*)&iface, sizeof(iface) ) != 0 ) {
			goto fail;
		}

		if( setsockopt( sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void const*)&opt_off, sizeof(opt_off) ) != 0 ) {
			goto fail;
		}
	} else {
		if( setsockopt( sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char*)&scope, sizeof(scope) ) != 0 ) {
			goto fail;
		}

		unsigned int ifindex = ifname ? if_nametoindex( ifname ) : 0;
		if( setsockopt( sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char*)&ifindex, sizeof(ifindex) ) != 0 ) { 
			goto fail;
		}

		if( setsockopt( sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (void const*)&opt_off, sizeof(opt_off) ) != 0 ) {
			goto fail;
		}
	}

	return sock;

fail:
	close( sock );

	log_warn( "LPD: Cannot create send %s socket: %s",  str_af( af ), strerror( errno ) );

	return -1;
}

int create_receive_socket( const IP *addr, const char ifname[] ) {
	const int opt_off = 0;
	const int af = addr->ss_family;
	int sock;

	if( (sock = net_socket( "LPD", ifname, IPPROTO_IP, af ) ) < 0 ) {
		goto fail;
	}

	if( bind( sock, (struct sockaddr*)addr, sizeof(IP) ) != 0) {
		goto fail;
	}

	if( af == AF_INET ) {
		struct ip_mreq mcastReq;

		memset( &mcastReq, 0, sizeof(mcastReq) );
		mcastReq.imr_multiaddr = ((IP4*) addr)->sin_addr;
		mcastReq.imr_interface.s_addr = htonl(INADDR_ANY);

		if( setsockopt( sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void const*)&mcastReq, sizeof(mcastReq) ) != 0 ) {
			goto fail;
		}

		if( setsockopt( sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void const*)&opt_off, sizeof(opt_off) ) != 0 ) {
			goto fail;
		}
	} else {
		struct ipv6_mreq mreq6;

		memcpy( &mreq6.ipv6mr_multiaddr, &((IP6*) addr)->sin6_addr, 16 );
		mreq6.ipv6mr_interface = ifname ? if_nametoindex( ifname ) : 0;

		if( setsockopt( sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6) ) < 0 ) {
			goto fail;
		}
	}

	return sock;

fail:

	close( sock );

	log_warn( "LPD: Cannot create receive %s socket: %s", str_af( af ), strerror( errno ) );

	return -1;
}

void lpd_setup( void ) {
	const char *ifname = gconf->dht_ifname;

	if( gconf->lpd_disable ) {
		return;
	}

	if( ifname && (gconf->af == AF_UNSPEC || gconf->af == AF_INET) ) {
		log_warn( "LPD: ifname setting not supported for IPv4" );
	}

	addr_parse( &g_lpd4.mcast_addr, LPD_ADDR4, STR(LPD_PORT), AF_INET );
	addr_parse( &g_lpd6.mcast_addr, LPD_ADDR6, STR(LPD_PORT), AF_INET6 );

	// Setup IPv4 sockets
	g_lpd4.sock_listen = create_receive_socket( &g_lpd4.mcast_addr, ifname );
	g_lpd4.sock_send = create_send_socket( AF_INET, ifname );

	// Setup IPv6 sockets
	g_lpd6.sock_listen = create_receive_socket( &g_lpd6.mcast_addr, ifname );
	g_lpd6.sock_send = create_send_socket( AF_INET6, ifname );

	if( g_lpd4.sock_listen >= 0 && g_lpd4.sock_send >= 0 ) {
		net_add_handler( g_lpd4.sock_listen, &handle_mcast4 );
	}

	if( g_lpd6.sock_listen >= 0 && g_lpd6.sock_send >= 0 ) {
		net_add_handler( g_lpd6.sock_listen, &handle_mcast6 );
	}
}

void lpd_free( void ) {
	// Nothing to do
}
