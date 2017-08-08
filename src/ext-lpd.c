
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#include "ext-lpd.h"


// Multicast message format - inspired by, but not
// compatible to the BitTorrent Local Peer Discovery (LPD)
const char msg_fmt[] =
	"BT-SEARCH * HTTP/1.0\r\n"
	"Host: %s\r\n"
	"Port: %u\r\n"
	"Infohash: %s\r\n"
	"\r\n"
	"\r\n";

/*
* The last infohash received via LPD,
* KadNode uses it for its own requests
* so that other clients will accept it as peer.
*/
#define LPD_DEFAULT_INFOHASH "0000000000000000000000000000000000000000"
static char g_infohash[SHA1_HEX_LENGTH + 1] = LPD_DEFAULT_INFOHASH;

// Packets per minute to be handled
enum { PACKET_LIMIT_MAX = 20 };

// Indicates if the multicast addresses has been registered
static int g_mcast_registered = 0;

// Next time to perform a multicast ping
static time_t g_mcast_time = 0;

static int g_packet_limit = 0;
static IP g_lpd_addr4 = { 0 };
static IP g_lpd_addr6 = { 0 };


/*
* Join/leave a multicast group (ba mulitcast address) on the given interface.
* The interface may be null.
*/
int mcast_set_group( int sock, const IP *mcast_addr, const char ifname[], int join ) {
#if defined(MCAST_JOIN_GROUP) && !defined(__APPLE__) && !defined(__FreeBSD__)
	struct group_req req;
	int level, optname;

	if( ifname ) {
		if( (req.gr_interface = if_nametoindex( ifname )) == 0 ) {
			log_warn( "LPD: Cannot find interface '%s' for multicast: %s", ifname, strerror( errno ) );
			return -1;
		}
	} else {
		// Register to first interface
		req.gr_interface = 0;
	}

	memcpy( &req.gr_group, mcast_addr, addr_len( mcast_addr ) );

	level = (mcast_addr->ss_family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6;
	optname = (join == 0) ? MCAST_LEAVE_GROUP : MCAST_JOIN_GROUP;

	if( setsockopt( sock, level, optname, &req, sizeof(req) ) < 0 ) {
		log_warn( "LPD: Failed to %s multicast group on %s: %s", join ? "join" : "leave", ifname ? ifname : "<any>", strerror( errno ) );
		return -1;
	}

	return 0;
#else
	switch( mcast_addr->ss_family ) {
		case AF_INET: {
			struct ip_mreqn mreq;

			memcpy( &mreq.imr_multiaddr, &((IP4*) mcast_addr)->sin_addr, 4 );

			if( ifname ) {
				mreq.imr_address.s_addr = htonl( INADDR_ANY );
				if( (mreq.imr_ifindex = if_nametoindex( ifname )) == 0 ) {
					log_warn( "LPD: Cannot find interface '%s' for multicast: %s", ifname, strerror( errno ) );
					return -1;
				}
			} else {
				mreq.imr_address.s_addr = htonl( INADDR_ANY );
				mreq.imr_ifindex = 0;
			}

			int opt = join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
			if( setsockopt(sock, IPPROTO_IP, opt, &mreq, sizeof(mreq)) < 0 ) {
				log_warn( "LPD: Failed to %s IPv4 multicast group on %s: %s", join ? "join" : "leave", ifname ? ifname : "<any>", strerror( errno ) );
				return -1;
			}
			return 0;
		}
		case AF_INET6: {
			struct ipv6_mreq mreq6;

			memcpy( &mreq6.ipv6mr_multiaddr, &((IP6*) mcast_addr)->sin6_addr, 16 );

			if( ifname ) {
				if( (mreq6.ipv6mr_interface = if_nametoindex( ifname )) == 0 ) {
					log_warn( "LPD: Cannot find interface '%s' for multicast: %s", ifname, strerror( errno ) );
					return -1;
				}
			} else {
				mreq6.ipv6mr_interface = 0;
			}

			int opt = join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP;
			if( setsockopt(sock, IPPROTO_IPV6, opt, &mreq6, sizeof(mreq6)) < 0 ) {
				log_warn( "LPD: Failed to %s IPv6 multicast group on %s: %s", join ? "join" : "leave", ifname ? ifname : "<any>", strerror( errno ) );
				return -1;
			}
			return 0;
		}
		default:
			return -1;
	}
#endif
}

int mcast_send_packet( const char msg[], const IP *src_addr,const IP *dst_addr, const char ifname[] ) {
	int sock;
	IP addr;

	// Copy address to separate field and set port
	memcpy( &addr, src_addr, addr_len( (IP*) src_addr ) );
	port_set( &addr, atoi( LPD_PORT ) );

	// For IPv6, only send from link local addresses
	if( addr.ss_family == AF_INET6) {
		unsigned char* a = &((IP6*) &addr)->sin6_addr.s6_addr[0];
		if( !(a[0] == 0xFE && a[1] == 0x80) ) {
			return 1;
		}
	}

	if( (sock = socket( addr.ss_family, SOCK_DGRAM, IPPROTO_UDP )) < 0 ) {
		log_warn( "LPD: Cannot create send socket: %s", strerror( errno ) );
		goto skip;
	}

	const int opt_on = 1;
	if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &opt_on, sizeof(opt_on) ) < 0 ) {
		log_warn( "LPD: Unable to set SO_REUSEADDR: %s", strerror( errno ) );
		goto skip;
	}

	if( bind( sock, (struct sockaddr*) &addr, addr_len( &addr ) ) < 0 ) {
		log_warn( "LPD: Cannot bind send socket: %s", strerror( errno ) );
		goto skip;
	}

	if( sendto( sock, msg, strlen( msg ), 0, (struct sockaddr*) dst_addr, addr_len( dst_addr ) ) < 0 ) {
		log_warn( "LPD: Cannot send message from '%s': %s", str_addr( &addr ), strerror( errno ) );
		goto skip;
	}

	log_debug( "LPD: Send peer discovery packet from source address: %s", str_addr( src_addr ) );

	skip:
	close(sock);

	return 0;
}

// Register to multicast group on all specified interfaces
int multicast_set_groups( int sock, const IP *mcast_addr, const char ifname[], int join ) {
	const struct ifaddrs *cur;
	struct ifaddrs *addrs;

	if( getifaddrs( &addrs ) < 0 ) {
		log_err( "LPD: Cannot get interface list." );
		return -1;
	}

	// Iterate all interfaces
	cur = addrs;
	while( cur != NULL ) {
		if( cur->ifa_addr && (cur->ifa_addr->sa_family == mcast_addr->ss_family)
			&& !(cur->ifa_flags & IFF_LOOPBACK)
			&& !(cur->ifa_flags & IFF_POINTOPOINT)
			&& (cur->ifa_flags & IFF_MULTICAST)
			&& !(ifname && strcmp( cur->ifa_name, ifname ) != 0) ) {
			mcast_set_group( sock, mcast_addr, cur->ifa_name, join );
		}

		cur = cur->ifa_next;
	}

	freeifaddrs( addrs );

	return 0;
}

// Send packet to all specified interfaces
int mcast_send_packets( const char msg[], const char ifname[], const IP *dst_addr ) {
	const struct ifaddrs *cur;
	struct ifaddrs *addrs;

	if( getifaddrs( &addrs ) < 0 ) {
		log_err( "LPD: Cannot get interface list." );
		return -1;
	}

	// Iterate all interfaces
	cur = addrs;
	while( cur != NULL ) {
		if( cur->ifa_addr && (cur->ifa_addr->sa_family == dst_addr->ss_family)
			&& !(cur->ifa_flags & IFF_LOOPBACK)
			&& !(cur->ifa_flags & IFF_POINTOPOINT)
			&& (cur->ifa_flags & IFF_MULTICAST)
			&& !(ifname && strcmp( cur->ifa_name, ifname ) != 0) ) {
			mcast_send_packet( msg, (IP*) cur->ifa_addr, dst_addr, cur->ifa_name );
		}

		cur = cur->ifa_next;
	}

	freeifaddrs( addrs );

	return 0;
}

// Parse received packet
const char *parse_packet_param( const char str[], const char param[] ) {
	const char* pos;

	pos = strstr( str, param );
	if( pos == NULL ) {
		return NULL;
	} else {
		return (pos + strlen( param ));
	}
}

int parse_packet( const char str[] ) {
	const char *beg;
	int port = 0;

	// Find port (required)
	beg = parse_packet_param( str, "Port: ");
	if( beg == NULL ) {
		return 0;
	}

	// Read port
	if( sscanf( beg, "%d\r\n", &port ) != 1 && port > 0 && port < 65536 ) {
		return 0;
	}

	// Find infohash (optional)
	beg = parse_packet_param( str, "Infohash: " );
	if( beg != NULL ) {
		// Read infohash for own request
		if( (strstr(beg, "\r\n") - beg) == SHA1_HEX_LENGTH
			&& str_isHex( beg, SHA1_HEX_LENGTH )
			&& memcmp( beg, LPD_DEFAULT_INFOHASH, SHA1_HEX_LENGTH ) != 0 ) {
			memcpy( g_infohash, beg, SHA1_HEX_LENGTH );
		}
	}

	return port;
}

void handle_mcast( int rc, int sock_recv, const IP *lpd_addr ) {
	char buf[512];
	IP c_addr;
	socklen_t addrlen;
	int rc_recv;

	if( g_mcast_time <= time_now_sec() ) {
		// No peers known, send multicast
		if( kad_count_nodes( 0 ) == 0 ) {
			// Join multicast group if possible
			if( g_mcast_registered == 0 && multicast_set_groups( sock_recv, lpd_addr, gconf->dht_ifname, 1 ) == 0 ) {
				log_info( "LPD: No peers known. Joined multicast group." );
				g_mcast_registered = 1;
			}

			if( g_mcast_registered == 1 ) {
				log_info( "LPD: Send multicast message to find nodes." );

				// Create message
				snprintf(
					buf, sizeof(buf), msg_fmt, str_addr( lpd_addr ),
					addr_port( lpd_addr ), g_infohash
				);

				mcast_send_packets( buf, gconf->dht_ifname, lpd_addr );
			}
		}

		// Cap number of received packets to 10 per minute
		g_packet_limit = 5 * PACKET_LIMIT_MAX;

		// Try again in ~5 minutes
		g_mcast_time = time_add_mins( 5 );
	}

	if( rc <= 0 ) {
		return;
	}

	// Receive multicast ping
	addrlen = sizeof(IP);
	rc_recv = recvfrom( sock_recv, buf, sizeof(buf), 0, (struct sockaddr*) &c_addr, (socklen_t*) &addrlen );
	if( rc_recv < 0 ) {
		log_warn( "LPD: Cannot receive multicast message: %s", strerror( errno ) );
		return;
	}

	if( g_packet_limit < 0 ) {
		// Too much traffic - leave multicast group for now
		if( g_mcast_registered == 1 && multicast_set_groups( sock_recv, lpd_addr, gconf->dht_ifname, 0 ) == 0 ) {
			log_warn( "LPD: Too much traffic. Left multicast group." );
			g_mcast_registered = 0;
		}
		return;
	} else {
		g_packet_limit -= 1;
	}

	if( rc_recv >= sizeof(buf) ) {
		return;
	} else {
		buf[rc_recv] = '\0';
	}

	int port = parse_packet( buf );
	if( port > 0 ) {
		port_set( &c_addr, port );
		log_debug( "LPD: Ping lonely peer at %s", str_addr( &c_addr ) );
		kad_ping( &c_addr );
	} else {
		log_debug( "LPD: Received invalid packet on multicast group." );
	}
}

void handle_mcast4( int rc, int sock ) {
	handle_mcast( rc, sock, &g_lpd_addr4 );
}

void handle_mcast6( int rc, int sock ) {
	handle_mcast( rc, sock, &g_lpd_addr6 );
}

int multicast_set_loop( int sock, int val ) {
	IP addr;

	if( socket_addr( sock, &addr ) != 0 ) {
		return -1;
	}

	switch( addr.ss_family ) {
		case AF_INET: {
			unsigned char flag = val;
			return setsockopt( sock, IPPROTO_IP, IP_MULTICAST_LOOP, &flag, sizeof(flag) );
		}
		case AF_INET6: {
			unsigned int flag = val;
			return setsockopt( sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &flag, sizeof(flag)  );
		}
		default:
			errno = EAFNOSUPPORT;
			return -1;
	}
}

int create_listen_socket( const char addr[] ) {
	const int opt_off = 0;
	const int opt_on = 1;
	int sock;

	sock = net_bind( "LPD", addr, LPD_PORT, gconf->dht_ifname, IPPROTO_UDP );

	if( sock < 0) {
		goto fail;
	}

	if( multicast_set_loop( sock, opt_off ) < 0 ) {
		log_warn( "LPD: Failed to set IP_MULTICAST_LOOP: %s", strerror( errno ) );
		goto fail;
	}

	if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &opt_on, sizeof(opt_on) ) < 0 ) {
		log_warn( "LPD: Unable to set SO_REUSEADDR: %s", strerror( errno ) );
		goto fail;
	}

	return sock;

fail:
	close( sock );

	return -1;
}

void lpd_setup( void ) {
	int sock4;
	int sock6;

	g_packet_limit = PACKET_LIMIT_MAX;
	addr_parse( &g_lpd_addr4, LPD_ADDR4, LPD_PORT, AF_INET );
	addr_parse( &g_lpd_addr6, LPD_ADDR6, LPD_PORT, AF_INET6 );

	if( gconf->lpd_disable ) {
		return;
	}

	sock4 = create_listen_socket( "0.0.0.0" );
	sock6 = create_listen_socket( "::" );

	if( sock4 >= 0 ) {
		net_add_handler( sock4, &handle_mcast4 );
	}

	if( sock6 >= 0 ) {
		net_add_handler( sock6, &handle_mcast6 );
	}
}

void lpd_free( void ) {
	// Nothing to do
}
