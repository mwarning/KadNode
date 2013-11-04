
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#include "bootstrap.h"


/* Multicast message format - inspired by, but not compatible to the BitTorrent Local Peer Discovery (LPD) */
const char msg_fmt[] =
	"DHT-SEARCH * HTTP/1.0\r\n"
	"Port: %u\r\n"
	"Server: KadNode\r\n"
	"Version: "MAIN_VERSION"\r\n"
	"\r\n"
	"\r\n";

enum { PACKET_LIMIT_MAX =  20 }; /* Packets per minute to be handled */
static int packet_limit = 0;
static IP mcast_addr;
static int mcast_registered = 0; /* Indicates if the multicast addresses has been registered */
static time_t mcast_time = 0; /* Next time to perform a multicast ping */


/* Try to join/leave multicast group */
int multicast_setup4( int sock, IP *addr, int enable ) {
	struct ip_mreq mreq;
	int optname;
	int optvalue;

	memset( &mreq, '\0', sizeof(mreq) );
	memcpy( &mreq.imr_multiaddr, &((IP4 *)addr)->sin_addr, sizeof(mreq.imr_multiaddr) );

	/* Using an interface index of x is indicated by 0.0.0.x */
	if( gconf->dht_ifce && ((mreq.imr_interface.s_addr = htonl( if_nametoindex( gconf->dht_ifce )) ) == 0) ) {
		log_err( "BOOT: Cannot find interface '%s' for multicast: %s", gconf->dht_ifce, strerror( errno ) );
		return 0;
	} else {
		mreq.imr_interface.s_addr = 0;
	}

	optvalue = 0;
	/* We don't want to receive our own packets */
	if( setsockopt( sock, IPPROTO_IP, IP_MULTICAST_LOOP, &optvalue, sizeof(optvalue) ) < 0 ) {
		log_warn( "BOOT: Failed to set IP_MULTICAST_LOOP: %s", strerror( errno ) );
		return 1;
	}

	optname = enable ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
	if( setsockopt( sock, IPPROTO_IP, optname, &mreq, sizeof(mreq) ) < 0 ) {
		if( enable ) {
			log_warn( "BOOT: Failed to join IPv4 multicast group: %s", strerror( errno ) );
		} else {
			log_warn( "BOOT: Failed to leave IPv4 multicast group: %s", strerror( errno ) );
		}
		return 0;
	}

	return 1;
}

/* Try to join/leave multicast group */
int multicast_setup6( int sock, IP *addr, int enable ) {
	struct ipv6_mreq mreq;
	int optname;
	int optvalue;

	memset( &mreq, '\0', sizeof(mreq) );
	memcpy( &mreq.ipv6mr_multiaddr, &((IP6 *)addr)->sin6_addr, sizeof(mreq.ipv6mr_multiaddr) );

	if( gconf->dht_ifce && ((mreq.ipv6mr_interface = if_nametoindex( gconf->dht_ifce )) == 0) ) {
		log_err( "BOOT: Cannot find interface '%s' for multicast: %s", gconf->dht_ifce, strerror( errno ) );
		return 0;
	}

	optvalue = 0;
	if( setsockopt( sock, IPPROTO_IPV6, IP_MULTICAST_LOOP, &optvalue, sizeof(optvalue) ) < 0 ) {
		log_warn( "BOOT: Failed to set IP_MULTICAST_LOOP: %s", strerror( errno ) );
		return 1;
	}

	optname = enable ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP;
	if( setsockopt( sock, IPPROTO_IPV6, optname, &mreq, sizeof(mreq)) != 0 ) {
		if( enable ) {
			log_warn( "BOOT: Failed to join IPv6 multicast group: %s", strerror( errno ) );
		} else {
			log_warn( "BOOT: Failed to leave IPv6 multicast group: %s", strerror( errno ) );
		}
		return 0;
	}

	return 1;
}

int multicast_join( int sock, IP *addr ) {
	const int af = addr->ss_family;

	if( af == AF_INET ) {
		return multicast_setup4( sock, addr, 1 );
	} else if( af == AF_INET6 ) {
		return multicast_setup6( sock, addr, 1 );
	} else {
		return 0;
	}
}

int multicast_leave( int sock, IP *addr ) {
	const int af = addr->ss_family;

	if( af == AF_INET ) {
		return multicast_setup4( sock, addr, 0 );
	} else if( af == AF_INET6 ) {
		return multicast_setup6( sock, addr, 0 );
	} else {
		return 0;
	}
}

const char *parse_packet_param( const char* str, const char* param ) {
	const char* pos;

	pos = strstr( str, param );
	if( pos == NULL ) {
		return NULL;
	} else {
		return (pos + strlen( param ));
	}
}

int parse_packet( const char *str ) {
	const char *beg;
	int port = 0;

	/* Parse port */
	beg = parse_packet_param( str, "Port: ");
	if( beg == NULL ) {
		return 0;
	}

	if( sscanf( beg, "%d\r\n", &port ) != 1 && port > 0 && port < 65536 ) {
		return 0;
	}

	/* Check for existence of server field */
	beg = parse_packet_param( str, "Server: ");
	if( beg == NULL ) {
		return 0;
	}

	/* Check for existence of version field */
	beg = parse_packet_param( str, "Version: ");
	if( beg == NULL ) {
		return 0;
	}

	return port;
}

void bootstrap_export_peerfile( void ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	const char *filename;
	IP addrs[32];
	size_t i, num;
	FILE * fp;

	filename = gconf->peerfile;
	if( filename == NULL ) {
		return;
	}

	num = N_ELEMS(addrs);
	if( kad_export_nodes( addrs, &num ) != 0 ) {
		log_warn("BOOT: Failed to export nodes.");
		return;
	}

	/* No peers to export */
	if( num == 0 ) {
		log_info( "BOOT: No peers to export." );
		return;
	}

	if( time_now_sec() - gconf->startup_time < (5 * 60) ) {
		log_info( "BOOT: No peers exported. KadNode needs to run at least 5 minutes." );
		return;
	}

	fp = fopen( filename, "w" );
	if( fp == NULL ) {
		log_warn( "BOOT: Cannot open file '%s' for peer export: %s", filename, strerror( errno ) );
		return;
	}

	/* Write peers to file */
	for( i = 0; i < num; ++i ) {
		if( fprintf( fp, "%s\n", str_addr( &addrs[i], addrbuf ) ) < 0 ) {
			break;
		}
	}

	fclose( fp );

	log_info( "BOOT: Exported %d peers to: %s", i, filename );
}

void bootstrap_import_peerfile( void ) {
	char linebuf[256];
	const char *filename;
	FILE *fp;
	int num;
	IP addr;

	filename = gconf->peerfile;
	if( filename == NULL ) {
		return;
	}

	fp = fopen( filename, "r" );
	if( fp == NULL ) {
		log_warn( "BOOT: Cannot open file '%s' for peer import: %s", filename, strerror( errno ) );
		return;
	}

	num = 0;
	while( fgets( linebuf, sizeof(linebuf), fp ) != NULL ) {
		linebuf[strcspn( linebuf, "\n" )] = '\0';
		if( linebuf[0] == '\0' ) {
			continue;
		}

		if( addr_parse_full( &addr, linebuf, DHT_PORT, gconf->af ) == ADDR_PARSE_SUCCESS ) {
			if( kad_ping( &addr ) == 0 ) {
				num++;
			} else {
				fclose( fp );
				log_err( "BOOT: Cannot ping peers: %s", strerror( errno ) );
				return;
			}
		}
	}

	fclose( fp );

	log_info( "BOOT: Imported %d peers from: %s", num, filename );
}

int set_port( IP *addr, unsigned short port ) {
	if( addr->ss_family == AF_INET ) {
		((IP4 *)addr)->sin_port = htons( port );
	} else if( addr->ss_family == AF_INET6 ) {
		((IP6 *)addr)->sin6_port = htons( port );
	} else {
		return 1;
	}
	return 0;
}

void bootstrap_handle( int rc, int sock ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	char buf[512];
	IP c_addr;
	socklen_t addrlen;
	int rc_send;
	int rc_recv;

	if( mcast_time <= time_now_sec() ) {
		if( kad_count_nodes() == 0 ) {
			/* Join multicast group if possible */
			if( mcast_registered == 0 && multicast_join( sock, &mcast_addr ) ) {
				log_info( "BOOT: No peers known. Joined multicast group." );
				mcast_registered = 1;
			}

			if( mcast_registered == 1 ) {
				snprintf( buf, sizeof(buf), msg_fmt, atoi(gconf->dht_port) );

				rc_send = sendto( sock, buf, strlen(buf), 0, (struct sockaddr*) &mcast_addr, sizeof(IP) );
				if( rc_send < 0 ) {
					log_warn( "BOOT: Cannot send multicast message: %s", strerror( errno ) );
				} else {
					log_info( "BOOT: Send multicast message to find nodes." );
				}
			}

			/* Ping peers from peerfile, if present */
			bootstrap_import_peerfile();
		}

		/* Cap number of received packets to 10 per minute */
		packet_limit = 5 * PACKET_LIMIT_MAX;

		/* Try again in ~5 minutes */
		mcast_time = time_add_min( 5 );
	}

	if( rc > 0 ) {
		/* Reveice multicast ping */
		addrlen = sizeof(IP);
		rc_recv = recvfrom( sock, buf, sizeof(buf), 0, (struct sockaddr*) &c_addr, (socklen_t*) &addrlen );
		if( rc_recv < 0 ) {
			log_warn( "BOOT: Cannot receive multicast message: %s", strerror( errno ) );
			return;
		}

		packet_limit -= 1;
		if( packet_limit < 0 ) {
			/* Too much traffic - leave multicast group for now */
			if( mcast_registered == 1 && multicast_leave( sock, &mcast_addr ) ) {
				log_warn( "BOOT: Too much traffic. Left multicast group." );
				mcast_registered = 0;
			}
			return;
		}

		if( rc_recv >= sizeof(buf) ) {
			return;
		} else {
			buf[rc_recv] = '\0';
		}

		int port = parse_packet( buf );
		if( port > 0 ) {
			set_port( &c_addr, port );
			log_debug( "BOOT: Ping lonely peer at %s", str_addr( &c_addr, addrbuf ) );
			kad_ping( &c_addr );
		} else {
			log_debug( "BOOT: Received invalid packet on multicast group." );
		}
	}
}

void bootstrap_setup( void ) {
	int sock;

	packet_limit = PACKET_LIMIT_MAX;
	if( addr_parse( &mcast_addr, gconf->mcast_addr, DHT_PORT_MCAST, gconf->af ) != 0 ) {
		log_err( "BOOT: Failed to parse IP address for '%s'.", gconf->mcast_addr );
	}

	if( gconf->disable_multicast == 0 ) {
		sock = net_bind( "BOOT", gconf->mcast_addr, DHT_PORT_MCAST, NULL, IPPROTO_UDP, gconf->af );
	} else {
		return;
	}

	net_add_handler(sock , &bootstrap_handle );
}
