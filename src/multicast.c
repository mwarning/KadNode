
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "multicast.h"


/* Try to join/leave multicast group */
int multicast_setup4( int sock, IP *addr, int enable ) {
	struct ip_mreq mreq;
	int optname;

	memset( &mreq, '\0', sizeof(mreq) );
	memcpy( &mreq.imr_multiaddr, &((IP4 *)addr)->sin_addr, sizeof(mreq.imr_multiaddr) );

	/* Using an interface index of x is indicated by 0.0.0.x */
	if( gstate->dht_ifce && ((mreq.imr_interface.s_addr = htonl( if_nametoindex( gstate->dht_ifce )) ) == 0) ) {
		log_err( "MC: Cannot find interface '%s' for multicast: %s", gstate->dht_ifce, strerror( errno ) );
		return 0;
	} else {
		mreq.imr_interface.s_addr = 0;
	}

	optname = enable ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
	if( setsockopt( sock, IPPROTO_IP, optname, &mreq, sizeof(mreq) ) < 0 ) {
		if( enable ) {
			log_warn( "MC: Failed to join IPv4 multicast group: %s", strerror( errno ) );
		} else {
			log_warn( "MC: Failed to leave IPv4 multicast group: %s", strerror( errno ) );
		}
		return 0;
	} else {
		if( enable ) {
			log_info( "MC: Joined IPv4 multicast group." );
		} else {
			log_info( "MC: Left IPv4 multicast group." );
		}
		return 1;
	}
}

/* Try to join/leave multicast group */
int multicast_setup6( int sock, IP *addr, int enable ) {
	struct ipv6_mreq mreq;
	int optname;

	memset( &mreq, '\0', sizeof(mreq) );
	memcpy( &mreq.ipv6mr_multiaddr, &((IP6 *)addr)->sin6_addr, sizeof(mreq.ipv6mr_multiaddr) );

	if( gstate->dht_ifce && ((mreq.ipv6mr_interface = if_nametoindex( gstate->dht_ifce )) == 0) ) {
		log_err( "MC: Cannot find interface '%s' for multicast: %s", gstate->dht_ifce, strerror( errno ) );
		return 0;
	}

	optname = enable ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP;
	if( setsockopt( sock, IPPROTO_IPV6, optname, &mreq, sizeof(mreq)) != 0 ) {
		if( enable ) {
			log_warn( "MC: Failed to join IPv6 multicast group: %s", strerror( errno ) );
		} else {
			log_warn( "MC: Failed to leave IPv6 multicast group: %s", strerror( errno ) );
		}
		return 0;
	} else {
		if( enable ) {
			log_info( "MC: Joined IPv6 multicast group." );
		} else {
			log_info( "MC: Left IPv6 multicast group." );
		}
		return 1;
	}
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
