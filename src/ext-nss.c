
#include <stdio.h>
#include <sys/socket.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "ext-nss.h"

#define MAX_ADDRS 32


void nss_lookup( int sock, IP *clientaddr, const char hostname[] ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	socklen_t addrlen;
	IP addrs[MAX_ADDRS];
	size_t num;

	/* Return at most MAX_ADDRS addresses */
	num = MAX_ADDRS;

	/* Lookup id. Starts search when not already started. */
	if( kad_lookup_value( hostname, addrs, &num ) >= 0 && num > 0 ) {
		/* Found addresses */
		log_debug( "NSS: Send %lu addresses to %s. Packet has %d bytes.",
		   num, str_addr( clientaddr, addrbuf ), sizeof(IP)
		);
	} else {
		num = 0;
	}

	addrlen = addr_len( clientaddr );
	sendto( sock, (UCHAR *) addrs, num * sizeof(IP), 0, (const struct sockaddr *) clientaddr, addrlen );
}

/*
* Handle a local connection
*/
void nss_handler( int rc, int sock ) {
	IP clientaddr;
	socklen_t addrlen_ret;
	char hostname[512];

	if( rc == 0 ) {
		return;
	}

	addrlen_ret = sizeof(IP);
	rc = recvfrom( sock, hostname, sizeof(hostname), 0, (struct sockaddr *) &clientaddr, &addrlen_ret );

	if( rc <= 0 || rc >= sizeof(hostname) ) {
		return;
	}

	/* Add missing null terminator */
	hostname[rc] = '\0';

	if( !is_suffix( hostname, gconf->query_tld ) ) {
		return;
	}

	/* Validate hostname */
	if( !str_isValidHostname( hostname ) ) {
		log_warn( "NSS: Invalid hostname for lookup: '%s'", hostname );
		return;
	}

	nss_lookup( sock, &clientaddr, hostname );
}

void nss_setup( void ) {
	int sock;

	if( str_isZero( gconf->nss_port ) ) {
		return;
	}

	sock = net_bind( "NSS", "localhost", gconf->nss_port, NULL, IPPROTO_UDP, AF_UNSPEC );
	net_add_handler( sock, &nss_handler );
}

void nss_free( void ) {
	/* Nothing to do */
}
