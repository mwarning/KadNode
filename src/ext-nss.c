
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


static void nss_lookup( int sock, IP *clientaddr, const char hostname[] ) {
	socklen_t addrlen;
	IP addrs[MAX_ADDRS];

	// Lookup id, starts search when not already started
	int num = kad_lookup( hostname, addrs, N_ELEMS(addrs) );
	if( num > 0 ) {
		// Found addresses
		log_debug( "NSS: Send %lu addresses to %s. Packet has %d bytes.",
		   num, str_addr( clientaddr ), sizeof(IP)
		);
	} else {
		num = 0;
	}

	addrlen = addr_len( clientaddr );
	sendto( sock, (uint8_t *) addrs, num * sizeof(IP), 0, (const struct sockaddr *) clientaddr, addrlen );
}

// Handle a local connection
static void nss_handler( int rc, int sock ) {
	IP clientaddr;
	socklen_t addrlen_ret;
	char hostname[QUERY_MAX_SIZE];

	if( rc == 0 ) {
		return;
	}

	addrlen_ret = sizeof(IP);
	rc = recvfrom( sock, hostname, sizeof(hostname), 0, (struct sockaddr *) &clientaddr, &addrlen_ret );

	if( rc <= 0 || rc >= sizeof(hostname) ) {
		return;
	}

	// Add missing null terminator
	hostname[rc] = '\0';

	if( !is_suffix( hostname, gconf->query_tld ) ) {
		return;
	}

	// Validate hostname
	if( !str_isValidHostname( hostname ) ) {
		log_warn( "NSS: Invalid hostname for lookup: '%s'", hostname );
		return;
	}

	nss_lookup( sock, &clientaddr, hostname );
}

void nss_setup( void ) {
	int sock4;
	int sock6;

	if( gconf->nss_port < 1 ) {
		return;
	}

	sock4 = net_bind( "NSS", "127.0.0.1", gconf->nss_port, NULL, IPPROTO_UDP );
	sock6 = net_bind( "NSS", "::1", gconf->nss_port, NULL, IPPROTO_UDP );

	if( sock4 >= 0 ) {
		net_add_handler( sock4, &nss_handler );
	}

	if( sock6 >= 0 ) {
		net_add_handler( sock6, &nss_handler );
	}
}

void nss_free( void ) {
	// Nothing to do
}
