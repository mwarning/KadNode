
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <semaphore.h>
#include <signal.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "ext-nss.h"


void nss_lookup( int sock, IP *clientaddr, const char *hostname ) {
	char addrbuf1[FULL_ADDSTRLEN+1];
	char addrbuf2[FULL_ADDSTRLEN+1];
	IP addr;
	size_t n;

	/* Lookup id. Starts search when not already started. */
	n = 1;
	if( kad_lookup_value( hostname, &addr, &n ) != 0 ) {
		log_debug( "NSS: Node not found; starting search." );
		return;
	}

	/* Found address */
	log_debug( "NSS: Send address %s to %s. Packet has %d bytes.",
		str_addr( &addr, addrbuf1 ),
		str_addr( clientaddr, addrbuf2 ),
		sizeof(IP)
	);

	sendto( sock, (UCHAR *) &addr, sizeof(IP), 0, (const struct sockaddr *) clientaddr, sizeof(IP) );
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

	/* Validate hostname */
	if ( !str_isValidHostname( (char*) hostname, strlen( hostname ) ) ) {
		log_warn( "NSS: Invalid hostname for lookup: '%s'", hostname );
		return;
	}

	nss_lookup( sock, &clientaddr, hostname );
}

void nss_setup( void ) {
	int sock;

	if( str_isZero( gstate->nss_port ) ) {
		return;
	}

	sock = net_bind( "NSS", "::1", gstate->nss_port, NULL, IPPROTO_UDP, AF_INET6 );
	net_add_handler( sock, &nss_handler );
}
