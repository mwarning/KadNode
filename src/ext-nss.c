
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "dht_wrapper.h"
#include "ext-nss.h"


void nss_lookup( int sock, IP *clientaddr, UCHAR *id ) {
	char addrbuf1[FULL_ADDSTRLEN+1];
	char addrbuf2[FULL_ADDSTRLEN+1];
	IP addr;

	/* Check if we know that node already. */
	if( kad_lookup_node( AF_UNSPEC, id, &addr ) != 0 ) {
		/* Start find process */
		kad_search( AF_UNSPEC, id );
		log_debug( "NSS: Node not found; starting search.");
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
listen for local connection
*/
void* nss_loop( void* _ ) {

	int rc;
	int val;
	struct timeval tv;

	int sock;
	IP clientaddr, sockaddr;
	socklen_t addrlen_ret;
	char hostname[256];
	UCHAR host_id[SHA_DIGEST_LENGTH];
	char hexbuf[HEX_LEN+1];
	char addrbuf[FULL_ADDSTRLEN+1];

	if( addr_parse( &sockaddr, "::1", gstate->nss_port, AF_INET6 ) != 0 ) {
		log_err( "NSS: Failed to parse address." );
		return NULL;
	}

	if( (sock = socket( sockaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP )) < 0 ) {
		log_err( "NSS: Failed to create socket: '%s'", strerror( errno ) );
		return NULL;
	}

	val = 1;
	if ( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val) ) < 0 ) {
		log_err( "NSS: Failed to set socket option SO_REUSEADDR: %s", strerror( errno ));
		return NULL;
	}

	/* Set receive timeout */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if( setsockopt( sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv) ) < 0 ) {
		log_err( "NSS: Failed to set socket option SO_RCVTIMEO: '%s'", strerror( errno ) );
		return NULL;
	}

	if( bind( sock, (struct sockaddr*) &sockaddr, sizeof(IP) ) < 0 ) {
		log_err( "NSS: Failed to bind socket to address: '%s'", strerror( errno ) );
		return NULL;
	}

	log_info( "NSS: Bind to %s", str_addr( &sockaddr, addrbuf ) );

	while( gstate->is_running ) {

		addrlen_ret = sizeof(IP);
		rc = recvfrom( sock, hostname, sizeof(hostname), 0, (struct sockaddr *) &clientaddr, &addrlen_ret );

		if( rc <= 0 || rc >= sizeof(hostname) ) {
			continue;
		}

		/* Add missing null terminator */
		hostname[rc] = '\0';

		/* Validate hostname */
		if ( !str_isValidHostname( (char*) hostname, strlen( hostname ) ) ) {
			log_warn( "NSS: Invalid hostname for lookup: '%s'", hostname );
			continue;
		}

		/* That is the lookup key */
		id_compute( host_id, hostname );
		log_debug( "NSS: Lookup '%s' as '%s'.", hostname, str_id( host_id, hexbuf ) );

		nss_lookup( sock, &clientaddr, host_id );
	}

	close( sock );

	return NULL;
}

void nss_start( void ) {
	pthread_attr_t attr;

	if( str_isZero( gstate->nss_port ) ) {
		return;
	}

	pthread_attr_init( &attr );
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_JOINABLE );

	if( pthread_create( &gstate->nss_thread, &attr, &nss_loop, NULL ) != 0 ) {
		log_crit( "NSS: Failed to create thread." );
	}
}

void nss_stop( void ) {

	if( str_isZero( gstate->nss_port ) ) {
		return;
	}

	if( pthread_join( gstate->nss_thread, NULL ) != 0 ) {
		log_err( "NSS: Failed to join thread." );
	}
}
