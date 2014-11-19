
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "log.h"
#include "ext-fwd.h"
#include "natpmp.h"


enum {
	NATPMP_STATE_INIT,
	NATPMP_STATE_REQUEST_GATEWAY,
	NATPMP_STATE_RECEIVE_GATEWAY,
	NATPMP_STATE_REQUEST_PORTMAPPING,
	NATPMP_STATE_RECEIVE_PORTMAPPING,
	NATPMP_STATE_ERROR
};

#ifdef DEBUG
const char* natpmp_statestr( int state ) {
	switch( state ) {
		case NATPMP_STATE_INIT:
			return "NATPMP_STATE_INIT";
		case NATPMP_STATE_REQUEST_GATEWAY:
			return "NATPMP_STATE_REQUEST_GATEWAY";
		case NATPMP_STATE_RECEIVE_GATEWAY:
			return "NATPMP_STATE_RECEIVE_GATEWAY";
		case NATPMP_STATE_REQUEST_PORTMAPPING:
			return "NATPMP_STATE_REQUEST_PORTMAPPING";
		case NATPMP_STATE_RECEIVE_PORTMAPPING:
			return "NATPMP_STATE_RECEIVE_PORTMAPPING";
		case NATPMP_STATE_ERROR:
			return "NATPMP_STATE_ERROR";
		default:
			return "<unknown>";
	}
}
#endif

void natpmp_init( struct natpmp_handle_t **handle ) {
	/* Initialize data structure */
	struct natpmp_handle_t *m = calloc( 1, sizeof(struct natpmp_handle_t) );
	m->state = 0;
	m->retry = 0;
	m->natpmp.s = -1;
	*handle = m;
}

void natpmp_uninit( struct natpmp_handle_t **handle ) {
	/* Remove all port mapping associated with this host */
	struct natpmp_handle_t *m = *handle;
	sendnewportmappingrequest( &m->natpmp, NATPMP_PROTOCOL_TCP, 0, 0, 0 );
	sendnewportmappingrequest( &m->natpmp, NATPMP_PROTOCOL_UDP, 0, 0, 0 );
	closenatpmp( &m->natpmp );
	free( *handle );
	*handle = NULL;
}

int natpmp_handler( struct natpmp_handle_t *handle, unsigned short port, time_t lifespan, time_t now ) {
	natpmpresp_t response;

	/* Retry later if we want to wait longer */
	if( handle->retry > now ) {
		return PF_RETRY;
	}

#ifdef DEBUG
	log_debug( "NAT-PMP: Handle port: %hu, lifespan: %ld, state: %s", port, lifespan, natpmp_statestr( handle->state ) );
#endif

	/* Initialize data structure / socket */
	if( handle->state == NATPMP_STATE_INIT ) {
		int rc = initnatpmp( &handle->natpmp, 0, 0 );
		if( rc >= 0 ) {
			handle->state = NATPMP_STATE_REQUEST_GATEWAY;
			return PF_RETRY;
		} else {
			log_debug( "NAT-PMP: Method initnatpmp returned %d.", rc );
			goto error;
		}
	}

	/* Request gateway address */
	if( handle->state == NATPMP_STATE_REQUEST_GATEWAY ) {
		int rc = sendpublicaddressrequest( &handle->natpmp );
		if( rc >= 0 ) {
			handle->retry = now + 8;
			handle->state = NATPMP_STATE_RECEIVE_GATEWAY;
			return PF_RETRY;
		} else {
			log_debug( "NAT-PMP: Method sendpublicaddressrequest returned %d.", rc );
			goto error;
		}
	}

	/* Read public gateway address */
	if( handle->state == NATPMP_STATE_RECEIVE_GATEWAY ) {
		int rc = readnatpmpresponseorretry( &handle->natpmp, &response );
		
		if( rc >= 0 ) {
			char str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &response.pnu.publicaddress.addr, str, sizeof (str));
			log_info( "NAT-PMP: Found public address \"%s\".", str );
			handle->state = NATPMP_STATE_REQUEST_PORTMAPPING;
			return PF_RETRY;
		} else if( rc == NATPMP_TRYAGAIN ) {
			handle->retry = now + (10 * 60);
			handle->state = NATPMP_STATE_REQUEST_GATEWAY;
			return PF_RETRY;
		} else {
			log_debug( "NAT-PMP: Method readnatpmpresponseorretry returned %d.", rc );
			goto error;
		}
	}

	/* Add/Remove port mappings */
	if( handle->state == NATPMP_STATE_REQUEST_PORTMAPPING ) {
		int rc_udp = sendnewportmappingrequest( &handle->natpmp, NATPMP_PROTOCOL_UDP, port, port, lifespan );
		int rc_tcp = sendnewportmappingrequest( &handle->natpmp, NATPMP_PROTOCOL_TCP, port, port, lifespan );

		if( rc_udp >= 0 && rc_tcp >= 0 ) {
			handle->retry = now + 2;
			handle->state = NATPMP_STATE_RECEIVE_PORTMAPPING;
			return PF_RETRY;
		} else {
			int rc = (rc_udp >= 0) ? rc_tcp : rc_udp;
			log_debug( "NAT-PMP: Method sendnewportmappingrequest returned %d (%s): %s",
				rc, strnatpmperr( rc ), strerror( errno ) );
			goto error;
		}
	}

	/* Check port mapping */
	if( handle->state == NATPMP_STATE_RECEIVE_PORTMAPPING ) {
		int rc = readnatpmpresponseorretry( &handle->natpmp, &response );
		if( rc >= 0 ) {
			int private_port = response.pnu.newportmapping.privateport;
			int public_port = response.pnu.newportmapping.mappedpublicport;
			time_t lifetime = response.pnu.newportmapping.lifetime;

			if( lifetime > 0 ) {
				log_info( "NAT-PMP: Port forwarding added for port %d (to private port %d) for %ld seconds.", public_port, private_port, lifetime );
				handle->state = NATPMP_STATE_REQUEST_PORTMAPPING;
				return PF_DONE;
			} else {
				log_debug( "NAT-PMP: Port forwarding removed for public port %d (to private port %d) for %ld seconds.", public_port, private_port, lifetime );
				handle->state = NATPMP_STATE_REQUEST_PORTMAPPING;
				return PF_DONE;
			}
		} else if( rc == NATPMP_TRYAGAIN ) {
			handle->state = NATPMP_STATE_RECEIVE_PORTMAPPING;
			return PF_RETRY;
		} else {
			log_debug( "NAT-PMP: Port forwarding failed for port %d.", port );
			goto error;
		}
	}
	
	error:;
	handle->retry = now + 60;
	handle->state = NATPMP_STATE_ERROR;
	return PF_ERROR;
}
