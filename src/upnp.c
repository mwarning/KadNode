
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "log.h"
#include "ext-fwd.h"
#include "upnp.h"


/*
* MINIUPNPC_API_VERSION is not defined for
* miniupnp version 1.5 and older. Let's fix that.
*/
#ifndef UPNPDISCOVER_SUCCESS
#define MINIUPNPC_API_VERSION 5
#endif

#ifndef MINIUPNPC_API_VERSION
#define MINIUPNPC_API_VERSION 8
#endif

enum {
	UPNP_STATE_DISCOVER_GATEWAY,
	UPNP_STATE_RECEIVE_GATEWAY,
	UPNP_STATE_GET_PORTMAPPING,
	UPNP_STATE_ADD_PORTMAPPING,
	UPNP_STATE_ERROR
};

#ifdef DEBUG
const char* upnp_statestr( int state ) {
	switch( state ) {
		case UPNP_STATE_DISCOVER_GATEWAY:
			return "UPNP_STATE_DISCOVER_GATEWAY";
		case UPNP_STATE_RECEIVE_GATEWAY:
			return "UPNP_STATE_RECEIVE_GATEWAY";
		case UPNP_STATE_GET_PORTMAPPING:
			return "UPNP_STATE_GET_PORTMAPPING";
		case UPNP_STATE_ADD_PORTMAPPING:
			return "UPNP_STATE_ADD_PORTMAPPING";
		case UPNP_STATE_ERROR:
			return "UPNP_STATE_ERROR";
		default:
			return "<unknown>";
	}
}
#endif

void upnp_init( struct upnp_handle_t **handle ) {
	*handle = (struct upnp_handle_t *) calloc( 1, sizeof(struct upnp_handle_t) );
}

void upnp_uninit( struct upnp_handle_t **handle ) {
	free( *handle );
	*handle = NULL;
}

int upnpGetSpecificPortMappingEntry( struct upnp_handle_t *handle, const char *proto, unsigned short port ) {
	char extPort[6];
	char intClient[16];
	char intPort[6];

	snprintf( extPort, sizeof(extPort), "%hu", port );

	*intClient = '\0';
	*intPort = '\0';

#if (MINIUPNPC_API_VERSION <= 5)
	return UPNP_GetSpecificPortMappingEntry( handle->urls.controlURL, handle->data.first.servicetype, extPort, proto, intClient, intPort );
#elif (MINIUPNPC_API_VERSION <= 9)
	return UPNP_GetSpecificPortMappingEntry( handle->urls.controlURL, handle->data.first.servicetype, extPort, proto, intClient, intPort, NULL, NULL, NULL );
#else
	return UPNP_GetSpecificPortMappingEntry( handle->urls.controlURL, handle->data.first.servicetype, extPort, proto, NULL, intClient, intPort, NULL, NULL, NULL );
#endif
}

int upnpDeletePortMapping( struct upnp_handle_t *handle, const char *proto, unsigned short port ) {
	char extPort[6];

	snprintf( extPort, sizeof(extPort), "%hu", port );

	return UPNP_DeletePortMapping( handle->urls.controlURL, handle->data.first.servicetype, extPort, proto, NULL );
}

int upnpAddPortMapping( struct upnp_handle_t *handle, const char *proto, unsigned short port ) {
	char extPort[6];
	char inPort[6];

	snprintf( extPort, sizeof(extPort), "%hu", port );
	snprintf( inPort, sizeof(inPort), "%hu", port );
#if (MINIUPNPC_API_VERSION <= 5)
	return UPNP_AddPortMapping( handle->urls.controlURL, handle->data.first.servicetype, extPort, inPort, handle->addr, NULL, proto, NULL );
#else
	return UPNP_AddPortMapping( handle->urls.controlURL, handle->data.first.servicetype, extPort, inPort, handle->addr, NULL, proto, NULL, NULL );
#endif
}

int upnp_handler( struct upnp_handle_t *handle, unsigned short port, time_t lifespan, time_t now ) {
	struct UPNPDev * devlist;

	/* Retry later if we want to wait longer */
	if( handle->retry > now ) {
		return PF_RETRY;
	}

#ifdef DEBUG
	log_debug( "UPnP: Handle port: %hu, lifespan: %ld, state: %s", port, lifespan, upnp_statestr( handle->state ) );
#endif

	/* Get gateway address */
	if( handle->state == UPNP_STATE_DISCOVER_GATEWAY ) {
#if (MINIUPNPC_API_VERSION <= 5)
		devlist = upnpDiscover( 1000, NULL, NULL, 0 );
		if( devlist == NULL ) {
#else
		int err = UPNPDISCOVER_SUCCESS;
		devlist = upnpDiscover( 1000, NULL, NULL, 0, 0, &err );
		if( err != UPNPDISCOVER_SUCCESS ) {
#endif
			log_debug( "UPnP: Method upnpDiscover failed." );
			handle->retry = now + (10 * 60);
			handle->state = UPNP_STATE_DISCOVER_GATEWAY;
			return PF_RETRY;
		} else if( UPNP_GetValidIGD( devlist, &handle->urls, &handle->data,
				handle->addr, sizeof(handle->addr) ) == 1 ) {
			freeUPNPDevlist( devlist );
			log_info( "UPnP: Found gateway device \"%s\".", handle->urls.controlURL );
			handle->state = UPNP_STATE_GET_PORTMAPPING;
			return PF_RETRY;
		} else {
			freeUPNPDevlist( devlist );
			goto error;
		}
	}

	if( handle->state == UPNP_STATE_GET_PORTMAPPING ) {
		if( lifespan == 0 ) {
			/* Remove port forwarding */
			int rc_tcp = upnpDeletePortMapping( handle, "TCP", port );
			int rc_udp = upnpDeletePortMapping( handle, "UDP", port );

			if( rc_tcp == UPNPCOMMAND_SUCCESS && rc_udp == UPNPCOMMAND_SUCCESS ) {
				log_debug( "UPnP: Removed port forwarding for local port %d through \"%s\".", port, handle->urls.controlURL );
				handle->state = UPNP_STATE_GET_PORTMAPPING;
				return PF_DONE;
			} else {
				log_debug( "UPnP: Removing port mapping failed." );
				goto error;
			}
		} else {
			/* Check port forwarding */
			int rc_tcp = upnpGetSpecificPortMappingEntry( handle, "TCP", port );
			int rc_udp = upnpGetSpecificPortMappingEntry( handle, "UDP", port );

			if( rc_tcp == UPNPCOMMAND_SUCCESS && rc_udp == UPNPCOMMAND_SUCCESS ) {
				log_debug( "UPnP: Port forwarding for local port %d already exists.", port );
				handle->state = UPNP_STATE_GET_PORTMAPPING;
				return PF_DONE;
			} else {
				log_debug( "UPnP: Port %d isn't forwarded.", port );
				handle->state = UPNP_STATE_ADD_PORTMAPPING;
				return PF_RETRY;
			}
		}
	}

	/* Add port forwarding */
	if( handle->state == UPNP_STATE_ADD_PORTMAPPING ) {
		if ( handle->urls.controlURL && handle->data.first.servicetype ) {
			int rc_tcp = upnpAddPortMapping( handle, "TCP", port );
			int rc_udp = upnpAddPortMapping( handle, "UDP", port );

			if( rc_tcp == UPNPCOMMAND_SUCCESS && rc_udp == UPNPCOMMAND_SUCCESS ) {
				log_info( "UPnP: Port %d through \"%s\" forwarded to local address %s:%d.",
					port, handle->urls.controlURL, handle->addr, port );
				handle->state = UPNP_STATE_GET_PORTMAPPING;
				return PF_DONE;
			} else {
				log_debug( "UPnP: Port forwarding of port %d failed.", port );
				goto error;
			}
		} else {
			goto error;
		}
	}

	error:;

	handle->retry = now + 60;
	handle->state = UPNP_STATE_ERROR;
	return PF_ERROR;
}
