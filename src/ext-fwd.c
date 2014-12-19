
#define _WITH_DPRINTF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "main.h"
#include "conf.h"
#include "net.h"
#include "log.h"
#include "utils.h"
#include "ext-fwd.h"
#ifdef FWD_NATPMP
#include "natpmp.h"
#endif
#ifdef FWD_UPNP
#include "upnp.h"
#endif


#ifdef FWD_NATPMP
static struct natpmp_handle_t *natpmp = NULL;
#endif

#ifdef FWD_UPNP
static struct upnp_handle_t *upnp = NULL;
#endif

static time_t g_fwd_retry = 0;
static struct forwarding_t *g_fwds = NULL;
static struct forwarding_t *g_fwd_cur = NULL;


struct forwarding_t *fwd_get( void ) {
	return g_fwds;
}

int fwd_count( void ) {
	struct forwarding_t *cur;
	size_t count;

	count = 0;
	cur = g_fwds;
	while( cur ) {
		count++;
		cur = cur->next;
	}

	return count;
}

void fwd_debug( int fd ) {
	struct forwarding_t *cur;
	char refreshed[64];
	char lifetime[64];
	time_t now;
	size_t counter;

	now = time_now_sec();
	counter = 0;
	cur = g_fwds;
	while( cur ) {
		if( cur->refreshed == 0 ) {
			sprintf( refreshed, "never" );
		} else {
			sprintf( refreshed, "%ld [min]", (now - cur->refreshed) / 60 );
		}

		if( cur->lifetime == LONG_MAX ) {
			sprintf( lifetime, "infinite" );
		} else {
			sprintf( lifetime, "%ld [min]", (cur->lifetime -  now) / 60 );
		}

		dprintf( fd, " port: %hu\n", cur->port );
		dprintf( fd, "  refreshed ago: %s\n", refreshed );
		dprintf( fd, "  lifetime remaining: %s\n", lifetime );

		counter++;
		cur = cur->next;
	}

	dprintf( fd, " Found %d forwardings.\n", counter );
}

void fwd_add( int port, time_t lifetime ) {
	struct forwarding_t *cur;
	struct forwarding_t *new;

	if( port <= 1 || port > 65535 ) {
		return;
	}

	cur = g_fwds;
	while( cur ) {
		if( cur->port == port ) {
			cur->lifetime = lifetime;
			return;
		}
		cur = cur->next;
	}

	new = (struct forwarding_t*) calloc( 1, sizeof(struct forwarding_t) );
	new->port = port;
	new->lifetime = lifetime;
	new->refreshed = 0;
	new->next = g_fwds;

	g_fwds = new;
	g_fwd_retry = 0; /* Trigger quick handling */
}

/* Remove a port from the list - internal use only */
void fwd_remove( struct forwarding_t *item ) {
	struct forwarding_t *pre;
	struct forwarding_t *cur;

	if( g_fwd_cur == item ) {
		g_fwd_cur = NULL;
	}

	pre = NULL;
	cur = g_fwds;
	while( cur ) {
		if( cur == item ) {
			if( pre ) {
				pre->next = cur->next;
			} else {
				g_fwds = cur->next;
			}
			free( cur );
			return;
		}
		pre = cur;
		cur = cur->next;
	}
}

/*
* Try to add a port forwarding to a router.
* We do not actually check if we are in a private network.
* This function is called in intervals.
*/
void fwd_handle( int _rc, int _sock ) {
	struct forwarding_t *item;
	int rc;
	time_t lifespan;
	time_t now;

	now = time_now_sec();
	item = g_fwd_cur;

	/* Handle current forwarding entry or wait 60 seconds to select a new one to process */
	if( item == NULL ) {
		if( g_fwd_retry > now ) {
			return;
		} else {
			item = g_fwds;
			g_fwd_retry = now + (1 * 60);
		}
	}

	while( item ) {
		if( (item->refreshed + (30 * 60)) < now ) {
			break;
		}
		item = item->next;
	}

	if( item == NULL ) {
		g_fwd_cur = NULL;
		return;
	} else {
		g_fwd_cur = item;
	}

	if( item->lifetime < now ) {
		lifespan = 0;
	} else {
		lifespan = (32 * 60);
	}

#ifdef FWD_NATPMP
	if( natpmp ) {
		rc = natpmp_handler( natpmp, item->port, lifespan, now );

		if( rc == PF_DONE ) {
			if( lifespan == 0 ) {
				log_debug( "FWD: Remove NAT-PMP forwarding for port %hu.", item->port );
				fwd_remove( item );
			} else {
				log_debug( "FWD: Add NAT-PMP forwarding for port %hu.", item->port );
				item->refreshed = now;
			}
			return;
		} else if( rc == PF_ERROR ) {
			log_info("FWD: Disable NAT-PMP - not available.");
			natpmp_uninit( &natpmp );
		} else if( rc == PF_RETRY ) {
			//return;
		} else {
			log_err( "FWD: Unhandled NAT-PMP reply." );
		}
	}
#endif

#ifdef FWD_UPNP
	if( upnp ) {
		rc = upnp_handler( upnp, item->port, lifespan, now );

		if( rc == PF_DONE ) {
			if( lifespan == 0 ) {
				log_debug( "FWD: Remove UPnP forwarding for port %hu.", item->port );
				fwd_remove( item );
			} else {
				log_debug( "FWD: Add UPnP forwarding for port %hu.", item->port );
				item->refreshed = now;
			}
			return;
		} else if( rc == PF_ERROR ) {
			log_info("FWD: Disable UPnP - not available.");
			upnp_uninit( &upnp );
		} else if( rc == PF_RETRY ) {
			//return;
		} else {
			log_err( "FWD: Unhandled UPnP reply." );
		}
	}
#endif
}

void fwd_setup( void ) {
	if( gconf->fwd_disable == 1 ) {
		return;
	}

#ifdef FWD_NATPMP
	log_info("FWD: Enable NAT-PMP.");
	natpmp_init( &natpmp );
#endif
#ifdef FWD_UPNP
	log_info("FWD: Enable UPnP.");
	upnp_init( &upnp );
#endif

	/* Add a port forwarding for the DHT for the entire run time */
	int port = atoi( gconf->dht_port );
	fwd_add( port, LONG_MAX );

	/* Cause the callback to be called in intervals */
	net_add_handler( -1, &fwd_handle );
}

void fwd_free( void ) {
	struct forwarding_t *cur;
	struct forwarding_t *next;

	cur = g_fwds;
	while( cur ) {
		next = cur->next;
		free( cur );
		cur = next;
	}
	g_fwds = NULL;

#ifdef FWD_NATPMP
	natpmp_uninit( &natpmp );
#endif
#ifdef FWD_UPNP
	upnp_uninit( &upnp );
#endif
}
