
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "log.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#include "values.h"


static time_t g_values_expire = 0;
static struct value_t *g_values = NULL;

struct value_t* values_get( void ) {
	return g_values;
}

int values_count( void ) {
	struct value_t *value;
	int count;

	count = 0;
	value = g_values;
	while( value ) {
		count++;
		value = value->next;
	}

	return count;
}

void values_debug( int fd ) {
	char hexbuf[256+1];
	struct value_t *value;
	time_t now;
	int value_counter;

	now = time_now_sec();
	value_counter = 0;
	value = g_values;
	dprintf( fd, "Announced values:\n" );
	while( value ) {
		dprintf( fd, " id: %s\n", str_id( value->id, hexbuf ) );
		dprintf( fd, "  port: %d\n", value->port );
		if( value->refreshed == -1 ) {
			dprintf( fd, "  refreshed ago: never\n" );
		} else {
			dprintf( fd, "  refreshed: %ld min ago\n", (now - value->refreshed) / 60 );
		}

		if( value->lifetime == LONG_MAX ) {
			dprintf( fd, "  lifetime: infinite\n" );
		} else {
			dprintf( fd, "  lifetime: %ld min left\n", (value->lifetime -  now) / 60 );
		}

		value_counter++;
		value = value->next;
	}

	dprintf( fd, " Found %d values.\n", value_counter );
}

void values_add( const char query[], int port, time_t lifetime ) {
	UCHAR id[SHA1_BIN_LENGTH];
	char hexbuf[SHA1_HEX_LENGTH+1];
	struct value_t *cur;
	struct value_t *new;

	if( port < 1 || port > 65535 ) {
		log_err("Announces: Port 0 is invalid.");
	}

	id_compute( id, query );

	log_debug( "VAL: Add value id %s:%hu.",  str_id( id, hexbuf ), port );

	cur = g_values;
	while( cur ) {
		if( id_equal( cur->id, id ) && cur->port == port ) {
			cur->lifetime = lifetime;
			cur->refreshed = 0;
			return;
		}
		cur = cur->next;
	}

	new = (struct value_t*) calloc( 1, sizeof(struct value_t) );
	memcpy( &new->id, id, SHA1_BIN_LENGTH );
	new->port = port;
	new->lifetime = lifetime;
	new->refreshed = 0;
	new->next = g_values;

	g_values = new;
	g_values_expire = 0; /* Trigger an immediate handling */
}

/* Remove a port from the list - internal use only */
void values_remove( struct value_t *value ) {
	struct value_t *pre;
	struct value_t *cur;

	pre = NULL;
	cur = g_values;
	while( cur ) {
		if( cur == value ) {
			if( pre ) {
				pre->next = cur->next;
			} else {
				g_values = cur->next;
			}
			free( cur );
			return;
		}
		pre = cur;
		cur = cur->next;
	}
}

void values_expire( void ) {
	struct value_t *value;
	time_t now;

	now = time_now_sec();
	value = g_values;
	while( value ) {
		if( value->lifetime < now ) {
			values_remove( value );
			value = value->next;
			continue;
		}

		if( (value->refreshed + (30 * 60)) < now ) {
#ifdef DEBUG
			char hexbuf[SHA1_HEX_LENGTH+1];
			log_debug( "VAL: Announce %s:%hu",  str_id( value->id, hexbuf ), value->port );
#endif
			kad_announce( value->id, value->port );
			value->refreshed = now;
		}

		value = value->next;
	}
}

void values_handle( int _rc, int _sock ) {
	/* Expire search results */
	if( g_values_expire <= time_now_sec() ) {
		values_expire();

		/* Try again in ~1 minute */
		g_values_expire = time_add_min( 1 );
	}
}

void values_setup( void ) {
	/* Cause the callback to be called in intervals */
	net_add_handler( -1, &values_handle );
}
