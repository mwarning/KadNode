
#define _WITH_DPRINTF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "log.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#ifdef BOB
#include "ext-bob.h"
#endif
#ifdef TLS
#include "ext-tls-client.h"
#endif
#include "announces.h"


// Announce values every 20 minutes
#define ANNOUNCES_INTERVAL (20*60)


static time_t g_announces_expire = 0;
static time_t g_announces_announce = 0;
static struct value_t *g_values = NULL;


struct value_t* announces_get( void ) {
	return g_values;
}

struct value_t* announces_find( const uint8_t id[] ) {
	struct value_t *value;

	value = g_values;
	while( value ) {
		if( id_equal( id, value->id ) ) {
			return value;
		}
		value = value->next;
	}
	return NULL;
}

void announces_debug( int fd ) {
	struct value_t *value;
	time_t now;
	int value_counter;

	now = time_now_sec();
	value_counter = 0;
	value = g_values;
	dprintf( fd, "Announcements:\n" );
	while( value ) {
		dprintf( fd, " id: %s\n", str_id( value->id ) );
		dprintf( fd, "  port: %d\n", value->port );
		if( value->refresh < now ) {
			dprintf( fd, "  refresh: now\n" );
		} else {
			dprintf( fd, "  refresh: in %ld min\n", (value->refresh - now) / 60 );
		}

		if( value->lifetime == LONG_MAX ) {
			dprintf( fd, "  lifetime: entire runtime\n" );
		} else {
			dprintf( fd, "  lifetime: %ld min left\n", (value->lifetime -  now) / 60 );
		}

		value_counter++;
		value = value->next;
	}

	dprintf( fd, " Found %d entries.\n", value_counter );
}

// Announce a sanitzed query
struct value_t *announces_add( const char query[], int port, time_t lifetime ) {
	uint8_t id[SHA1_BIN_LENGTH];
	struct value_t *cur;
	struct value_t *new;
	int ret = 0;
	time_t now = time_now_sec();

	// Get id from query
#ifdef BOB
	if( ret == 0 ) {
		ret = bob_get_id( id, sizeof(id), query );
	}
#endif

#ifdef TLS
	if( ret == 0 ) {
		ret = tls_client_get_id( id, sizeof(id), query );
	}
#endif

	if( ret == 0 ) {
		ret = hex_get_id( id, sizeof(id), query );
	}

	if( ret == 0 || port < 1 || port > 65535 || lifetime < now ) {
		log_err( "Invalid announcement: %s (port %d)", query, port );
		return NULL;
	}

	// Value already exists - refresh
	if( (cur = announces_find( id )) != NULL ) {
		cur->refresh = now - 1;

		if( lifetime > now ) {
			cur->lifetime = lifetime;
		}

		// Trigger immediate handling
		g_announces_announce = 0;

		return cur;
	}

	// Prepend new entry
	new = (struct value_t*) calloc( 1, sizeof(struct value_t) );
	memcpy( new->id, id, SHA1_BIN_LENGTH );
	new->port = port;
	new->refresh = now - 1; // Send first announcement as soon as possible
	new->lifetime = lifetime;

	if( lifetime == LONG_MAX ) {
		log_debug( "Add announcement for %s (%s:%hu). Update for entire runtime.", query, str_id( id ), port );
	} else {
		log_debug( "Add announcement for %s (%s:%hu). Update for %lu minutes.", query, str_id( id ), port, (lifetime - now) / 60 );
	}

	// Prepend to list
	new->next = g_values;
	g_values = new;

	// Trigger immediate handling
	g_announces_announce = 0;

	return new;
}

void value_free( struct value_t *value ) {
	free( value );
}

static void announces_expire( void ) {
	struct value_t *pre;
	struct value_t *cur;
	time_t now;

	now = time_now_sec();
	pre = NULL;
	cur = g_values;
	while( cur ) {
		if( cur->lifetime < now ) {
			if( pre ) {
				pre->next = cur->next;
			} else {
				g_values = cur->next;
			}
			value_free( cur );
			return;
		}
		pre = cur;
		cur = cur->next;
	}
}

static void announces_announce( void ) {
	struct value_t *value;
	time_t now;

	now = time_now_sec();
	value = g_values;
	while( value ) {
		if( value->refresh < now ) {
#ifdef DEBUG
			log_debug( "Announce %s:%hu",  str_id( value->id ), value->port );
#endif
			kad_announce_once( value->id, value->port );
			value->refresh = now + ANNOUNCES_INTERVAL;
		}
		value = value->next;
	}
}

static void announces_handle( int _rc, int _sock ) {
	// Expire search results
	if( g_announces_expire <= time_now_sec() ) {
		announces_expire();

		// Try again in ~1 minute
		g_announces_expire = time_add_mins( 1 );
	}

	if( g_announces_announce <= time_now_sec() && kad_count_nodes( 0 ) != 0 ) {
		announces_announce();

		// Try again in ~1 minute
		g_announces_announce = time_add_mins( 1 );
	}
}

void announces_setup( void ) {
	// Cause the callback to be called in intervals
	net_add_handler( -1, &announces_handle );
}

void announces_free( void ) {
	struct value_t *cur;
	struct value_t *next;

	cur = g_values;
	while( cur ) {
		next = cur->next;
		value_free( cur );
		cur = next;
	}
	g_values = NULL;
}
