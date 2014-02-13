
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "log.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#ifdef AUTH
#include "ext-auth.h"
#endif
#include "values.h"


static time_t g_values_expire = 0;
static time_t g_values_announce = 0;
static struct value_t *g_values = NULL;

struct value_t* values_get( void ) {
	return g_values;
}

struct value_t* values_find( UCHAR id[] ) {
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
	char hexbuf[SHA1_HEX_LENGTH+1];
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
		if( value->refresh < now ) {
			dprintf( fd, "  refresh: now\n" );
		} else {
			dprintf( fd, "  refresh: in %ld min\n", (value->refresh - now) / 60 );
		}

		if( value->lifetime == LONG_MAX ) {
			dprintf( fd, "  lifetime: infinite\n" );
		} else {
			dprintf( fd, "  lifetime: %ld min left\n", (value->lifetime -  now) / 60 );
		}

#ifdef AUTH
		if( value->skey ) {
			char sbuf[2*crypto_sign_SECRETKEYBYTES+1];
			dprintf( fd, "  skey: %s\n", auth_str_skey( sbuf, value->skey ) );
			dprintf( fd, "  (pkey: %s)\n", auth_str_pkey( sbuf, value->skey + crypto_sign_PUBLICKEYBYTES ) );
		}
#endif

		value_counter++;
		value = value->next;
	}

	dprintf( fd, " Found %d values.\n", value_counter );
}

int values_add( const char query[], int port, time_t lifetime ) {
	UCHAR id[SHA1_BIN_LENGTH];
	char hexbuf[SHA1_HEX_LENGTH+1];
	struct value_t *cur;
	struct value_t *new;

	if( port < 1 || port > 65535 ) {
		return -1;
	}

#ifdef AUTH
	UCHAR *skey = NULL;
	if( auth_is_skey( query ) ) {
		if( port != atoi( gconf->dht_port ) ) {
			return -1;
		}
		skey = auth_parse_skey( query );
		/*
		* Since the ID is based on the sha1 hash of the public key,
		* we need to convert the secret key to the public key in hex.
		* This is easy because the public key is in the second
		* half of the secret key string for libsodium.
		*/
		query += 2*crypto_sign_PUBLICKEYBYTES;
	}
#endif

	id_compute( id, query );

	log_debug( "VAL: Add value id %s:%hu.",  str_id( id, hexbuf ), port );

	/* Update only if entry exists */
	cur = g_values;
	while( cur ) {
		if( id_equal( cur->id, id ) && cur->port == port ) {
			cur->lifetime = lifetime;
			cur->refresh = time_now_sec() - 1;
			return 0;
		}

		cur = cur->next;
	}

	/* Prepend new entry */
	new = (struct value_t*) calloc( 1, sizeof(struct value_t) );
	memcpy( &new->id, id, SHA1_BIN_LENGTH );
#ifdef AUTH
	new->skey = skey;
#endif
	new->port = port;
	new->lifetime = lifetime;
	new->refresh = time_now_sec() - 1;
	new->next = g_values;

	g_values = new;

	/* Trigger immediate handling */
	g_values_announce= 0;

	return 0;
}

/* Remove an element from the list - internal use only */
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
#ifdef AUTH
			free( cur->skey );
#endif
			free( cur );
			return;
		}
		pre = cur;
		cur = cur->next;
	}
}

void values_expire( void ) {
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
#ifdef AUTH
			free( cur->skey );
#endif
			free( cur );
			return;
		}
		pre = cur;
		cur = cur->next;
	}
}

void values_announce( void ) {
	struct value_t *value;
	time_t now;

	now = time_now_sec();
	value = g_values;
	while( value ) {
		if( value->refresh < now ) {
#ifdef DEBUG
			char hexbuf[SHA1_HEX_LENGTH+1];
			log_debug( "VAL: Announce %s:%hu",  str_id( value->id, hexbuf ), value->port );
#endif
			kad_announce( value->id, value->port );
			value->refresh = now + (30 * 60);
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

	if( g_values_announce <= time_now_sec() && kad_count_nodes() != 0 ) {
		values_announce();

		/* Try again in ~1 minute */
		g_values_announce = time_add_min( 1 );
	}
}

void values_setup( void ) {
	/* Cause the callback to be called in intervals */
	net_add_handler( -1, &values_handle );
}
