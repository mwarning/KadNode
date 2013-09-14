
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


struct announcement_t {
	UCHAR value_id[SHA_DIGEST_LENGTH];
	int port;
	time_t lifetime; /* keep entry until lifetime expires */
	time_t refreshed; /* last time the entry was refreshed */
	struct announcement_t *next;
};

struct values_t {
	time_t retry;
	struct announcement_t *beg;
};

struct values_t values = { .retry = 0, .beg = NULL };

int values_count( void ) {
	struct announcement_t *item;
	int count;

	count = 0;
	item = values.beg;
	while( item ) {
		item = item->next;
		count++;
	}

	return count;
}

void values_debug( int fd ) {
	char hexbuf[HEX_LEN+1];
	struct announcement_t *item;
	time_t refreshed; /* in minutes */
	time_t lifetime; /* in minutes */
	time_t now;

	now = gstate->time_now.tv_sec;
	item = values.beg;
	while( item ) {
		refreshed = (now - item->refreshed) / 60;
		lifetime = (item->lifetime -  now) / 60;
		dprintf( fd, " id: %s, port: %hu, refreshed: %ld min. ago, lifetime: %ld min. remaining\n",
			str_id( item->value_id, hexbuf ), item->port, refreshed, (lifetime == LONG_MAX) ? -1 : lifetime );
		item = item->next;
	}
}

void values_add( const UCHAR *value_id, USHORT port, time_t lifetime ) {
	struct announcement_t *cur;
	struct announcement_t *new;

	if( port == 0 ) {
		log_err("Announces: Port 0 is invalid.");
	}

	cur = values.beg;
	while( cur ) {
		if( id_equal( cur->value_id, value_id ) && cur->port == port ) {
			cur->lifetime = lifetime;
			return;
		}
		cur = cur->next;
	}

	new = (struct announcement_t*) malloc( sizeof(struct announcement_t) );
	memcpy( &new->value_id, value_id, SHA_DIGEST_LENGTH);
	new->port = port;
	new->lifetime = lifetime;
	new->refreshed = 0;
	new->next = values.beg;

	values.beg = new;
	values.retry = 0; //trigger an immediate handling
}

/* Remove a port from the list - internal use only */
void values_remove( struct announcement_t *item ) {
	struct announcement_t *pre;
	struct announcement_t *cur;

	pre = NULL;
	cur = values.beg;
	while( cur ) {
		if( cur == item ) {
			if( pre ) {
				pre->next = cur->next;
			} else {
				values.beg = cur->next;
			}
			free( cur );
			return;
		}
		pre = cur;
		cur = cur->next;
	}
}

void values_handle( int __rc, int __sock ) {
	struct announcement_t *item;
	time_t now;

	now = gstate->time_now.tv_sec;

	if( values.retry > now ) {
		return;
	} else {
		values.retry = now + (1 * 60);
	}

	item = values.beg;
	while( item ) {
		if( item->lifetime < now ) {
			values_remove( item );
			item = item->next;
			continue;
		}

		if( (item->refreshed + (30 * 60)) < now ) {
#ifdef DEBUG
			char hexbuf[HEX_LEN+1];
			log_debug( "VAL: Announce %s:%hu.",  str_id( item->value_id, hexbuf ), item->port );
#endif
			kad_announce( item->value_id, item->port );
			item->refreshed = now;
		}

		item = item->next;
	}
}

void values_setup( void ) {
	/* Cause the callback to be called in intervals */
	net_add_handler( -1, &values_handle );
}
