
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "main.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "results.h"


/*
* The DHT implementation in KadNode does not store
* results from value searches. Therefore, results for value
* searches are collected and stored here until they expire.
*/

struct results_t *results = NULL;
int num_results = 0;


struct results_t *results_list( void ) {
	return results;
}

/* Find a value search result */
struct results_t *results_find( const UCHAR *id, int af ) {
	struct results_t *rs;

	rs = results;
	while( rs != NULL ) {
		if(  id_equal( rs->id, id ) && rs->af == af ) {
			return rs;
		}
		rs = rs->next;
	}

	return NULL;
}

int results_count( struct results_t *rs ) {
	struct result_t *result;
	int count;

	count = 0;
	result = rs->entries;
	while( result ) {
		count++;
		result = result->next;
	}
	return count;
}

/* Free a results_t item and all its result_t entries */
void results_free( struct results_t *rs ) {
	struct result_t *cur;
	struct result_t *next;

	cur = rs->entries;
	while( cur ) {
		next = cur->next;
		free( cur );
		cur = next;
	}

	free( rs );
}

struct results_t * results_new( const UCHAR *id, int af ) {
	struct results_t *new;

	new = calloc( 1, sizeof(struct results_t) );

	memcpy( new->id, id, SHA_DIGEST_LENGTH );
	new->af = af;
	new->start_time = time_now_sec();

	return new;
}

void results_expire( void ) {
	struct results_t *pre = NULL;
	struct results_t *rs = results;
	struct results_t *next = NULL;

    while( rs ) {
        next = rs->next;
        if( rs->start_time < (time_now_sec() - EXPIRE_SEARCH) ) {
            if( pre ) {
                pre->next = next;
            } else {
                results = next;
			}
			results_free( rs );
			num_results--;
        } else {
            pre = rs;
        }
        rs = next;
    }
}

int results_insert( const UCHAR *id, int af ) {
	struct results_t* new;
	struct results_t* rs;

	if( num_results > MAX_SEARCHES ) {
		return 1;
	}

	/* Search already exists */
	if( results_find( id, af ) != NULL ) {
		return 0;
	}

	new = results_new( id, af );
	num_results++;

	rs = results;
	while( rs ) {
		if( rs->next == NULL ) {
			break;
		}
		rs = rs->next;
	}

	/* Append new search */
	if( rs ) {
		rs->next = new;
	} else {
		results = new;
	}

	return 1;
}

struct result_t *result_new( IP* addr ) {
	struct result_t *new;

	new = calloc( 1, sizeof(struct result_t) );
	memcpy( &new->addr, addr, sizeof(IP) );

	return new;
}

/* Add an address to an array if it is not already contained in there */
void results_add_unique( struct results_t *rs, IP* addr ) {
	struct result_t *result;
	struct result_t *new;

	if( results_count( rs ) > MAX_RESULTS_PER_SEARCH ) {
		return;
	}

	result = rs->entries;
	while( result ) {
		if( addr_equal( &result->addr, addr ) ) {
			return;
		}

		if( result->next == NULL ) {
			break;
		}

		result = result->next;
	}

	new = result_new( addr );

	if( result ) {
		result->next = new;
	} else {
		rs->entries = new;
	}
}

/* Structure of the compact data received from the DHT */
typedef struct {
	UCHAR addr[16];
	unsigned short port;
} addr6_t;

typedef struct {
	UCHAR addr[4];
	unsigned short port;
} addr4_t;

void results_import( const UCHAR *id, void *data, int data_length, int af ) {
	struct results_t *rs;
	IP addr;
	int i;

	/* Find search to put results into */
	if( (rs = results_find( id, af )) == NULL ) {
		return;
	}

	if( results_count( rs ) > MAX_RESULTS_PER_SEARCH ) {
		return;
	}

	if( af == AF_INET ) {
		addr4_t *data4 = (addr4_t *) data;
		IP4 *a = (IP4 *)&addr;

		for( i = 0; i < (data_length / sizeof(addr4_t)); i++ ) {
			memset( &addr, '\0', sizeof(IP) );
			a->sin_family = AF_INET;
			a->sin_port = data4[i].port;
			memcpy( &a->sin_addr, &data4[i].addr, 4 );
			results_add_unique( rs, &addr );
		}
	}

	if( af == AF_INET6) {
		addr6_t *data6 = (addr6_t *) data;
		IP6 *a = (IP6 *)&addr;

		for( i = 0; i < (data_length / sizeof(addr6_t)); i++ ) {
			memset( &addr, '\0', sizeof(IP) );
			a->sin6_family = AF_INET6;
			a->sin6_port = data6[i].port;
			memcpy( &a->sin6_addr, &data6[i].addr, 16 );
			results_add_unique( rs, &addr );
		}
	}
}

void results_done( const UCHAR *id, int af ) {
	struct results_t *rs;

	/* Find search to put results into */
	if( (rs = results_find( id, af )) == NULL ) {
		return;
	}

	rs->done = 1;
}

void results_handle( int __rc, int __sock ) {
	/* Expire value search results */
	if( gstate->time_expire_results <= time_now_sec() ) {
		results_expire();

		/* Try again in ~2 minutes */
		gstate->time_expire_results = time_add_min( 2 );
	}
}

void results_setup( void ) {
	net_add_handler( -1, &results_handle );
}
