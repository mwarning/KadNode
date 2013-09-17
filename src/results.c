
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "main.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "results.h"

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

/*
* The DHT implementation in KadNode does not store
* results from value searches. Therefore, results for value
* searches are collected and stored here until they expire.
*/

struct result_t *results = NULL;
int num_results = 0;


struct result_t *results_list( void ) {
	return results;
}

/* Find a value search result */
struct result_t *results_find( const UCHAR *id, int af ) {
	struct result_t *vs;

	vs = results;
	while( vs != NULL ) {
		if(  id_equal( vs->id, id ) && vs->af == af ) {
			return vs;
		}
		vs = vs->next;
	}

	return NULL;
}

void results_expire( void ) {
	struct result_t *pre = NULL;
	struct result_t *vs = results;
	struct result_t *next = NULL;

    while( vs ) {
        next = vs->next;
        if( vs->start_time < (time_now_sec() - EXPIRE_SEARCH) ) {
            if( pre ) {
                pre->next = next;
            } else {
                results = next;
			}
			free( vs );
			num_results--;
        } else {
            pre = vs;
        }
        vs = next;
    }
}

int results_insert( const UCHAR *id, int af ) {
	struct result_t* vs;
	struct result_t* vss;

	if( num_results > MAX_SEARCHES ) {
		return 1;
	}

	vs = results_find( id, af );

	/* Search exists */
	if( vs != NULL ) {
		return 0;
	}

	vs = calloc( 1, sizeof(struct result_t) );
	if( vs == NULL ) {
		return 0;
	}

	memcpy( vs->id, id, SHA_DIGEST_LENGTH );
	vs->af = af;
	vs->start_time = time_now_sec();

	num_results++;

	if( results == NULL ) {
		results = vs;
		return 1;
	}

	vss = results;
	while( 1 ) {
		if( vss->next == NULL ) {
			vss->next = vs;
			return 1;
		}
		vss = vss->next;
	}

	return 1;
}

/* Add an address to an array if it is not already contained in there */
void results_add_unique( struct result_t *vs, IP* addr ) {
	int i;

	if( vs->numaddrs >= MAX_RESULTS_PER_SEARCH ) {
		return;
	}

	for( i = 0; i < vs->numaddrs; i++ ) {
		if( addr_equal( &vs->addrs[i], addr ) ) {
			return;
		}
	}

	memcpy( &vs->addrs[vs->numaddrs], addr, sizeof(IP) );
	vs->numaddrs++;
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
	struct result_t *vs;
	IP addr;
	int i;

	/* Find search to put results into */
	if( (vs = results_find( id, af )) == NULL ) {
		return;
	}

	if( af == AF_INET ) {
		addr4_t *data4 = (addr4_t *) data;
		size_t data4_len = MIN(data_length / sizeof(addr4_t), MAX_RESULTS_PER_SEARCH);
		IP4 *a = (IP4 *)&addr;

		for( i = 0; i < data4_len; i++ ) {
			memset( &addr, '\0', sizeof(IP) );
			a->sin_family = AF_INET;
			a->sin_port = data4[i].port;
			memcpy( &a->sin_addr, &data4[i].addr, 4 );
			results_add_unique( vs, &addr );
		}
	}

	if( af == AF_INET6) {
		addr6_t *data6 = (addr6_t *) data;
		size_t data6_len = MIN(data_length / sizeof(addr6_t), MAX_RESULTS_PER_SEARCH);
		IP6 *a = (IP6 *)&addr;

		for( i = 0; i < data6_len; i++ ) {
			memset( &addr, '\0', sizeof(IP) );
			a->sin6_family = AF_INET6;
			a->sin6_port = data6[i].port;
			memcpy( &a->sin6_addr, &data6[i].addr, 16 );
			results_add_unique( vs, &addr );
		}
	}
}

void results_done( const UCHAR *id, int af ) {
	struct result_t *vs;

	/* Find search to put results into */
	if( (vs = results_find( id, af )) == NULL ) {
		return;
	}

	vs->done = 1;
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
