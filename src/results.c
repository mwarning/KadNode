
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

static struct results_t *g_results = NULL;
static int g_results_num = 0;
static time_t g_results_expire = 0;

struct results_t* results_get( void ) {
	return g_results;
}

/* Find a value search result */
struct results_t *results_find( const UCHAR id[] ) {
	struct results_t *results;

	results = g_results;
	while( results != NULL ) {
		if( id_equal( results->id, id ) ) {
			return results;
		}
		results = results->next;
	}

	return NULL;
}

int results_count( struct results_t *results ) {
	struct result_t *result;
	int count;

	count = 0;
	result = results->entries;
	while( result ) {
		count++;
		result = result->next;
	}
	return count;
}

/* Free a results_t item and all its result_t entries */
void results_free( struct results_t *results ) {
	struct result_t *cur;
	struct result_t *next;

	cur = results->entries;
	while( cur ) {
		next = cur->next;
		free( cur );
		cur = next;
	}

	free( results );
}

void results_debug( int fd ) {
	char buf[256+1];
	struct results_t *results;
	struct result_t *result;
	int results_counter;
	int result_counter;

	results_counter = 0;
	results = g_results;
	dprintf( fd, "Received results:\n" );
	while( results != NULL ) {
		dprintf( fd, " id: %s\n", str_id( results->id, buf ) );
		dprintf( fd, "  done: %d\n", results->done );
		result_counter = 0;
		result = results->entries;
		while( result ) {
			dprintf( fd, "   addr: %s\n", str_addr( &result->addr, buf ) );
			result = result->next;
		}
		dprintf( fd, "  Found %d results.\n", result_counter );
		results_counter++;
		results = results->next;
	}
	dprintf( fd, " Found %d result buckets.\n", results_counter );
}

void results_expire( void ) {
	struct results_t *pre;
	struct results_t *next;
	struct results_t *results;
	time_t now;

	now = time_now_sec();
	pre = NULL;
	next = NULL;
	results = g_results;
    while( results ) {
        next = results->next;
        if( results->start_time < (now - MAX_SEARCH_LIFETIME) ) {
            if( pre ) {
                pre->next = next;
            } else {
                g_results = next;
			}
			results_free( results );
			g_results_num--;
        } else {
            pre = results;
        }
        results = next;
    }
}

int results_add( const UCHAR id[], const char query[] ) {
	struct results_t* new;
	struct results_t* results;

	if( g_results_num > MAX_SEARCHES ) {
		return -1;
	}

	/* Search already exists */
	if( (results = results_find( id )) != NULL ) {
		results->start_time = time_now_sec();
		results->done = 0;
		return 0;
	}

	new = calloc( 1, sizeof(struct results_t) );
	memcpy( new->id, id, SHA1_BIN_LENGTH );
	new->start_time = time_now_sec();
	g_results_num++;

	results = g_results;
	while( results ) {
		if( results->next == NULL ) {
			break;
		}
		results = results->next;
	}

	/* Append new search */
	if( results ) {
		results->next = new;
	} else {
		g_results = new;
	}

	return 0;
}

/* Add an address to an array if it is not already contained in there */
void results_add_addr( struct results_t *results, IP* addr ) {
	struct result_t *result;
	struct result_t *new;

	if( results_count( results ) > MAX_RESULTS_PER_SEARCH ) {
		return;
	}

	result = results->entries;
	while( result ) {
		if( addr_equal( &result->addr, addr ) ) {
			return;
		}

		if( result->next == NULL ) {
			break;
		}

		result = result->next;
	}

	new = calloc( 1, sizeof(struct result_t) );
	memcpy( &new->addr, addr, sizeof(IP) );

	if( result ) {
		result->next = new;
	} else {
		results->entries = new;
	}
}

typedef struct {
	unsigned char addr[16];
	unsigned short port;
} dht_addr6_t;

typedef struct {
	unsigned char addr[4];
	unsigned short port;
} dht_addr4_t;

int results_import( const UCHAR id[], void *data, size_t data_length ) {
	struct results_t *results;
	IP addr;
	size_t i;

	/* Find search to put results into */
	if( (results = results_find( id )) == NULL ) {
		return -1;
	}

	if( results->done == 1 ) {
		return -1;
	}

	if( results_count( results ) > MAX_RESULTS_PER_SEARCH ) {
		return -1;
	}

	if( gconf->af == AF_INET ) {
		dht_addr4_t *data4 = (dht_addr4_t *) data;
		IP4 *a = (IP4 *)&addr;

		for( i = 0; i < (data_length / sizeof(dht_addr4_t)); i++ ) {
			memset( &addr, '\0', sizeof(IP) );
			a->sin_family = AF_INET;
			a->sin_port = data4[i].port;
			memcpy( &a->sin_addr, &data4[i].addr, 4 );
			results_add_addr( results, &addr );
		}
		return 0;
	}

	if( gconf->af == AF_INET6) {
		dht_addr6_t *data6 = (dht_addr6_t *) data;
		IP6 *a = (IP6 *)&addr;

		for( i = 0; i < (data_length / sizeof(dht_addr6_t)); i++ ) {
			memset( &addr, '\0', sizeof(IP) );
			a->sin6_family = AF_INET6;
			a->sin6_port = data6[i].port;
			memcpy( &a->sin6_addr, &data6[i].addr, 16 );
			results_add_addr( results, &addr );
		}
		return 0;
	}

	return -1;
}

int results_done( const UCHAR id[] ) {
	struct results_t *results;

	/* Find search to put results into */
	if( (results = results_find( id )) == NULL ) {
		return -1;
	}

	results->done = 1;
	return 0;
}

int results_collect( const UCHAR id[], IP addr_array[], size_t addr_num ) {
	struct results_t *results;
	struct result_t *result;
	size_t i;

	results = results_find( id );
	if( results == NULL ) {
		return -1;
	}

	i = 0;
	result = results->entries;
	while( result && i < addr_num ) {
		memcpy( &addr_array[i], &result->addr, sizeof(IP) );
		i++;
		result = result->next;
	}

	return i;
}

void results_handle( int _rc, int _sock ) {
	/* Expire value search results */
	if( g_results_expire <= time_now_sec() ) {
		results_expire();

		/* Try again in ~2 minutes */
		g_results_expire = time_add_min( 2 );
	}
}

void results_setup( void ) {
	net_add_handler( -1, &results_handle );
}
