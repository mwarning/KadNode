
#define _WITH_DPRINTF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "main.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#ifdef AUTH
#include "ext-auth.h"
#endif
#include "results.h"


/*
* The DHT implementation in KadNode does not store
* results from value searches. Therefore, results for value
* searches are collected and stored here until they expire.
*/

static struct results_t *g_results[MAX_SEARCHES+1] = {NULL};
/* Index of next slot to be used */
static size_t g_results_idx = 0;

struct results_t** results_get( void ) {
	return &g_results[0];
}

/* Find a value search result */
struct results_t *results_find( const UCHAR id[] ) {
	struct results_t **results;
	struct results_t *bucket;

	results = results_get();
	while( *results != NULL ) {
		bucket = *results;
		if( id_equal( bucket->id, id ) ) {
			return bucket;
		}
		results++;
	}

	return NULL;
}

int results_entries_count( struct results_t *result ) {
	struct result_t *entry;
	int count;

	count = 0;
	entry = result->entries;
	while( entry ) {
#ifdef AUTH
		/* Omit unverified results */
		if( entry->challenge ) {
			entry = entry->next;
			continue;
		}
#endif
		count++;
		entry = entry->next;
	}

	return count;
}

/* Free a results_t item and all its result_t entries */
void results_item_free( struct results_t *bucket ) {
	struct result_t *cur;
	struct result_t *next;

	cur = bucket->entries;
	while( cur ) {
		next = cur->next;
#ifdef AUTH
		free( cur->challenge );
#endif
		free( cur );
		cur = next;
	}

#ifdef AUTH
	free( bucket->pkey );
#endif
	free( bucket );
}

void results_debug( int fd ) {
	char buf[256+1];
	struct results_t **results;
	struct results_t *bucket;
	struct result_t *result;
	int results_counter;
	int result_counter;

	results_counter = 0;
	results = results_get();
	dprintf( fd, "Result buckets:\n" );
	while( *results != NULL ) {
		bucket = *results;
		dprintf( fd, " id: %s\n", str_id( bucket->id, buf ) );
		dprintf( fd, "  done: %d\n", bucket->done );
#ifdef AUTH
		if( bucket->pkey ) {
			dprintf( fd, "  pkey: %s\n", bytes_to_hex( buf, bucket->pkey, crypto_sign_PUBLICKEYBYTES ) );
		}
#endif
		result_counter = 0;
		result = bucket->entries;
		while( result ) {
			dprintf( fd, "   addr: %s\n", str_addr_buf( &result->addr, buf ) );
#ifdef AUTH
			if( bucket->pkey ) {
				dprintf( fd, "    challenge: %s\n",  result->challenge ? bytes_to_hex( buf, result->challenge, CHALLENGE_BIN_LENGTH ) : "done" );
				dprintf( fd, "    challenges_send: %d\n", result->challenges_send );
			}
#endif
			result_counter++;
			result = result->next;
		}
		dprintf( fd, "  Found %d results.\n", result_counter );
		results_counter++;
		results++;
	}
	dprintf( fd, " Found %d result buckets.\n", results_counter );
}

/* Add a new bucket to collect results */
struct results_t* results_add( const char query[], int *is_new ) {
	char hexbuf[SHA1_HEX_LENGTH+1];
	UCHAR id[SHA1_BIN_LENGTH];
	struct results_t* new;
	struct results_t* results;

#ifdef AUTH
	UCHAR pkey[crypto_sign_PUBLICKEYBYTES];
	UCHAR *pkey_ptr = auth_handle_pkey( pkey, id, query );
#else
	id_compute( id, query );
#endif

	/* Search already exists */
	if( (results = results_find( id )) != NULL ) {
		*is_new = 0;
		return results;
	} else {
		*is_new = 1;
	}

	new = calloc( 1, sizeof(struct results_t) );
	memcpy( new->id, id, SHA1_BIN_LENGTH );
#ifdef AUTH
	if( pkey_ptr ) {
		new->pkey = memdup( pkey_ptr, crypto_sign_PUBLICKEYBYTES );
	}
#endif
	new->start_time = time_now_sec();

	log_debug( "Results: Add results bucket for query '%s', id '%s'.", query, str_id( id, hexbuf ) );

	/* Free slot if taken */
	if( g_results[g_results_idx] != NULL ) {
		results_item_free( g_results[g_results_idx] );
	}

	g_results[g_results_idx] = new;
	g_results_idx = (g_results_idx + 1) % MAX_SEARCHES;

	return new;
}

/* Add an address to an array if it is not already contained in there */
int results_add_addr( struct results_t *results, const IP *addr ) {
	struct result_t *result;
	struct result_t *new;

	if( results->done == 1 ) {
		return -1;
	}

	if( results_entries_count( results ) > MAX_RESULTS_PER_SEARCH ) {
		return -1;
	}

	/* Check if result already exists */
	result = results->entries;
	while( result ) {
		if( addr_equal( &result->addr, addr ) ) {
			return 0;
		}

		if( result->next == NULL ) {
			break;
		}

		result = result->next;
	}

	new = calloc( 1, sizeof(struct result_t) );
	memcpy( &new->addr, addr, sizeof(IP) );
#ifdef AUTH
	if( results->pkey ) {
		/* Create a new challenge if needed */
		new->challenge = calloc( 1, CHALLENGE_BIN_LENGTH );
		bytes_random( new->challenge, CHALLENGE_BIN_LENGTH );
	}
#endif

	/* Append new entry */
	if( result ) {
		result->next = new;
	} else {
		results->entries = new;
	}

	return 0;
}

int results_done( struct results_t *results, int done ) {
	if( done ) {
		results->done = 1;
		/* Remove search if no results have been found */
		/*
		if( results_entries_count( results ) == 0 ) {
			results_remove( results );
		}*/
	} else {
		results->start_time = time_now_sec();
		results->done = 0;
	}
	return 0;
}

int results_collect( struct results_t *results, IP addr_array[], size_t addr_num ) {
	struct result_t *result;
	size_t i;

	if( results == NULL ) {
		return 0;
	}

	i = 0;
	result = results->entries;
	while( result && i < addr_num ) {
#ifdef AUTH
		/* If there is a challenge - then the address is not verified yet */
		if( results->pkey && result->challenge ) {
			result = result->next;
			continue;
		}
#endif
		memcpy( &addr_array[i], &result->addr, sizeof(IP) );
		i++;
		result = result->next;
	}

	return i;
}


void results_setup( void ) {
	/* Nothing to do */
}

void results_free( void ) {
	struct results_t **results;

	results = results_get();
	while( *results != NULL ) {
		results_item_free( *results );
		*results = NULL;
		results++;
	}
}
