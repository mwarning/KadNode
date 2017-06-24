
#define _WITH_DPRINTF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "log.h"
#include "main.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#ifdef BOB
#include "ext-bob.h"
#endif
#ifdef TLS
#include "ext-tls-client.h"
#endif
#include "results.h"


/*
* The DHT implementation in KadNode does not store
* results (IP addresses) from hash searches.
* Therefore, results are collected and stored here.
*/

// A ring buffer for of all searches
static struct results_t *g_results[MAX_SEARCHES] = { NULL };
static size_t g_results_idx = 0;


const char *str_state( int state ) {
	switch( state ) {
	    case AUTH_OK: return "OK";
	    case AUTH_FAILED: return "FAILED";
	    case AUTH_ERROR: return "ERROR";
	    case AUTH_SKIP: return "SKIP";
	    case AUTH_PROGRESS: return "PROGRESS";
	    case AUTH_WAITING: return "WAITING";
	    default: return "???";
	}
}

// External access to all current results
struct results_t** results_get( void ) {
	return &g_results[0];
}

// Find a value search result
struct results_t *results_find( const char query[] ) {
	struct results_t **results;
	struct results_t *bucket;

	results = &g_results[0];
	while( *results ) {
		bucket = *results;
		if( strcmp( query, bucket->query ) == 0 ) {
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
		count++;
		entry = entry->next;
	}

	return count;
}

// Free a results_t item and all its result_t entries
void results_item_free( struct results_t *bucket ) {
	struct result_t *cur;
	struct result_t *next;

	cur = bucket->entries;
	while( cur ) {
		next = cur->next;
		free( cur );
		cur = next;
	}

	free( bucket->query );
	free( bucket );
}

void results_debug( int fd ) {
	struct results_t **results;
	struct results_t *bucket;
	struct result_t *result;
	int results_counter;
	int result_counter;

	results_counter = 0;
	results = &g_results[0];
	dprintf( fd, "Result buckets:\n" );
	while( *results ) {
		bucket = *results;
		dprintf( fd, " id: %s\n", str_id( bucket->id ) );
		//dprintf( fd, "  done: %d\n", bucket->done );
		result_counter = 0;
		result = bucket->entries;
		while( result ) {
			dprintf( fd, "   addr: %s\n", str_addr( &result->addr ) );
			dprintf( fd, "   state: %s\n", str_state( result->state ) );
			result_counter++;
			result = result->next;
		}
		dprintf( fd, "  Found %d results.\n", result_counter );
		results_counter++;
		results++;
	}
	dprintf( fd, " Found %d result buckets.\n", results_counter );
}

// Add a new bucket to collect results
// The query is expected to be sanitized (lower case and without query TLS)
struct results_t* results_add( const char query[], int *is_new ) {
	uint8_t id[SHA1_BIN_LENGTH];
	auth_callback *callback;
	struct results_t* new;
	struct results_t* results;

	// Find existing search
	if( (results = results_find( query )) != NULL ) {
		*is_new = 0;
		return results;
	} else {
		*is_new = 1;
	}

	if( bob_get_id( id, sizeof(id), query ) ) {
		// Use Bob authentication
		callback = &bob_trigger_auth;
	} else if( tls_client_get_id( id, sizeof(id), query ) ) {
		// Use TLS authentication
		callback = &tls_client_trigger_auth;
	} else {
		callback = NULL;
	}

	new = calloc( 1, sizeof(struct results_t) );
	memcpy( new->id, id, sizeof(id) );
	new->callback = callback;
	new->query = strdup( query );
	new->start_time = time_now_sec();

	log_debug( "Results: Add results bucket for query '%s', id '%s'.", query, str_id( id ) );

	// Free slot if taken
	if( g_results[g_results_idx] != NULL ) {
		results_item_free( g_results[g_results_idx] );
	}

	g_results[g_results_idx] = new;
	g_results_idx = (g_results_idx + 1) % MAX_SEARCHES;

	return new;
}

// Add an address to an array if it is not already contained in there
int results_add_addr( struct results_t *results, const IP *addr ) {
	struct result_t *result;
	struct result_t *new;

	if( results_entries_count( results ) > MAX_RESULTS_PER_SEARCH ) {
		return -1;
	}

	// Check if result already exists
	result = results->entries;
	while( result ) {
		if( addr_equal( &result->addr, addr ) ) {
			// Address already listed
			return 0;
		}

		result = result->next;
	}

	new = calloc( 1, sizeof(struct result_t) );
	memcpy( &new->addr, addr, sizeof(IP) );
	new->state = results->callback ? AUTH_WAITING : AUTH_OK;

	// Append new entry to list
	if( result ) {
		result->next = new;
	} else {
		results->entries = new;
	}

	if( results->callback ) {
		results->callback( results );
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
		if( result->state == AUTH_OK ) {
			memcpy( &addr_array[i], &result->addr, sizeof(IP) );
			i++;
		}
		result = result->next;
	}

	return i;
}


void results_setup( void ) {
	// Nothing to do
}

void results_free( void ) {
	struct results_t **results;

	results = &g_results[0];
	while( *results ) {
		results_item_free( *results );
		*results = NULL;
		results++;
	}
}
