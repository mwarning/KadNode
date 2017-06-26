
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

#define MAX_SEARCH_LIFETIME (20*60)

// A ring buffer for of all searches
static struct search_t *g_searches[MAX_SEARCHES] = { NULL };
static size_t g_searches_idx = 0;


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
struct search_t** results_get( void ) {
	return &g_searches[0];
}

// Find a value search result
struct search_t *results_find( const char query[] ) {
	struct search_t **search;
	struct search_t *searches;

	search = &g_searches[0];
	while( *search ) {
		searches = *search;
		if( strcmp( query, searches->query ) == 0 ) {
			return searches;
		}
		search += 1;
	}

	return NULL;
}

int results_entries_count( struct search_t *search ) {
	struct result_t *result;
	int count;

	count = 0;
	result = search->results;
	while( result ) {
		count += 1;
		result = result->next;
	}

	return count;
}

void result_free( struct result_t *result ) {
	free( result );
}

// Free a search_t struct
void search_free( struct search_t *search ) {
	struct result_t *cur;
	struct result_t *next;

	cur = search->results;
	while( cur ) {
		next = cur->next;
		result_free( cur );
		cur = next;
	}

	free( search->query );
	free( search );
}

void results_debug( int fd ) {
	struct search_t **results;
	struct search_t *bucket;
	struct result_t *result;
	int results_counter;
	int result_counter;

	results_counter = 0;
	results = &g_searches[0];
	dprintf( fd, "Result buckets:\n" );
	while( *results ) {
		bucket = *results;
		dprintf( fd, " id: %s\n", str_id( bucket->id ) );
		result_counter = 0;
		result = bucket->results;
		while( result ) {
			dprintf( fd, "   addr: %s\n", str_addr( &result->addr ) );
			dprintf( fd, "   state: %s\n", str_state( result->state ) );
			result_counter += 1;
			result = result->next;
		}
		dprintf( fd, "  Found %d results.\n", result_counter );
		results_counter += 1;
		results += 1;
	}
	dprintf( fd, " Found %d result buckets.\n", results_counter );
}

void search_restart( struct search_t *results ) {
	results->start_time = time_now_sec();
	//results->callback

	// Remove all failed results
	struct result_t *result = results->results;
	struct result_t *prev = NULL;
	struct result_t *next = NULL;

	while( result ) {
		// Remove element
		if( result->state == AUTH_ERROR || result->state == AUTH_SKIP ) {
			// Remove result
			next = result->next;
			if( prev ) {
				prev->next = next;
			} else {
				results->results = next;
			}
			result_free(result);
			result = next;
		} else {
			prev = result;
			result = result->next;
		}
	}
}

// Start a new search
// The query is expected to be sanitized (lower case and without query TLS)
//search_start()
struct search_t* results_lookup( const char query[] ) {
	uint8_t id[SHA1_BIN_LENGTH];
	auth_callback *callback;
	struct search_t* new;
	struct search_t* results;

	// Find existing search
	if( (results = results_find( query )) != NULL ) {
		// Restart search after half of search lifetime
		if( (time_now_sec() - results->start_time) > (MAX_SEARCH_LIFETIME / 2) ) {
			search_restart( results );
		}

		return results;
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

	new = calloc( 1, sizeof(struct search_t) );
	memcpy( new->id, id, sizeof(id) );
	new->callback = callback;
	new->query = strdup( query );
	new->start_time = time_now_sec();

	log_debug( "Results: Add results bucket for query: %s", query );

	// Free slot if taken
	if( g_searches[g_searches_idx] != NULL ) {
		// What to do with auths in progress?
		search_free( g_searches[g_searches_idx] );
	}

	g_searches[g_searches_idx] = new;
	g_searches_idx = (g_searches_idx + 1) % MAX_SEARCHES;

	return new;
}

// Add an address to an array if it is not already contained in there
int results_add_addr( struct search_t *search, const IP *addr ) {
	struct result_t *result;
	struct result_t *new;

	if( results_entries_count( search ) > MAX_RESULTS_PER_SEARCH ) {
		return -1;
	}

	// Check if result already exists
	result = search->results;
	while( result ) {
		if( addr_equal( &result->addr, addr ) ) {
			// Address already listed
			return 0;
		}

		result = result->next;
	}

	new = calloc( 1, sizeof(struct result_t) );
	memcpy( &new->addr, addr, sizeof(IP) );
	new->state = search->callback ? AUTH_WAITING : AUTH_OK;

	// Append new entry to list
	if( result ) {
		result->next = new;
	} else {
		search->results = new;
	}

	if( search->callback ) {
		search->callback( search );
	}

	return 0;
}

int results_collect( struct search_t *search, IP addr_array[], size_t addr_num ) {
	struct result_t *result;
	size_t i;

	if( search == NULL ) {
		return 0;
	}

	i = 0;
	result = search->results;
	while( result && i < addr_num ) {
		if( result->state == AUTH_OK ) {
			memcpy( &addr_array[i], &result->addr, sizeof(IP) );
			i += 1;
		}
		result = result->next;
	}

	return i;
}


void results_setup( void ) {
	// Nothing to do
}

void results_free( void ) {
	struct search_t **search;

	search = &g_searches[0];
	while( *search ) {
		search_free( *search );
		*search = NULL;
		search += 1;
	}
}
