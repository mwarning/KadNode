
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
#include "searches.h"


/*
* The DHT implementation in KadNode does not store
* results (IP addresses) from hash id searches.
* Therefore, results are collected and stored here.
*/

// Expected lifetime of announcements
#define MAX_SEARCH_LIFETIME (20*60)
#define MAX_RESULTS_PER_SEARCH 16
#define MAX_SEARCHES 64


// A ring buffer for of all searches
static struct search_t *g_searches[MAX_SEARCHES] = { NULL };
static size_t g_searches_idx = 0;


static const char *str_state( int state ) {
	switch( state ) {
		case AUTH_OK: return "OK";
		case AUTH_AGAIN: return "AGAIN";
		case AUTH_FAILED: return "FAILED";
		case AUTH_ERROR: return "ERROR";
		case AUTH_SKIP: return "SKIP";
		case AUTH_PROGRESS: return "PROGRESS";
		case AUTH_WAITING: return "WAITING";
		default:
			log_err( "Invalid state: %d", state );
			exit(1);
	}
}

// External access to all current results
struct search_t** searches_get( void ) {
	return &g_searches[0];
}

// Find a value search result
static struct search_t *searches_find( const char query[] ) {
	struct search_t **search;
	struct search_t *searches;

	search = &g_searches[0];
	while( *search ) {
		searches = *search;
		if( strcmp( query, &searches->query[0] ) == 0 ) {
			return searches;
		}
		search += 1;
	}

	return NULL;
}

// Free a search_t struct
void search_free( struct search_t *search ) {
	struct result_t *cur;
	struct result_t *next;

	cur = search->results;
	while( cur ) {
		next = cur->next;
		free( cur );
		cur = next;
	}

	free( search );
}

// Get next address to authenticate
static struct result_t *find_next_result( struct search_t *search ) {
	struct result_t *result;

	result = search->results;
	while( result ) {
		const int state = result->state;
		if( state == AUTH_WAITING || state == AUTH_AGAIN ) {
			return result;
		}
		result = result->next;
	}

	return NULL;
}

// Get next search to authenticate
static struct search_t *find_next_search( void ) {
	struct search_t **searches;

	searches = searches_get();
	while( *searches ) {
		if( !(*searches)->done && (*searches)->callback ) {
			return *searches;
		}
		searches++;
	}
	return NULL;
}

struct result_t *searches_get_auth_target( char query[], IP *addr ) {
	struct search_t *search;
	struct result_t *result;

	// Get next search to authenticate
	search = find_next_search();
	if( search == NULL ) {
		return NULL;
	}

	// Get next result to authenticate
	result = find_next_result( search );
	if( result == NULL ) {
		return NULL;
	}

	// Set query and addr to authenticate
	memcpy( query, &search->query, sizeof(search->query) );
	memcpy( addr, &result->addr, sizeof(IP) );

	return result;
}

void searches_set_auth_state( const char query[], const IP *addr, const int state ) {
	struct search_t *search;
	struct result_t *result;

	log_debug( "Authentication for %s: %s", query, str_state( state ) );

	search = searches_find( query );

	if( search ) {
		// Search and set authentication state of result
		result = search->results;
		while( result ) {
			if( addr_equal( &result->addr, addr ) ) {
				result->state = state;
				break;
			}
			result = result->next;
		}

		// Skip all other results if we found one that is ok
		if( state == AUTH_OK ) {
			search->done = 1;
			result = search->results;
			while( result ) {
				if( result->state == AUTH_WAITING ) {
					result->state = AUTH_SKIP;
				}
				result = result->next;
			}
		}
	}
}

void searches_debug( int fd ) {
	struct search_t **searches;
	struct search_t *search;
	struct result_t *result;
	int result_counter;
	int searche_counter;

	searche_counter = 0;
	searches = &g_searches[0];
	dprintf( fd, "Result buckets:\n" );
	while( *searches ) {
		search = *searches;
		dprintf( fd, " id: %s\n", str_id( search->id ) );
		dprintf( fd, " query: %s\n", &search->query[0] );
		dprintf( fd, " done: %s\n", search->done ? "true" : "false" );
		result_counter = 0;
		result = search->results;
		while( result ) {
			dprintf( fd, "   addr: %s\n", str_addr( &result->addr ) );
			dprintf( fd, "   state: %s\n", str_state( result->state ) );
			result_counter += 1;
			result = result->next;
		}
		dprintf( fd, "  Found %d results.\n", result_counter );
		result_counter += 1;
		searches++;
	}
	dprintf( fd, " Found %d searches.\n", searche_counter );
}

void search_restart( struct search_t *search ) {
	struct result_t *result;
	struct result_t *prev;
	struct result_t *next;

	log_debug( "Restart search for query: %s", search->query );

	search->start_time = time_now_sec();
	search->done = 0;

	// Remove all failed searches
	next = NULL;
	prev = NULL;
	result = search->results;
	while( result ) {
		const int state = result->state;
		if( state == AUTH_ERROR || state == AUTH_AGAIN ) {
			// Remove result
			next = result->next;
			if( prev ) {
				prev->next = next;
			} else {
				search->results = next;
			}
			free( result );
			result = next;
			continue;
		} else if( state == AUTH_OK ) {
			// Check again on another search
			result->state = AUTH_AGAIN;
		} else if( state == AUTH_SKIP ) {
			// Continue check
			result->state = AUTH_WAITING;
		}

		prev = result;
		result = result->next;
	}
}

// Start a new search (query is expected to be lower case and without .p2p)
struct search_t* searches_start( const char query[] ) {
	uint8_t id[SHA1_BIN_LENGTH];
	auth_callback *callback;
	struct search_t* search;
	struct search_t* new;

	// Find existing search
	if( (search = searches_find( query )) != NULL ) {
		// Restart search after half of search lifetime
		if( (time_now_sec() - search->start_time) > (MAX_SEARCH_LIFETIME / 2) ) {
			search_restart( search );
		}

		return search;
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
	new->done = 0;
	new->callback = callback;
	memcpy( &new->query, query, sizeof(new->query) );
	new->start_time = time_now_sec();

	log_debug( "Create new search for query: %s", query );

	// Free slot if taken
	if( g_searches[g_searches_idx] != NULL ) {
		// Remove and abort entire search
		search_free( g_searches[g_searches_idx] );
	}

	g_searches[g_searches_idx] = new;
	g_searches_idx = (g_searches_idx + 1) % MAX_SEARCHES;

	return new;
}

// Add an address to an array if it is not already contained in there
int searches_add_addr( struct search_t *search, const IP *addr ) {
	struct result_t *cur;
	struct result_t *new;
	int count;

	// Check if result already exists
	count = 0;
	cur = search->results;
	while( cur ) {
		if( addr_equal( &cur->addr, addr ) ) {
			// Address already listed
			return 0;
		}

		if( count > MAX_RESULTS_PER_SEARCH ) {
			return -1;
		}

		count += 1;
		cur = cur->next;
	}

	new = calloc( 1, sizeof(struct result_t) );
	memcpy( &new->addr, addr, sizeof(IP) );
	new->state = search->callback ? AUTH_WAITING : AUTH_OK;

	// Append new entry to list
	if( cur ) {
		cur->next = new;
	} else {
		search->results = new;
	}

	if( search->callback ) {
		search->callback();
	}

	return 0;
}

int searches_collect_addrs( struct search_t *search, IP addr_array[], size_t addr_num ) {
	struct result_t *cur;
	size_t i;

	if( search == NULL ) {
		return 0;
	}

	i = 0;
	cur = search->results;
	while( cur && i < addr_num ) {
		if( cur->state == AUTH_OK || cur->state == AUTH_AGAIN ) {
			memcpy( &addr_array[i], &cur->addr, sizeof(IP) );
			i += 1;
		}
		cur = cur->next;
	}

	return i;
}


void searches_setup( void ) {
	// Nothing to do
}

void searches_free( void ) {
	struct search_t **search;

	search = &g_searches[0];
	while( *search ) {
		search_free( *search );
		*search = NULL;
		search += 1;
	}
}
