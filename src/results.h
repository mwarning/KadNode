
#ifndef _EXT_RESULTS_H_
#define _EXT_RESULTS_H_

#ifdef BOB
#include <sodium.h>
#define CHALLENGE_BIN_LENGTH 16
#endif

#define MAX_RESULTS_PER_SEARCH 16
#define MAX_SEARCHES 64


// Authentication states
enum AUTH_STATE {
	AUTH_OK, // Successful or not needed
	AUTH_FAILED, // Verification failed
	AUTH_ERROR, // No reply
	AUTH_SKIP, // Skipped, only one result needed
	AUTH_PROGRESS, // In progress
	AUTH_WAITING // Not yet started
};

struct results_t;

typedef void auth_callback(struct results_t *results);

// An address that was received as a result of an id search
struct result_t {
	struct result_t *next;
	IP addr;
	int state;
};

// A bucket of results received when in search of an id
struct results_t {
	struct results_t *next;
	uint8_t id[SHA1_BIN_LENGTH];
	char *query;
	time_t start_time;
	struct result_t *entries;
	auth_callback *callback;
};

struct results_t **results_get( void );
struct results_t *results_find( const uint8_t id[] );

// Register a handler to call results_expire in intervalls
void results_setup( void );
void results_free( void );

// Create and append a new results item
struct results_t *results_add( const char query[], int *is_new );

// Add an address to a result bucket
int results_add_addr( struct results_t *results, const IP *addr );

// Collect addresses
int results_collect( struct results_t *results, IP addr_array[], size_t addr_num );

// Mark as done
//int results_done( struct results_t *results, int done );

// Count (valid) result entries
int results_entries_count( struct results_t *result );

void results_debug( int fd );

#endif // _EXT_RESULTS_H_
