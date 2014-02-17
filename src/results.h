
#ifndef _EXT_RESULTS_H_
#define _EXT_RESULTS_H_

#ifdef AUTH
#include <sodium.h>
#define CHALLENGE_BIN_LENGTH 16
#endif

#define MAX_RESULTS_PER_SEARCH 16
#define MAX_SEARCHES 64
#define MAX_SEARCH_LIFETIME (5*60)

/* An address that was received as a result of an id search */
struct result_t {
	IP addr;
#ifdef AUTH
	UCHAR *challenge;
	int challenges_send;
#endif
	struct result_t *next;
};

/* A bucket of results received when searching of an id */
struct results_t {
	/* The value id to search for */
	UCHAR id[SHA1_BIN_LENGTH];
#ifdef AUTH
	UCHAR *pkey;
#endif
	time_t start_time;
	struct result_t *entries;
	int done;

	struct results_t *next;
};

struct results_t *results_get( void );
struct results_t *results_find( const UCHAR id[] );

/* Register a handler to call results_expire in intervalls */
void results_setup( void );

/* Create and append a new results item */
struct results_t *results_add( const char query[] );

int results_add_addr( struct results_t *results, const IP *addr );

/* Import results from the DHT */
int results_import( struct results_t *results, void *data, size_t data_length );

int results_collect( struct results_t *results, IP addr_array[], size_t addr_num );

int results_done( struct results_t *results, int done );

void results_debug( int fd );

#endif /* _EXT_RESULTS_H_ */
