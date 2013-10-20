
#ifndef _EXT_RESULTS_H_
#define _EXT_RESULTS_H_

#define MAX_RESULTS_PER_SEARCH 16
#define MAX_SEARCHES 64
#define EXPIRE_SEARCH 60


/* An address we received as a result for an id */
struct result_t {
	IP addr;

	struct result_t *next;
};

/* Searches along with received addresses */
struct results_t {
	/* The value id to search for */
	UCHAR id[SHA_DIGEST_LENGTH];
	int af;
	time_t start_time;
	struct result_t *entries;
	int done; /* indicates if more results are to be expected - no real use */

	struct results_t *next;
};

/* Register a handler to call results_expire in intervalls */
void results_setup( void );

/* Access the internal results list */
struct results_t *results_list( void );

/* Remove results that are expired */
void results_expire( void );

/* Get a results item by id */
struct results_t *results_find( const UCHAR *id, int af );

/* Create a new results item */
int results_insert( const UCHAR *id, int af );

/* Import results from the DHT */
void results_import( const UCHAR *id, void *data, int data_length, int af );

/* Mark a result as done */
void results_done( const UCHAR *id, int af );

#endif /* _EXT_RESULTS_H_ */
