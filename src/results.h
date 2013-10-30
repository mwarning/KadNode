
#ifndef _EXT_RESULTS_H_
#define _EXT_RESULTS_H_

#define MAX_RESULTS_PER_SEARCH 16
#define MAX_SEARCHES 64
#define MAX_SEARCH_LIFETIME (5*60)

/* An address that was received as a result of an id search */
struct result_t {
	IP addr;
	struct result_t *next;
};

/* Searches along with received addresses */
struct results_t {
	/* The value id to search for */
	UCHAR id[SHA1_BIN_LENGTH];
	time_t start_time;
	struct result_t *entries;
	int done;

	struct results_t *next;
};

struct results_t* results_get( void );
struct results_t *results_find( const UCHAR id[] );

/* Register a handler to call results_expire in intervalls */
void results_setup( void );

/* Create a new results item */
int results_add( const UCHAR id[], const char query[] );

/* Import results from the DHT */
int results_import( const UCHAR id[], void *data, size_t data_length );

int results_collect( const UCHAR id[], IP addr_array[], size_t addr_num );

int results_done( const UCHAR id[] );

void results_debug( int fd );

#endif /* _EXT_RESULTS_H_ */
