
#ifndef _EXT_SEARCHES_H_
#define _EXT_SEARCHES_H_


// Authentication states
enum AUTH_STATE {
	AUTH_OK, // Successful or not needed
	AUTH_AGAIN, // Was already successful, but needs to be retested
	AUTH_FAILED, // Verification failed
	AUTH_ERROR, // No reply
	AUTH_SKIP, // Skipped, only one result needed
	AUTH_PROGRESS, // In progress
	AUTH_WAITING // Not yet started
};

// Forward declaration
struct search_t;

typedef void auth_callback(struct search_t *search);

// An address that was received as a result of an id search
struct result_t {
	struct result_t *next;
	IP addr;
	enum AUTH_STATE state;
};

// A bucket of results received when in search of an id
struct search_t {
	struct search_t *next;
	uint8_t id[SHA1_BIN_LENGTH];
	char *query;
	time_t start_time;
	struct result_t *results;
	auth_callback *callback;
};

struct search_t **searches_get( void );
struct search_t *searches_find( const char query[] );

// Register a handler to call results_expire in intervalls
void searches_setup( void );
void searches_free( void );

// Start a search
struct search_t *searches_start( const char query[] );

// Add an address to a result bucket
int searches_add_addr( struct search_t *search, const IP *addr );

// Collect addresses
int searches_collect_addrs( struct search_t *search, IP addr_array[], size_t addr_num );

void searches_debug( int fd );


#endif // _EXT_SEARCHES_H_
