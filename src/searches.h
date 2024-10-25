
#ifndef _EXT_SEARCHES_H_
#define _EXT_SEARCHES_H_

#include <stdio.h>

// Authentication states
enum AUTH_STATE {
	AUTH_OK, // Authentication successful or not needed
	AUTH_AGAIN, // Was already successful, but needs to be retested
	AUTH_FAILED, // Verification failed
	AUTH_ERROR, // No reply
	AUTH_SKIP, // Skipped, only one result needed
	AUTH_PROGRESS, // In progress
	AUTH_WAITING // Not yet started
};

typedef void auth_callback(void);

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
	bool done;
	char query[QUERY_MAX_SIZE];
	time_t start_time;
	struct result_t *results;
	auth_callback *callback;
};

void searches_set_auth_state(const char query[], const IP *addr, const int state);
struct result_t *searches_get_auth_target(char query[], IP *addr, auth_callback *callback);
int is_valid_result(const struct result_t *result);

void searches_setup(void);
void searches_free(void);

// Start a search
struct search_t *searches_start(const char query[]);

// Find a search by infohash, so we can add results
struct search_t *searches_find_by_id(const uint8_t id[]);

// Add an address to a result bucket
void searches_add_addr(struct search_t *search, const IP *addr);

void searches_debug(FILE *fp);


#endif // _EXT_SEARCHES_H_
