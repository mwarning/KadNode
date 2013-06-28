#ifndef _EXT_RESULTS_H_
#define _EXT_RESULTS_H_

#define MAX_RESULTS_PER_SEARCH 16
#define MAX_SEARCHES 64
#define EXPIRE_SEARCH 60


/* Searches along with received addresses */
struct result {
	/* The value id to search for */
	UCHAR id[SHA_DIGEST_LENGTH];
	int af;
	time_t start_time;
	/* These nodes have announced id */
	IP addrs[MAX_RESULTS_PER_SEARCH];
	size_t numaddrs;
	int done;

	struct result* next;
};

struct result* results_list( void );
void results_expire( void );
struct result* results_find( const UCHAR *id, int af );
int results_insert( const UCHAR *id, int af );

void results_import( const UCHAR *id, void *data, int data_length, int af );
void results_done( const UCHAR *id, int af );

#endif /* _EXT_RESULTS_H_ */
