
#ifndef _EXT_VALUES_H_
#define _EXT_VALUES_H_

#include <sys/time.h>

/*
* Announce a value id / port pair every 30 minutes
* using the DHT until the lifetime expires.
*/

struct value_t {
	UCHAR value_id[SHA_DIGEST_LENGTH];
	int port;
	time_t lifetime; /* keep entry until lifetime expires */
	time_t refreshed; /* last time the entry was refreshed */
	struct value_t *next;
};

void values_setup( void );

struct value_t* values_get( void );

/* List all entries */
void values_debug( int fd );

/* Count all entries */
int values_count( void );

/* Add a value id / port that will be announced until lifetime is exceeded */
void values_add( const UCHAR *value_id, USHORT port, time_t lifetime );


#endif /* _EXT_VALUES_H_ */
