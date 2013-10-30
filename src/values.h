
#ifndef _EXT_VALUES_H_
#define _EXT_VALUES_H_

#include <sys/time.h>

/*
* Announce a value id / port pair every 30 minutes
* using the DHT until the lifetime expires.
*/

struct value_t {
	UCHAR id[SHA1_BIN_LENGTH];
	int port;
	time_t lifetime; /* Keep entry until lifetime expires */
	time_t refreshed; /* Last time the entry was refreshed */
	struct value_t *next;
};

void values_setup( void );

struct value_t* values_get( void );

/* List all entries */
void values_debug( int fd );

/* Count all entries */
int values_count( void );

/* Add a value id / port that will be announced until lifetime is exceeded */
void values_add( const char query[], int port, time_t lifetime );


#endif /* _EXT_VALUES_H_ */
