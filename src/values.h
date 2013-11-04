
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
	time_t lifetime; /* Keep entry refreshed until the lifetime expires */
	time_t refresh; /* Next time the entry need to be refreshed */
	struct value_t *next;
};

void values_setup( void );

struct value_t* values_get( void );
struct value_t* values_find( UCHAR id[] );

/* List all entries */
void values_debug( int fd );

/* Count all entries */
int values_count( void );

/* Add a value id / port that will be announced until lifetime is exceeded */
int values_add( const char query[], int port, time_t lifetime );


#endif /* _EXT_VALUES_H_ */
