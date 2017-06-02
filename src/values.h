
#ifndef _EXT_VALUES_H_
#define _EXT_VALUES_H_

#include <sys/time.h>

/*
* Announce a value id / port pair in regular
* intervals until the lifetime expires.
*/

struct value_t {
	struct value_t *next;
	uint8_t id[SHA1_BIN_LENGTH];
	int port;
	time_t lifetime; /* Keep entry refreshed until the lifetime expires */
	time_t refresh; /* Next time the entry need to be refreshed */
};

void values_setup( void );
void values_free( void );

struct value_t* values_get( void );
struct value_t* values_find( uint8_t id[] );

/* List all entries */
void values_debug( int fd );

/* Count all entries */
int values_count( void );

/* Add a value id / port that will be announced until lifetime is exceeded */
struct value_t *values_add( const char query[], int port, time_t lifetime );


#endif /* _EXT_VALUES_H_ */
