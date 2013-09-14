
#ifndef _EXT_VALUES_H_
#define _EXT_VALUES_H_

#include <sys/time.h>

/*
* Announce a value id / port pair every 30 minutes
* using the DHT until the lifetime expires.
*/

void values_setup( void );

/* List all entries */
void values_debug( int fd );

/* Count all entries */
int values_count( void );

/* Add a value id / port that will be announced until lifetime is exceeded */
void values_add( const UCHAR *value_id, USHORT port, time_t lifetime );


#endif /* _EXT_VALUES_H_ */
