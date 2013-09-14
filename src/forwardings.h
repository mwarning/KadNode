
#ifndef _PORTFORWARDING_H_
#define _PORTFORWARDING_H_

#include <sys/time.h>

/*
* Every value id announcement also carries a port on which
* the id can be satisfied. There needs to be a port forwarding
* to allow another node on the Internet to reach this computers
* local port.
*/


/* Return values for UPNP/NAT-PMP */
enum {
	PF_DONE = 1,
	PF_RETRY = 0,
	PF_ERROR = -1
};

void forwardings_setup( void );

/* List all entries */
void forwardings_debug( int fd );

/* Count all entries */
int forwardings_count( void );

/* Add a port forwarding from external port to the same local port. */
void forwardings_add( USHORT port, time_t host_lifetime );


#endif /* _PORTFORWARDING_H_ */
