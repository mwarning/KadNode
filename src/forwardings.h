
#ifndef _FORWARDINGs_H_
#define _FORWARDINGs_H_

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

struct forwarding_t {
	int port; /* the port to be forwarded on the router */
	time_t lifetime; /* keep entry until lifetime expires */
	time_t refreshed; /* last time the entry was refreshed */
	struct forwarding_t *next;
};

void forwardings_setup( void );

struct forwarding_t *forwardings_get( void );

/* List all entries */
void forwardings_debug( int fd );

/* Count all entries */
int forwardings_count( void );

/* Add a port forwarding from external port to the same local port. */
void forwardings_add( int port, time_t host_lifetime );


#endif /* _FORWARDINGs_H_ */
