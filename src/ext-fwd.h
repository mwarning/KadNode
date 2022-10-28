
#ifndef _EXT_FWD_H_
#define _EXT_FWD_H_

#include <sys/time.h>
#include <stdio.h>

/*
* Every value id announcement also carries a port on which
* the id can be satisfied. There needs to be a port forwarding
* to allow another node on the Internet to reach this computer's
* local port.
*/


// Return values for UPNP/NAT-PMP
enum {
	PF_DONE = 1,
	PF_RETRY = 0,
	PF_ERROR = -1
};

struct forwarding_t {
	struct forwarding_t *next;
	int port; // Port to be forwarded on the router
	time_t lifetime; // Keep entry until lifetime expires
	time_t refreshed; // Last time the entry was refreshed
};

int fwd_setup(void);
void fwd_free(void);

struct forwarding_t *fwd_get(void);

// List all entries
void fwd_debug(FILE *fp);

// Count all entries
int fwd_count(void);

// Add a port forwarding from external port to the same local port
void fwd_add(int port, time_t host_lifetime);


#endif // _EXT_FWD_H_
