
#ifndef _NATPMP_H_
#define _NATPMP_H_

#define ENABLE_STRNATPMPERR
#include <natpmp.h>

/*
* NAT-PMP allows a program to add
* temporary port forwarding to a router.
*/

struct natpmp_handle_t {
	int state;
	time_t retry;
	natpmp_t natpmp;
};

void natpmp_init( struct natpmp_handle_t ** );
void natpmp_uninit( struct natpmp_handle_t ** );

int natpmp_handler( struct natpmp_handle_t *nat,
	unsigned short port, time_t lifespan, time_t now );

#endif /* _NATPMP_H_ */
