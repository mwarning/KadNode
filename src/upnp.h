
#ifndef _UPNP_H_
#define _UPNP_H_

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>

/*
* UPNP allows a program to add
* temporary port forwardings to a router.
*/

struct upnp_handle_t {
	int state;
	time_t retry;
	struct UPNPUrls urls;
	struct IGDdatas data;
	char addr[16]; //local addr
};

void upnp_init( struct upnp_handle_t **nat );
void upnp_uninit( struct upnp_handle_t **nat );

int upnp_handler( struct upnp_handle_t *nat,
	unsigned short port, time_t lifespan, time_t now );

#endif /* _UPNP_H_ */
