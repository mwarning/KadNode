
#ifndef _NET_H
#define _NET_H

/* Callback for event loop */
typedef void net_callback( int rc, int fd );

/* Create a socket and bind to interface */
int net_socket(
	const char name[],
	const char ifname[],
	int protocol, int af
);

/* Create a socket and bind to address/interface */
int net_bind(
	const char name[],
	const char addr[],
	const char port[],
	const char ifname[],
	int protocol, int af
);

/* Add callback with file descriptor to listen for packets */
void net_add_handler( int fd, net_callback *callback );

/* Remove callback */
void net_remove_handler( int fd, net_callback *callback );

/* Start loop for all network events */
void net_loop( void );

/* Close sockets */
void net_free( void );

#endif /* _NET_H */
