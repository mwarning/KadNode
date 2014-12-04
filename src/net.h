
#ifndef _NET_H
#define _NET_H

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

/* Add a socket to the file descriptor set */
void net_add_handler( int fd, net_callback *callback );

/* Start loop for all network events */
void net_loop( void );

#endif /* _NET_H */
