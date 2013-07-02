
#ifndef _NET_H
#define _NET_H

typedef void net_callback( int rc, int fd );

/* Create and bind to a socket */
int net_bind(
	const char* name,
	const char* addr, 
	const char* port,
	const char* ifce,
	int protocol, int af
);

/* A socket to the file descriptor set */
void net_add_handler( int fd, net_callback *callback );

/* Start loop for all network events */
void net_loop( void );

#endif /* _NET_H */
