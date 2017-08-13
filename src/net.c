
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h> // close()
#include <net/if.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"


struct task_t {
	int fd;
	net_callback *callback;
};

static struct task_t g_tasks[16] = { { 0 } };
static int g_tasks_changed = 1;


void net_add_handler( int fd, net_callback *callback ) {
	int i;

	for (i = 0; i < N_ELEMS(g_tasks); i++) {
		struct task_t *task = &g_tasks[i];
		if (task->callback == NULL) {
			task->fd = fd;
			task->callback = callback;
			g_tasks_changed = 1;
			return;
		}
	}

	log_err("NET: No more space for handlers.");
	exit(1);
}

void net_remove_handler( int fd, net_callback *callback ) {
	int i;

	for (i = 0; i < N_ELEMS(g_tasks); i++) {
		struct task_t *task = &g_tasks[i];
		if (task->fd == fd && task->callback == callback) {
			task->fd = -1;
			task->callback = NULL;
			g_tasks_changed = 1;
			return;
		}
	}

	log_err("NET: Handler not found to remove.");
	exit(1);
}

// Set a socket non-blocking
int net_set_nonblocking( int fd ) {
	return fcntl( fd, F_SETFL, fcntl( fd, F_GETFL ) | O_NONBLOCK );
}

int net_socket( const char name[], const char ifname[], const int protocol, const int af ) {
	const int opt_on = 1;
	int sock;

	// Disable IPv6 or IPv4
	if( gconf->af != AF_UNSPEC && gconf->af != af ) {
		return -1;
	}

	if( (sock = socket( af, (protocol == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM, protocol ) ) < 0 ) {
		log_err( "%s: Failed to create socket: %s", name, strerror( errno ) );
		goto fail;
	}

	if( net_set_nonblocking( sock ) < 0 ) {
		log_err( "%s: Failed to make socket nonblocking: %s", name, strerror( errno ) );
		goto fail;
	}

#if defined(__APPLE__) || defined(__CYGWIN__) || defined(__FreeBSD__)
	if( ifname ) {
		log_err( "%s: Bind to device not supported on Windows and MacOSX.", name );
		goto fail;
	}
#else
	if( ifname && setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen( ifname ) ) ) {
		log_err( "%s: Unable to bind to device %s: %s", name, ifname, strerror( errno ) );
		goto fail;
	}
#endif

	if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &opt_on, sizeof(opt_on) ) < 0 ) {
		log_err( "%s: Unable to set SO_REUSEADDR for %s: %s", name, ifname, strerror( errno ) );
		goto fail;
	}

	return sock;

fail:
	close( sock );

	return -1;
}

int net_bind(
	const char name[],
	const char addr[],
	const char port[],
	const char ifname[],
	const int protocol
) {
	const int opt_on = 1;
	socklen_t addrlen;
	IP sockaddr;
	int sock = -1;;

	if( addr_parse( &sockaddr, addr, port, AF_UNSPEC ) != 0 ) {
		log_err( "%s: Failed to parse IP address '%s' and port '%s'.",
			name, addr, port
		);
		goto fail;
	}

	if( (sock = net_socket( name, ifname, protocol, sockaddr.ss_family )) < 0 ) {
		goto fail;
	}

	if( sockaddr.ss_family == AF_INET6 ) {
		if( setsockopt( sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt_on, sizeof(opt_on) ) < 0 ) {
			log_err( "%s: Failed to set IPV6_V6ONLY for %s: %s",
				name, str_addr( &sockaddr ), strerror( errno ) );
			goto fail;
		}
	}

	addrlen = addr_len( &sockaddr );
	if( bind( sock, (struct sockaddr*) &sockaddr, addrlen ) < 0 ) {
		log_err( "%s: Failed to bind socket to %s: %s",
			name, str_addr( &sockaddr ), strerror( errno )
		);
		goto fail;
	}

	if( protocol == IPPROTO_TCP && listen( sock, 5 ) < 0 ) {
		log_err( "%s: Failed to listen on %s: %s (%s)",
			name, str_addr( &sockaddr ), strerror( errno )
		);
		goto fail;
	}

	log_info( ifname ? "%s: Bind to %s, interface %s" : "%s: Bind to %s",
		name, str_addr( &sockaddr ), ifname
	);

	return sock;

fail:
	close( sock );
	return -1;
}

void net_loop( void ) {
	int i;
	int rc;
	fd_set fds_working;
	fd_set fds;
	int max_fd = -1;
	struct timeval tv;

	// Make sure we generate a new set
	g_tasks_changed = 1;

	while( gconf->is_running ) {
		// Wait one second for inconing traffic
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		// Update clock
		gconf->time_now = time( NULL );

		if( g_tasks_changed ) {
			// Create new file descriptor set
			FD_ZERO( &fds );
			max_fd = -1;

			for( i = 0; i < N_ELEMS(g_tasks); ++i ) {
				struct task_t *task = &g_tasks[i];
				if( task->callback && task->fd >= 0) {
					if( task->fd > max_fd ) {
						max_fd = task->fd;
					}
					FD_SET( task->fd, &fds );
				}
			}
			g_tasks_changed = 0;
		}

		// Get a fresh copy
		memcpy( &fds_working, &fds, sizeof(fd_set) );

		rc = select( max_fd + 1, &fds_working, NULL, NULL, &tv );

		if( rc < 0 ) {
			if( errno == EINTR ) {
				continue;
			} else {
				printf( "NET: Error using select: %s", strerror( errno ) );
				exit( 1 );
			}
		}

		// Call all callbacks
		for( i = 0; i < N_ELEMS(g_tasks); ++i ) {
			struct task_t *task = &g_tasks[i];
			if( task->callback ) {
				if( task->fd >= 0 && FD_ISSET( task->fd, &fds_working ) ) {
					task->callback( rc, task->fd );
				} else {
					task->callback( 0, task->fd );
				}
			}
		}
	}
}

void net_free( void ) {
	int i;

	// Close sockets and FDs
	for( i = 0; i < N_ELEMS(g_tasks); ++i ) {
		close( g_tasks[i].fd );
	}
}
