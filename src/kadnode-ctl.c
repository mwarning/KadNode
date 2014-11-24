
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "main.h"

#define BUFSIZE 1472

const char *usage = MAIN_SRVNAME" Control Program - Send commands to a KadNode instance.\n\n"
"Usage: kadnode-ctl [OPTIONS]* [COMMANDS]*\n"
"\n"
" -p <port>	Connect to this port (Default: "CMD_PORT")\n"
" -h		Print this help.\n"
"\n";


/* Parse a port - treats 0 as valid port */
int port_parse( const char *pstr, int err ) {
	int port;
	size_t i;

	port = 0;
	for( i = 0; pstr[i] != '\0'; i++ ) {
		if( pstr[i] < '0' || pstr[i] > '9' ) {
			return err;
		}
		port *= 10;
		port += pstr[i] - '0';
	}

	if( i == 0 || port < 0 || port > 65535 ) {
		return err;
	} else {
		return port;
	}
}

int addr_len( const IP *addr ) {
	switch( addr->ss_family ) {
		case AF_INET:
			return sizeof(IP4);
		case AF_INET6:
			return sizeof(IP6);
		default:
			return 0;
	}
}

/*
* Parse/Resolve an IP address.
* The port must be specified separately.
*/
int addr_parse( IP *addr, const char addr_str[], const char port_str[], int af ) {
	struct addrinfo hints;
	struct addrinfo *info = NULL;
	struct addrinfo *p = NULL;

	memset( &hints, '\0', sizeof(struct addrinfo) );
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = af;

	if( getaddrinfo( addr_str, port_str, &hints, &info ) != 0 ) {
		return -2;
	}

	p = info;
	while( p != NULL ) {
		if( p->ai_family == AF_INET6 ) {
			memcpy( addr, p->ai_addr, sizeof(IP6) );
			freeaddrinfo( info );
			return 0;
		}
		if( p->ai_family == AF_INET ) {
			memcpy( addr, p->ai_addr, sizeof(IP4) );
			freeaddrinfo( info );
			return 0;
		}
	}

	freeaddrinfo( info );
	return -3;
}

/* Read from socket with timeout */
int select_read( int sockfd, char *buffer, int bufsize, struct timeval *tv ) {
	fd_set rfds;
	int retval;

	FD_ZERO( &rfds );
	FD_SET( sockfd, &rfds );

	retval = select( sockfd + 1, &rfds, NULL, NULL, tv );

	if( retval == -1 ) {
		/* Error */
		return -1;
	} else if( retval ) {
		/* Data available */
		return read( sockfd, buffer, bufsize );
	} else {
		/* Timeout reached */
		return 0;
	}
}

int udp_send( char buffer[], const char port[] ) {
	struct timeval tv;
	IP sockaddr;
	socklen_t addrlen;
	int sockfd;
	int n;

	if( addr_parse( &sockaddr, "localhost", CMD_PORT, AF_UNSPEC ) < 0 ) {
		fprintf( stderr, "Failed to get localhost address: %s\n", strerror( errno ) );
		return 1;
	}

	if( (sockfd = socket( sockaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP )) < 0 ) {
		fprintf( stderr, "Failed to create socket: %s\n", strerror( errno ) );
		return 1;
	}

	addrlen = addr_len( &sockaddr );
	if( sendto( sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&sockaddr, addrlen ) < 0 ) {
		fprintf( stderr, "Cannot connect to server: %s\n", strerror( errno ) );
		return 1;
	}

	/* Set receive timeout: 200ms */
	tv.tv_sec = 0;
	tv.tv_usec = 200000;

#ifdef __CYGWIN__
	/* Receive reply */
	n = select_read( sockfd, buffer, BUFSIZE - 1, &tv );
#else
	if( setsockopt( sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv) ) < 0 ) {
		fprintf( stderr, "Failed to set socket option SO_RCVTIMEO: %s\n", strerror( errno ) );
		return 1;
	}

	/* Receive reply */
	n = read( sockfd, buffer, BUFSIZE - 1 );
#endif

	if( n <= 0 ) {
		close( sockfd );
		fprintf( stderr, "No response received.\n" );
		return 1;
	}

	buffer[n] = '\0';
	close( sockfd );

	if( buffer[0] == '0' ) {
		fprintf( stdout, "%s", buffer+1 );
		return 0;
	} else if( buffer[0] == '1' ) {
		fprintf( stderr, "%s", buffer+1 );
		return 1;
	} else {
		fprintf( stderr, "Invalid response received.\n" );
		return 2;
	}
}

int main( int argc, char **argv ) {
	char buffer[BUFSIZE];
	size_t i;
	const char *port;

	/* Use the default port */
	port = CMD_PORT;

	/* Skip binary name */
	argc -= 1;
	argv += 1;

	if( argc >= 1 ) {
		if( strcmp( argv[0], "-h") == 0 ) {
			fprintf( stdout, "%s", usage );
			return 0;
		} else if( strcmp( argv[0], "-p" ) == 0 ) {
			if( argc >= 2 ) {
				port = argv[1];
				/* Skip option and port */
				argc -= 2;
				argv += 2;
			} else {
				fprintf( stderr, "Port is missing!\n" );
				return 1;
			}
		}
	}

	if( port_parse( port, -1 ) < 1 ) {
		fprintf( stderr, "Port is invalid!\n" );
		return 1;
	}

	/* Construct request string from args */
	buffer[0] = '\0';
	for( i = 0; i < argc; ++i ) {
		strcat( buffer, " " );
		strcat( buffer, argv[i] );
	}
	strcat( buffer, "\n" );

	return udp_send( buffer, port );
}
