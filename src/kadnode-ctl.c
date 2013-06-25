
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>

#include "main.h"

#define BUFSIZE 1500


int udp_send( char* buffer, int port ) {
	struct timeval tv;
	int sockfd;
	int n;
	IP6 sockaddr;

	memset( &sockaddr, '\0', sizeof(sockaddr) );
	sockaddr.sin6_family = AF_INET6;
	sockaddr.sin6_port = htons( port );
	inet_pton( AF_INET6, "::1", &sockaddr.sin6_addr );

	if( (sockfd = socket( sockaddr.sin6_family, SOCK_DGRAM, IPPROTO_UDP )) < 0 ) {
		fprintf( stderr, "Failed to create socket: %s\n", strerror( errno ) );
		return 1;
	}

	/* Set receive timeout: 200ms */
	tv.tv_sec = 0;
	tv.tv_usec = 200;
	if( setsockopt( sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv) ) < 0 ) {
		fprintf( stderr, "Failed to set socket option SO_RCVTIMEO: %s\n", strerror( errno ) );
		return 1;
	}

	if( sendto( sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&sockaddr, sizeof(IP6) ) < 0 ) {
		fprintf( stderr, "Cannot connect to server: %s\n", strerror( errno ) );
		return 1;
	}

	/* Receive reply */
	n = read( sockfd, buffer, BUFSIZE - 1);

	if( n <= 0 ) {
		fprintf( stderr, "No response received.\n" );
		return 1;
	}

	buffer[n] = '\0';
	close( sockfd );

	if( buffer[0] == '0' ) {
		fprintf( stdout, buffer+1 );
		return 0;
	} else {
		fprintf( stderr, buffer+1 );
		return 1;
	}
}

int main( int argc, char **argv ) {
	char buffer[BUFSIZE];
	int i;
	int port;

	/* Use the default port */
	port = atoi( CMD_PORT );

	/* Skip binary name */
	argc -= 1;
	argv += 1;

	if( argc >= 1 ) {
		if( strcmp( argv[0], "-h") == 0 ) {
			fprintf( stdout, "kadnode-ctl [-h|-p <port>] <commands>...\n\n" );
			return 0;
		} else if( strcmp( argv[0], "-p" ) == 0 ) {
			if( argc >= 2 ) {
				port = atoi( argv[1] );
				/* Skip option and port */
				argc -= 2;
				argv += 2;
			} else {
				fprintf( stderr, "Port is missing!\n" );
				return 1;
			}
		}
	}

	if( port < 1 || port > 65535 ) {
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
