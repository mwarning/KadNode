
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


int main( int argc, char **argv ) {
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	struct timeval tv;
	IP6 sockaddr;
	char buffer[1500];
	int i, n;

	sockaddr.sin6_family = AF_INET6;
	sockaddr.sin6_port = htons( atoi( CMD_PORT ) );
	inet_pton( AF_INET6, "::1", &sockaddr.sin6_addr );

	/* Construct request string from args */
    buffer[0] = '\0';
	for( i = 1; i < argc; ++i ) {
		strcat( buffer, " " );
		strcat( buffer, argv[i] );
	}
	strcat(buffer, "\n");

	if( (sockfd = socket( sockaddr.sin6_family, SOCK_DGRAM, IPPROTO_UDP )) < 0 ) {
		fprintf( stderr, "Failed to create socket: %s\n", strerror( errno ) );
		return 1;
	}

	/* Set receive timeout */
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
	n = read( sockfd, buffer, sizeof(buffer) - 1);

	if( n <= 0 ) {
		fprintf( stderr, "No response received.\n");
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
