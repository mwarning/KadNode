
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netdb.h>
#include <unistd.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "ext-web.h"


const char *reply_header = "HTTP/1.1 200 OK\r\n"
"Connection: close\r\n"
"Content-Length: %ul\r\n"
"Content-Type: text/plain\r\n"
"\r\n";

void* web_loop( void* _ ) {

	int val, n, i;
	struct timeval tv;

	UCHAR node_id[SHA_DIGEST_LENGTH];
	char hexbuf[HEX_LEN+1];

	int sock, clientfd;
	IP clientaddr, sockaddr;
	socklen_t addrlen_ret;
	char request_buf[1500];
	char reply_buf[512];
	IP addrs[16];
	int addrsnum;

	char *hostname_start, *hostname_end;
	char addrbuf[FULL_ADDSTRLEN+1];

	if( addr_parse( &sockaddr, "::1", gstate->web_port, AF_INET6 ) != 0 ) {
		log_err( "WEB: Failed to parse address." );
		return NULL;
	}

	if( (sock = socket( sockaddr.ss_family, SOCK_STREAM, IPPROTO_TCP )) < 0 ) {
		log_err( "WEB: Failed to create socket: '%s'", strerror( errno ) );
		return NULL;
	}

	val = 1;
	if ( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val) ) < 0 ) {
		log_err( "WEB: Failed to set socket option SO_REUSEADDR: %s", strerror( errno ));
		return NULL;
	}

	val = 1;
	if( setsockopt( sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &val, sizeof(val) ) < 0 ) {
		log_err( "WEB: Failed to set socket option IPV6_V6ONLY: '%s'", strerror( errno ) );
		return NULL;
	}

	val = 1;
	if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val) ) < 0 ) {
		log_err( "WEB: Failed to set socket option SO_REUSEADDR: '%s'", strerror( errno ) );
		return NULL;
	}

	/* Set receive timeout */
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	if( setsockopt( sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv) ) < 0 ) {
		log_err( "WEB: Failed to set socket option SO_RCVTIMEO: '%s'", strerror( errno ) );
		return NULL;
	}

	if( bind( sock, (struct sockaddr*) &sockaddr, sizeof(IP) ) < 0 ) {
		log_err( "WEB: Failed to bind socket to address: '%s'", strerror( errno ) );
		return NULL;
	}

	if( listen( sock, 5 ) < 0 ) {
		log_err( "WEB: Failed to listen on socket: '%s'", strerror( errno ) );
		return NULL;
	}

	log_info( "WEB: Bind to %s" , str_addr( &sockaddr, addrbuf ) );

	while( gstate->is_running ) {

		addrlen_ret = sizeof(IP);
		clientfd = accept( sock, (struct sockaddr*)&clientaddr, &addrlen_ret );
		n = recv( clientfd, request_buf, sizeof(request_buf) - 1, 0 );

		if( n < 0 ) {
			goto done;
		}

		/* Only handle GET requests. */
		if( n < 6 || strncmp( "GET /", request_buf, 5 ) != 0 ) {
			goto done;
		}

		/* Jump after slash */
		hostname_start = request_buf + 5;

		request_buf[n] = ' ';
		hostname_end = strchr( hostname_start, ' ' );
		if( hostname_end == NULL ) {
			goto done;
		}

		*hostname_end = '\0';
		if( strlen( hostname_start ) == 0 || strcmp( hostname_start, "favicon.ico" ) == 0 ) {
			goto done;
		}

		/* That is the lookup key */
		id_compute( node_id, hostname_start );
		log_debug( "WEB: Lookup '%s' as '%s'.", hostname_start, str_id( node_id, hexbuf ) );

		/* Check searches for node */
		addrsnum = N_ELEMS(addrs);
		if( kad_lookup_value( node_id, addrs, &addrsnum ) != 0 ) {
			/* Start find process */
			kad_search( node_id );
		} else {
			sprintf( reply_buf, reply_header );
			for( i = 0; i < addrsnum; i++ ) {
				sprintf( reply_buf, "%s\n", str_addr( &addrs[i], addrbuf ) );
			}
			log_debug( "WEB: Answer request for '%s':\n%s", reply_buf );

			sendto( clientfd, reply_buf, strlen( reply_buf ), 0, (struct sockaddr*) &clientaddr, sizeof(IP) );
		}

		done:;

		close( clientfd );
	}

	close( sock );

	return NULL;
}

void web_start( void ) {
	pthread_attr_t attr;

	if( str_isZero( gstate->web_port ) ) {
		return;
	}

	pthread_attr_init( &attr );
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_JOINABLE );

	if( pthread_create( &gstate->web_thread, &attr, &web_loop, NULL ) != 0 ) {
		log_crit( "WEB: Failed to create thread." );
	}
}

void web_stop( void ) {

	if( str_isZero( gstate->web_port ) ) {
		return;
	}

	if( pthread_join( gstate->web_thread, NULL ) != 0 ) {
		log_err( "WEB: Failed to join thread." );
	}
}
