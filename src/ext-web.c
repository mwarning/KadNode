
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


/* handle 'GET /search?foo.p2p' */
void handle_search( char *reply_buf, char *params ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	char hexbuf[HEX_LEN+1];
	UCHAR id[SHA_DIGEST_LENGTH];
	IP addrs[16];
	int addrsnum;
	int i, n;

	/* That is the lookup key */
	id_compute( id, params );
	log_debug( "WEB: Lookup '%s' as '%s'.", params, str_id( id, hexbuf ) );

	/* Check searches for node */
	addrsnum = N_ELEMS(addrs);
	if( kad_lookup_value( id, addrs, &addrsnum ) != 0 ) {
		/* Start find process */
		kad_search( id );
	} else {
		for( n = 0, i = 0; i < addrsnum; i++ ) {
			n += sprintf( reply_buf + n, "%s\n", str_addr( &addrs[i], addrbuf ) );
		}
	}
}

/* handle 'GET /announce?foo.p2p' */
void handle_announce( char *reply_buf, char *params ) {
	UCHAR id[SHA_DIGEST_LENGTH];
	id_compute( id, params );

	kad_announce( id, 1 );

	sprintf( reply_buf , "done\n" );
}

void* web_loop( void* _ ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	int val;
	struct timeval tv;
	int sock, clientfd;
	IP clientaddr, sockaddr;
	socklen_t addrlen_ret;
	char request_buf[1024];
	char reply_buf[1024];
	char *cmd, *params;
	char *space, *delim;
	int n;

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

		/* Only handle GET requests. */
		if( n < 6 || strncmp( "GET /", request_buf, 5 ) != 0 ) {
			goto done;
		} else {
			cmd = request_buf + 5;
		}

		/* Safety first */
		request_buf[n] = '\0';

		space = strchr( cmd, ' ' );
		if( space == NULL ) {
			goto done;
		} else {
			*space = '\0';
		}

		delim = strchr( cmd, '?' );
		if( delim == NULL ) {
			goto done;
		} else {
			*delim = '\0';
			params = delim + 1;
		}

		log_debug( "WEB: cmd: '%s', params: '%s'\n", cmd, params);

		reply_buf[0] = '\n';
		reply_buf[1] = '\0';

		if( match( cmd, "search" ) ) {
			handle_search( reply_buf, params );
		} else if( match( cmd, "announce" ) ) {
			handle_announce( reply_buf, params );
		} else {
			reply_buf[0] = '\0';
		}

		sendto( clientfd, reply_buf, strlen( reply_buf ), 0, (struct sockaddr*) &clientaddr, sizeof(IP) );

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
