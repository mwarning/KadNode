
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "ext-web.h"


/* handle 'GET /lookup?foo.p2p' */
void handle_lookup( char *reply_buf, char *params ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	char hexbuf[SHA1_HEX_LENGTH+1];
	UCHAR id[SHA1_BIN_LENGTH];
	IP addrs[16];
	int addrsnum;
	int i, n;

	/* That is the lookup key */
	id_compute( id, params );
	log_debug( "WEB: Lookup '%s' as '%s'.", params, str_id( id, hexbuf ) );

	/* Lookup id - starts search when not already done */
	addrsnum = N_ELEMS(addrs);
	if( kad_lookup_value( id, addrs, &addrsnum ) == 0 ) {
		for( n = 0, i = 0; i < addrsnum; i++ ) {
			n += sprintf( reply_buf + n, "%s\n", str_addr( &addrs[i], addrbuf ) );
		}
	}
}

/* handle 'GET /announce?foo.p2p' */
void handle_announce( char *reply_buf, char *params ) {
	UCHAR id[SHA1_BIN_LENGTH];
	id_compute( id, params );

	kad_announce( id, 1 );

	sprintf( reply_buf , "done\n" );
}

/* handle 'GET /blacklist?1.2.3.4' */
void handle_blacklist( char *reply_buf, char *params ) {
	IP addr;

	if( addr_parse( &addr, params, NULL, AF_UNSPEC ) == 0 ) {
		kad_blacklist( &addr );
		sprintf( reply_buf , "done\n" );
	} else {
		sprintf( reply_buf , "failed\n" );
	}
}

void web_handler( int rc, int sock ) {
	int clientfd;
	IP clientaddr;
	socklen_t addrlen_ret;
	char request_buf[1024];
	char reply_buf[1024];
	char *cmd, *params;
	char *space, *delim;
	int n;

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

	if( match( cmd, "lookup" ) ) {
		handle_lookup( reply_buf, params );
	} else if( match( cmd, "announce" ) ) {
		handle_announce( reply_buf, params );
	} else if( match( cmd, "blacklist" ) ) {
		handle_blacklist( reply_buf, params );
	} else {
		reply_buf[0] = '\0';
	}

	sendto( clientfd, reply_buf, strlen( reply_buf ), 0, (struct sockaddr*) &clientaddr, sizeof(IP) );

	done:;

	close( clientfd );
}

void web_setup( void ) {
	int sock;

	if( str_isZero( gstate->web_port ) ) {
		return;
	}

	sock = net_bind( "WEB", "::1", gstate->web_port, NULL, IPPROTO_TCP, AF_INET6 );
	net_add_handler( sock, &web_handler );
}
