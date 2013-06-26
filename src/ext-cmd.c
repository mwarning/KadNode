
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/un.h>
#include <pthread.h>
#include <errno.h>
#include <stdarg.h>

#include "main.h"
#include "conf.h"
#include "utils.h"
#include "log.h"
#include "dht_wrapper.h"
#include "ext-cmd.h"


const char* cmd_usage_str = 
"Usage:\n"
"	status\n"
"	import <addr>\n"
"	lookup_node <id>\n"
"	lookup_values <id>\n"
"	search <id>\n"
"	announce <id> <port>\n"
"	blacklist <addr>\n"
"	export [v4|v6]\n"
#ifdef DEBUG
"	debug\n"
#endif
"	shutdown\n";

void r_init( REPLY *r ) {
	r->data[0] = '\0';
	r->size = 0;
}

/* Append a formatted string to the packet buffer */
void r_printf( REPLY *r, const char *format, ... ) {
	va_list vlist;
	int written;

	va_start( vlist, format );
	written = vsnprintf( r->data + r->size, M_SIZEOF(REPLY, data) - 1 , format, vlist );
	va_end( vlist );

	/* Ignore characters that do not fit into packet */
	if( written > 0 ) {
		r->size += written;
	} else {
		r->data[r->size] = '\0';
	}
}

/* Partition a string to the common argc/argv arguments */
void cmd_to_args( char *str, int *argc, char **argv, int max_argv ) {
    int len, i;

    len = strlen(str);
    *argc = 0;

	/* Zero out white/control characters  */
    for( i = 0; i <= len; i++ ) {
		if( str[i] <= ' ') {
            str[i] = '\0';
		}
    }

	/* Record strings */
    for( i = 0; i <= len; i++ ) {

        if( str[i] == '\0') {
			continue;
		}

		if( *argc >= max_argv - 1 ) {
			break;
		}

        argv[*argc] = &str[i];
        *argc += 1;
        i += strlen( &str[i] );
    }

	argv[*argc] = NULL;
}

int cmd_import( REPLY *r, const char *addr_str) {
	char addrbuf[FULL_ADDSTRLEN+1];
	IP addr;

	/* If the address contains no port - use the default port */
	if( addr_parse_full( &addr, addr_str, DHT_PORT, AF_UNSPEC ) == 0 ) {
		kad_ping( &addr );
		r_printf( r, "Send ping to: %s\n", str_addr( &addr, addrbuf ) );
		return 0;
	} else {
		r_printf( r, "Failed to parse address.\n" );
		return 1;
	}
}

void cmd_print_status( REPLY *r ) {
	r->size += kad_status( r->data + r->size, 1472 - r->size );
}

#ifdef DEBUG
void cmd_print_debug( REPLY *r ) {
	kad_debug( STDOUT_FILENO );
	r_printf( r ,"Debug output send to stdout.\n" );
}
#endif

int cmd_blacklist( REPLY *r, const char *addr_str ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	IP addr;

	if( addr_parse( &addr, addr_str, NULL, AF_INET6 ) != 0 ) {
		r_printf( r, "Invalid address.\n" );
		return 1;
	} else {
		kad_blacklist( &addr );
		r_printf( r, "%s added to blacklist.\n", str_addr( &addr, addrbuf ) );
		return 0;
	}
}

int print_export( REPLY *r, int af ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	IP addr_array[8];
	int addr_num = N_ELEMS(addr_array);
	int i;

	if( kad_export_nodes( af, addr_array, &addr_num ) != 0 ) {
		return 1;
	}

	for( i = 0; i < addr_num; ++i ) {
		r_printf( r, "%s\n", str_addr( &addr_array[i], addrbuf ) );
	}

	return addr_num;
}

int cmd_export( REPLY *r, const char *af ) {
	int count = 0;

	if( af == NULL ) {
		count += print_export( r, AF_INET );
		count += print_export( r, AF_INET6 );
	} else if( match( af, "v6" ) ) {
		count += print_export( r, AF_INET6 );
	} else if( match( af, "v4" ) ) {
		count += print_export( r, AF_INET );
	} else {
		r_printf( r, "Invalid argument.\n" );
		return 1;
	}

	if( count == 0 ) {
		r_printf( r, "No nodes found.\n" );
		return 1;
	}

	return 0;
}

int cmd_exec( REPLY * r, int argc, char **argv ) {
	UCHAR id[SHA_DIGEST_LENGTH];
	char addrbuf[FULL_ADDSTRLEN+1];
	char hexbuf[HEX_LEN+1];
	IP addrs[16];
	int port;
	int rc = 0;

	if( argc == 0 ) {

		/* Print usage */
		r_printf( r, cmd_usage_str );
		rc = 1;

	} else if( match( argv[0], "import" ) && argc == 2 ) {

		rc = cmd_import( r, argv[1] );

	} else if( match( argv[0], "lookup_node" ) && argc == 2 ) {

		/* That is the node id to lookup */
		id_compute( id, argv[1] );

		/* Check searches for node */
		if( kad_lookup_node( AF_UNSPEC, id, &addrs[0] ) == 0 ) {
			r_printf( r, "%s\n", str_addr( &addrs[0], addrbuf ) );
			rc = 0;
		} else {
			r_printf( r ,"No node found.\n" );
			rc = 1;
		}
	} else if( match( argv[0], "lookup_values" ) && argc == 2 ) {

		/* That is the value id to lookup */
		id_compute( id, argv[1] );

		int addrs_n = N_ELEMS(addrs);
		int i;

		/* Check searches for node */
		if( kad_lookup_values( AF_UNSPEC, id, addrs, &addrs_n ) == 0 ) {
			for( i = 0; i < addrs_n; ++i ) {
				r_printf( r, "%s\n", str_addr( &addrs[i], addrbuf ) );
			}
			rc = 0;
		} else {
			r_printf( r ,"No node found.\n" );
			rc = 1;
		}
	} else if( match( argv[0], "search" ) && argc == 2 ) {

		/* That is the id to lookup nodes for */
		id_compute( id, argv[1] );

		/* Start find process */
		kad_search( AF_UNSPEC, id );

		r_printf( r, "Search started for %s.\n", str_id( id, hexbuf ) );

	} else if( match( argv[0], "status" ) && argc == 1 ) {

		/* Print node id and statistics */
		cmd_print_status( r );

	} else if( match( argv[0], "announce" ) && argc == 3 ) {

		/* That is the id to announce using the IP address of this instance */
		id_compute( id, argv[1] );

		port = atoi( argv[2] );

		if( port >= 1 && port <= 65535 ) {
			kad_announce( AF_INET6, id, port );
		} else {
			r_printf( r ,"Invalid port.\n" );
			rc = 1;
		}
#ifdef DEBUG
	} else if( match( argv[0], "debug" ) && argc == 1 ) {

		cmd_print_debug( r );
#endif
	} else if( match( argv[0], "blacklist" ) && argc == 2 ) {

		rc = cmd_blacklist( r, argv[1] );

	} else if( match( argv[0], "export" ) && (argc == 1 || argc == 2) ) {

		rc = cmd_export( r, (argc == 2 ) ? argv[1] : NULL );

	} else if( match( argv[0], "shutdown" ) && argc == 1 ) {

		r_printf( r, "Shutting down ...\n" );
		gstate->is_running = 0;

	} else {
		/* print usage */
		r_printf( r, cmd_usage_str );
		rc = 1;
	}

	return rc;
}

void *cmd_remote_loop( void *_ ) {
	struct timeval tv;
	int rc;
	char* argv[32];
	int argc;

	int sock;
    fd_set fds;
	IP clientaddr, sockaddr;
	socklen_t addrlen_ret;
	char request[1500];
	REPLY reply;
	char addrbuf[FULL_ADDSTRLEN+1];

	if( addr_parse( &sockaddr, "::1", gstate->cmd_port, AF_INET6 ) != 0 ) {
		log_err( "CMD: Failed to parse address." );
		return NULL;
	}

	sock = socket( sockaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP );
	if( sock < 0 ) {
		log_err( "CMD: Failed to create socket: '%s'", strerror( errno ) );
		return NULL;
	}

	/* Set receive timeout */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if( setsockopt( sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv) ) < 0) {
		log_err( "CMD: Failed to set socket option: '%s'", strerror( errno ) );
		return NULL;
	}

	if( bind( sock, (struct sockaddr*) &sockaddr, sizeof(IP) ) < 0 ) {
		log_err( "CMD: Failed to bind socket to address: '%s'", strerror( errno ) );
		return NULL;
	}

	log_info( "CMD: Bind to %s", str_addr( &sockaddr, addrbuf ) );

    while( gstate->is_running ) {
		FD_ZERO( &fds );
		FD_SET( sock, &fds );

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		rc = select( sock+1, &fds, NULL, NULL, &tv );
		if( rc <= 0 ) {
			continue;
		}

		addrlen_ret = sizeof(IP);
		rc = recvfrom( sock, request, sizeof(request) - 1, 0, (struct sockaddr*)&clientaddr, &addrlen_ret );
		if( rc <= 0 ) {
			continue;
		} else {
			request[rc] = '\0';
		}

		/* init reply and reserve room for return status */
		r_init( &reply );
		r_printf( &reply, "_" );

		/* split up the command line into an argument array */
		cmd_to_args( request, &argc, &argv[0], N_ELEMS(argv) );

		/* execute command line */
		rc = cmd_exec( &reply, argc, argv );

		/* insert return code */
		reply.data[0] = (rc == 0) ? '0' : '1';

		rc = sendto( sock, reply.data, reply.size, 0, (struct sockaddr *)&clientaddr, sizeof(IP) );
	}

	close( sock );

	return NULL;
}

void cmd_console_loop() {
	char request[512];
	REPLY reply;
	char *argv[32];
	int argc;
	struct timeval tv;
    fd_set fds;
	int rc;

	fprintf( stdout, "Press Enter for help.\n" );

    while( gstate->is_running ) {
		FD_ZERO( &fds );
		FD_SET( STDIN_FILENO, &fds );

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		rc = select( STDIN_FILENO+1, &fds, NULL, NULL, &tv );

		if( rc == 0 ) {
			continue;
		}

		if( rc < 0 ) {
			break;
		}

		/* read line */
		fgets( request, sizeof(request), stdin );

		/* split up the command line into an argument array */
		cmd_to_args( request, &argc, &argv[0], N_ELEMS(argv) );

		/* init reply */
		r_init( &reply );

		/* execute command line */
		rc = cmd_exec( &reply, argc, argv );

		if( rc == 0 ) {
			fprintf( stdout, "%.*s\n", (int) reply.size, reply.data );
		} else {
			fprintf( stderr, "%.*s\n", (int) reply.size, reply.data );
		}
    }
}

void cmd_start( void ) {
	pthread_attr_t attr;

	if( str_isZero( gstate->cmd_port ) ) {
		return;
	}

	pthread_attr_init( &attr );
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_JOINABLE );

	if( pthread_create( &gstate->cmd_thread, &attr, &cmd_remote_loop, NULL ) != 0 ) {
		log_crit( "CMD: Failed to create thread." );
	}
}

void cmd_stop() {

	if( str_isZero( gstate->cmd_port ) ) {
		return;
	}

	if( pthread_join( gstate->cmd_thread, NULL ) != 0 ) {
		log_err( "CMD: Failed to join thread." );
	}
}
