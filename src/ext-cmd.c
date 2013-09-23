
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/un.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>

#include "main.h"
#include "conf.h"
#include "utils.h"
#include "log.h"
#include "kad.h"
#include "net.h"
#include "values.h"
#ifdef FWD
#include "forwardings.h"
#endif
#include "ext-cmd.h"


const char* cmd_usage_str = 
"Usage:\n"
"	status\n"
"	search <id>\n"
"	lookup <id>\n"
#if 0
"	lookup_node <id>\n"
#endif
"	announce <id> [<port>] [<minutes>]\n"
"	import <addr>\n"
"	export\n"
"	blacklist <addr>\n"
#ifdef FWD
"	list [values|forwardings]\n"
#else
"	list [values]\n"
#endif
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
	int rc;

	/* If the address contains no port - use the default port */
	if( (rc = addr_parse_full( &addr, addr_str, DHT_PORT, gstate->af )) == ADDR_PARSE_SUCCESS ) {
		if( kad_ping( &addr ) == 0 ) {
			r_printf( r, "Send ping to: %s\n", str_addr( &addr, addrbuf ) );
			return 0;
		} else {
			r_printf( r, "Failed to send ping.\n" );
			return 1;
		}
	} else if( rc == ADDR_PARSE_CANNOT_RESOLVE ) {
		r_printf( r, "Failed to resolve address.\n" );
		return 1;
	} else if( rc == ADDR_PARSE_NO_ADDR_FOUND ) {
		r_printf( r, "Failed to aquire address of required protocol.\n" );
		return 1;
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
	r_printf( r ,"\nDebug output send to stdout.\n" );
}
#endif

int cmd_blacklist( REPLY *r, const char *addr_str ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	IP addr;

	if( addr_parse( &addr, addr_str, NULL, gstate->af ) != 0 ) {
		r_printf( r, "Invalid address.\n" );
		return 1;
	} else {
		kad_blacklist( &addr );
		r_printf( r, "Added to blacklist: %s\n", str_addr( &addr, addrbuf ) );
		return 0;
	}
}

int cmd_export( REPLY *r ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	IP addr_array[32];
	int addr_num = N_ELEMS(addr_array);
	int i;

	if( kad_export_nodes( addr_array, &addr_num ) != 0 ) {
		return 1;
	}

	for( i = 0; i < addr_num; ++i ) {
		r_printf( r, "%s\n", str_addr( &addr_array[i], addrbuf ) );
	}

	if( i == 0 ) {
		r_printf( r, "No good nodes found.\n" );
		return 1;
	}

	return 0;
}

int cmd_list_values( REPLY *r ) {
	struct value_t *item;
	char hexbuf[HEX_LEN+1];
	time_t now;
	int counter;

	counter = 0;
	now = time_now_sec();
	item = values_get();
	r_printf( r, "id:port | refreshed min. ago | lifetime min. remaining\n");
	while( item ) {
		r_printf(
			r, " %s:%hu | %ld | %ld\n",
			str_id( item->value_id, hexbuf ), item->port,
			(item->refreshed == -1) ? (-1) : ((now - item->refreshed) / 60),
			(item->lifetime == LONG_MAX) ? (-1) : ((item->lifetime -  now) / 60)
		);
		counter++;
		item = item->next;
	}

	r_printf( r, "Found %d items.\n", counter );
	return 0;
}

#ifdef FWD
int cmd_list_forwardings( REPLY *r ) {
	struct forwarding_t *item;
	time_t now;
	int counter;

	counter = 0;
	now = time_now_sec();
	item = forwardings_get();
	r_printf( r, "port | refreshed min. ago | lifetime min. remaining\n");
	while( item ) {
		r_printf(
			r, "%hu | %ld | %ld\n",
			item->port,
			(item->refreshed == 0) ? (-1) : ((now - item->refreshed) / 60),
			(item->lifetime == LONG_MAX ) ? (-1) : ((item->lifetime -  now) / 60)
		);
		counter++;
		item = item->next;
	}

	r_printf( r, "Found %d items.\n", counter );
	return 0;
}
#endif

int cmd_exec( REPLY * r, int argc, char **argv ) {
	UCHAR id[SHA_DIGEST_LENGTH];
	char addrbuf[FULL_ADDSTRLEN+1];
	char hexbuf[HEX_LEN+1];
	time_t lifetime;
	int minutes;
	IP addrs[16];
	int port;
	int rc = 0;

	if( argc == 0 ) {

		/* Print usage */
		r_printf( r, cmd_usage_str );
		rc = 1;

	} else if( match( argv[0], "import" ) && argc == 2 ) {

		rc = cmd_import( r, argv[1] );
#if 0
	} else if( match( argv[0], "lookup_node" ) && argc == 2 ) {

		/* That is the node id to lookup */
		id_compute( id, argv[1] );

		/* Check searches for node */
		rc = kad_lookup_node( id, &addrs[0] );
		if( rc == 0 ) {
			r_printf( r, "%s\n", str_addr( &addrs[0], addrbuf ) );
		} else if( rc == 1 ) {
			r_printf( r ,"No search found.\n" );
			rc = 1;
		} else {
			r_printf( r ,"No node found.\n" );
			rc = 1;
		}
#endif
	} else if( match( argv[0], "lookup" ) && argc == 2 ) {

		/* That is the value id to lookup */
		id_compute( id, argv[1] );

		int addrs_n = N_ELEMS(addrs);
		int i;

		/* Check searches for node */
		rc = kad_lookup_value( id, addrs, &addrs_n );
		if( rc == 0 ) {
			for( i = 0; i < addrs_n; ++i ) {
				r_printf( r, "%s\n", str_addr( &addrs[i], addrbuf ) );
			}
		} else if( rc == 1 ) {
			r_printf( r ,"No search found.\n" );
			rc = 1;
		} else {
			r_printf( r ,"No nodes found.\n" );
			rc = 1;
		}
	} else if( match( argv[0], "search" ) && argc == 2 ) {

		/* That is the id to lookup nodes for */
		id_compute( id, argv[1] );

		/* Start find process */
		kad_search( id );

		r_printf( r, "Search started for: %s\n", str_id( id, hexbuf ) );

	} else if( match( argv[0], "status" ) && argc == 1 ) {

		/* Print node id and statistics */
		cmd_print_status( r );

	} else if( match( argv[0], "announce" ) && (argc == 2 || argc == 3 || argc == 4) ) {

		/* The value id to announce using the IP address of this instance */
		id_compute( id, argv[1] );

		if( argc == 4 ) {
			port = atoi( argv[2] );
			minutes = atoi( argv[3] );
		} else if( argc == 3 ) {
			port = atoi( argv[2] );
			minutes = 0;
		} else {
			/* Kademlia doesn't accept port 0 */
			port = 1;
			minutes = 0;
		}

		if( port < 1 || port > 65535 ) {
			r_printf( r ,"Invalid port.\n" );
			rc = 1;
		} else if( minutes < -1 ) {
			r_printf( r ,"Invalid time.\n" );
			rc = 1;
		} else {
			/* round up to multiple of 30 minutes */
			minutes = (minutes < 0) ? -1 : (30 * (minutes/30 + 1));
			lifetime = (minutes < 0) ? LONG_MAX : (time_now_sec() + (minutes * 60));

			values_add( id, port, lifetime );
#ifdef FWD
			forwardings_add( port,  lifetime);
#endif
			if( minutes > -1 ) {
				r_printf( r ,"Announce value id %s on port %d for %d minutes.\n", str_id( id, hexbuf ), port, minutes );
			} else {
				r_printf( r ,"Announce value id %s on port %d for entire run time.\n", str_id( id, hexbuf ), port );
			}
		}
#ifdef DEBUG
	} else if( match( argv[0], "debug" ) && argc == 1 ) {

		cmd_print_debug( r );
#endif
	} else if( match( argv[0], "blacklist" ) && argc == 2 ) {

		rc = cmd_blacklist( r, argv[1] );

	} else if( match( argv[0], "export" ) && argc == 1 ) {

		rc = cmd_export( r );

	} else if( match( argv[0], "list" ) && argc == 2 ) {

		if( match( argv[1], "values" ) ) {
			rc = cmd_list_values( r );
#ifdef FWD
		} else if( match( argv[1], "forwardings" ) ) {
			rc = cmd_list_forwardings( r );
#endif
		} else {
			r_printf( r ,"Argument is wrong.\n");
			rc = 1;
		}

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

void cmd_remote_handler( int rc, int sock ) {
	char* argv[32];
	int argc;

	IP clientaddr;
	socklen_t addrlen_ret;
	char request[1500];
	REPLY reply;

	addrlen_ret = sizeof(IP);
	rc = recvfrom( sock, request, sizeof(request) - 1, 0, (struct sockaddr*)&clientaddr, &addrlen_ret );
	if( rc <= 0 ) {
		return;
	} else {
		request[rc] = '\0';
	}

	/* Initialize reply and reserve room for return status */
	r_init( &reply );
	r_printf( &reply, "_" );

	/* Split up the command line into an argument array */
	cmd_to_args( request, &argc, &argv[0], N_ELEMS(argv) );

	/* Execute command line */
	rc = cmd_exec( &reply, argc, argv );

	/* Insert return code */
	reply.data[0] = (rc == 0) ? '0' : '1';

	rc = sendto( sock, reply.data, reply.size, 0, (struct sockaddr *)&clientaddr, sizeof(IP) );
}

void cmd_console_handler( int rc, int fd ) {
	char request[512];
	char *req;
	REPLY reply;
	char *argv[32];
	int argc;

	if( rc == 0 ) {
		return;
	}

	/* Read line */
	req = fgets( request, sizeof(request), stdin );

	if( req == NULL ) {
		return;
	}

	/* Split up the command line into an argument array */
	cmd_to_args( request, &argc, &argv[0], N_ELEMS(argv) );

	/* Initialize reply */
	r_init( &reply );

	/* Execute command line */
	rc = cmd_exec( &reply, argc, argv );

	if( rc == 0 ) {
		fprintf( stdout, "%.*s\n", (int) reply.size, reply.data );
	} else {
		fprintf( stderr, "%.*s\n", (int) reply.size, reply.data );
	}
}

void cmd_setup( void ) {
	int sock;

	if( str_isZero( gstate->cmd_port ) ) {
		return;
	}

	sock = net_bind( "CMD", "::1", gstate->cmd_port, NULL, IPPROTO_UDP, AF_INET6 );
	net_add_handler( sock, &cmd_remote_handler );

	if( gstate->is_daemon == 0 ) {
		/* Wait for other messages to be displayed */
		sleep(1);

		fprintf( stdout, "Press Enter for help.\n" );
		net_add_handler( STDIN_FILENO, &cmd_console_handler );
	}
}
