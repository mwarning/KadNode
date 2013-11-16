
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
#include "results.h"
#ifdef AUTH
#include "ext-auth.h"
#endif
#ifdef FWD
#include "forwardings.h"
#endif
#include "ext-cmd.h"


const char* cmd_usage_str = 
"Usage:\n"
"	status\n"
"	lookup <id>\n"
#if 0
"	lookup_node <id>\n"
#endif
"	announce <id>[:<port>] [<minutes>]\n"
"	import <addr>\n"
"	export\n"
"	blacklist <addr>\n"
#ifdef FWD
"	list [blacklist|buckets|constants|forwardings|results|searches|storage|values]\n"
#else
"	list [blacklist|buckets|constants|results|searches|storage|values]\n"
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
	if( (rc = addr_parse_full( &addr, addr_str, DHT_PORT, gconf->af )) == ADDR_PARSE_SUCCESS ) {
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

int cmd_blacklist( REPLY *r, const char *addr_str ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	IP addr;

	if( addr_parse( &addr, addr_str, NULL, gconf->af ) != 0 ) {
		r_printf( r, "Invalid address.\n" );
		return 1;
	} else {
		kad_blacklist( &addr );
		r_printf( r, "Added to blacklist: %s\n", str_addr( &addr, addrbuf ) );
		return 0;
	}
}

/* Export up to 32 peer addresses - more would not fit into one UDP packet */
int cmd_export( REPLY *r ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	IP addr_array[32];
	size_t addr_num;
	size_t i;

	addr_num = N_ELEMS(addr_array);
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

int cmd_exec( REPLY *r, int argc, char **argv ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	time_t lifetime;
	int minutes;
	IP addrs[16];
	int port;
	char *p;
	int rc = 0;

	if( argc == 0 ) {

		/* Print usage */
		r_printf( r, cmd_usage_str );
		rc = 1;

	} else if( match( argv[0], "import" ) && argc == 2 ) {

		rc = cmd_import( r, argv[1] );
#if 0
	} else if( match( argv[0], "lookup_node" ) && argc == 2 ) {

		/* Check searches for node */
		rc = kad_lookup_node( argv[1, &addrs[0] );
		if( rc == 0 ) {
			r_printf( r, "%s\n", str_addr( &addrs[0], addrbuf ) );
		} else if( rc == -1 ) {
			r_printf( r ,"No search found.\n" );
			rc = 1;
		} else {
			r_printf( r ,"No node found.\n" );
			rc = 1;
		}
#endif
	} else if( match( argv[0], "lookup" ) && argc == 2 ) {

		size_t addrs_n = N_ELEMS(addrs);
		size_t i;

		/* Check searches for node */
		rc = kad_lookup_value( argv[1], addrs, &addrs_n );
		if( rc > 0 ) {
			r_printf( r ,"Search started - try again.\n" );
			rc = 1;
		} else if( addrs_n == 0 ) {
			r_printf( r ,"No nodes found.\n" );
			rc = 1;
		} else {
			for( i = 0; i < addrs_n; ++i ) {
				r_printf( r, "%s\n", str_addr( &addrs[i], addrbuf ) );
			}
		}
	} else if( match( argv[0], "status" ) && argc == 1 ) {

		/* Print node id and statistics */
		cmd_print_status( r );

	} else if( match( argv[0], "announce" ) && (argc == 2 || argc == 3) ) {

		if( argc == 3 ) {
			minutes = atoi( argv[2] );
		} else {
			minutes = 0;
		}

		/* round up to multiple of 30 minutes */
		if( minutes < 0 ) {
			minutes = -1;
			lifetime = LONG_MAX;
		} else {
			minutes = (30 * (minutes/30 + 1));
			lifetime = (time_now_sec() + (minutes * 60));
		}

		/* Find <id>:<port> delimiter */
		p = strchr( argv[1], ':' );
		if( p ) {
			*p = '\0';
		}

#ifdef AUTH
		if( auth_is_skey( argv[1] ) ) {
			if( p ) {
				r_printf( r ,"No port expected. Auth requests will be expected on the DHT port.\n" );
				rc = 1;
				goto end;
			} else {
				port = atoi( gconf->dht_port );
			}
		} else {
#endif
			if( p ) {
				port = port_parse( p + 1, -1 );
			} else {
				/* Preselect a random port */
				port = port_random();
			}
#ifdef AUTH
		}
#endif

		rc = values_add( argv[1], port, lifetime );
		if( rc < 0 ) {
			r_printf( r ,"Invalid port.\n" );
			rc = 1;
		} else {
#ifdef FWD
			forwardings_add( port, lifetime);
#endif
			if( minutes < 0 ) {
				r_printf( r ,"Announce value on port %d for the entire run time.\n", port );
			} else {
				r_printf( r ,"Announce value on port %d for %d minutes.\n", port, minutes );
			}
		}

	} else if( match( argv[0], "blacklist" ) && argc == 2 ) {

		rc = cmd_blacklist( r, argv[1] );

	} else if( match( argv[0], "export" ) && argc == 1 ) {

		rc = cmd_export( r );

	} else if( match( argv[0], "list" ) && argc == 2 ) {

		if( gconf->is_daemon == 1 ) {
			r_printf( r ,"The 'list' command is not available while KadNode runs as daemon.\n" );
			rc = 1;
			goto end;
		} else if( match( argv[1], "blacklist" ) ) {
			kad_debug_blacklist( STDOUT_FILENO );
			rc = 0;
		} else if( match( argv[1], "buckets" ) ) {
			kad_debug_buckets( STDOUT_FILENO );
			rc = 0;
		} else if( match( argv[1], "constants" ) ) {
			kad_debug_constants( STDOUT_FILENO );
			rc = 0;
#ifdef FWD
		} else if( match( argv[1], "forwardings" ) ) {
			forwardings_debug( STDOUT_FILENO );
			rc = 0;
#endif
		} else if( match( argv[1], "results" ) ) {
			results_debug( STDOUT_FILENO );
			rc = 0;
		} else if( match( argv[1], "searches" ) ) {
			kad_debug_searches( STDOUT_FILENO );
			rc = 0;
		} else if( match( argv[1], "storage" ) ) {
			kad_debug_storage( STDOUT_FILENO );
			rc = 0;
		} else if( match( argv[1], "values" ) ) {
			values_debug( STDOUT_FILENO );
			rc = 0;
		} else {
			dprintf( STDERR_FILENO, "Unknown argument.\n" );
			rc = 1;
		}
		r_printf( r ,"\nOutput send to console.\n" );

	} else if( match( argv[0], "shutdown" ) && argc == 1 ) {

		r_printf( r, "Shutting down ...\n" );
		gconf->is_running = 0;

	} else {
		/* print usage */
		r_printf( r, cmd_usage_str );
		rc = 1;
	}

	end:;
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

	if( str_isZero( gconf->cmd_port ) ) {
		return;
	}

	sock = net_bind( "CMD", "::1", gconf->cmd_port, NULL, IPPROTO_UDP, AF_INET6 );
	net_add_handler( sock, &cmd_remote_handler );

	if( gconf->is_daemon == 0 ) {
		/* Wait for other messages to be displayed */
		sleep(1);

		fprintf( stdout, "Press Enter for help.\n" );
		net_add_handler( STDIN_FILENO, &cmd_console_handler );
	}
}
