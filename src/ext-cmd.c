
#define _WITH_DPRINTF
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "main.h"
#include "conf.h"
#include "utils.h"
#include "log.h"
#include "kad.h"
#include "net.h"
#include "announces.h"
#include "searches.h"
#ifdef BOB
#include "ext-bob.h"
#endif
#ifdef FWD
#include "ext-fwd.h"
#endif
#include "ext-cmd.h"


static const char* cmd_usage =
	"Usage:\n"
	"	status\n"
	"	lookup <query>\n"
	"	announce [<query>[:<port>] [<minutes>]]\n"
	"	ping <addr>\n"
	"	blacklist <addr>\n";

const char* cmd_usage_debug =
	"	list nodes|blacklist|buckets|constants"
#ifdef FWD
	"|forwardings"
#endif
#ifdef BOB
	"|keys"
#endif
	"|results|searches|storage|announcements\n";

#define REPLY_DATA_SIZE 1472

// A UDP packet sized reply
struct reply_t {
	char data[REPLY_DATA_SIZE];
	ssize_t size;
	// Prevent secret keys to be shown to other users
	bool allow_debug;
};

void r_init( struct reply_t *r, bool allow_debug ) {
	r->data[0] = '\0';
	r->size = 0;
	r->allow_debug = allow_debug;
}

// Append a formatted string to the packet buffer
void r_printf( struct reply_t *r, const char *format, ... ) {
	va_list vlist;
	int written;

	va_start( vlist, format );
	written = vsnprintf( r->data + r->size, REPLY_DATA_SIZE - 1, format, vlist );
	va_end( vlist );

	// Ignore characters that do not fit into packet
	if( written > 0 ) {
		r->size += written;
	} else {
		r->data[r->size] = '\0';
	}
}

int cmd_ping( struct reply_t *r, const char *addr_str) {
	IP addr;
	int rc;

	// If the address contains no port - use the default port
	if( (rc = addr_parse_full( &addr, addr_str, DHT_PORT, gconf->af )) == 0 ) {
		if( kad_ping( &addr ) == 0 ) {
			r_printf( r, "Send ping to: %s\n", str_addr( &addr ) );
			return 0;
		}
		r_printf( r, "Failed to send ping.\n" );
	} else if( rc == -1 ) {
		r_printf( r, "Failed to parse address.\n" );
	} else {
		r_printf( r, "Failed to resolve address.\n" );
	}

	return 1;
}

void cmd_print_status( struct reply_t *r ) {
	r->size += kad_status( r->data + r->size, REPLY_DATA_SIZE - r->size );
}

int cmd_blacklist( struct reply_t *r, const char *addr_str ) {
	IP addr;

	if( addr_parse( &addr, addr_str, NULL, gconf->af ) == 0 ) {
		kad_blacklist( &addr );
		r_printf( r, "Added to blacklist: %s\n", str_addr( &addr ) );
		return 0;
	} else {
		r_printf( r, "Invalid address.\n" );
		return 1;
	}
}

// Export up to 32 peer addresses - more would not fit into one UDP packet
int cmd_debug_nodes( struct reply_t *r ) {
	IP addr_array[32];
	size_t addr_num;
	size_t i;

	addr_num = kad_export_nodes( addr_array, N_ELEMS(addr_array) );

	if( addr_num == 0 ) {
		r_printf( r, "No good nodes found.\n" );
		return 1;
	}

	for( i = 0; i < addr_num; ++i ) {
		r_printf( r, "%s\n", str_addr( &addr_array[i] ) );
	}

	return 0;
}

int cmd_announce( struct reply_t *r, const char hostname[], int port, int minutes ) {
	time_t lifetime;

	if( port < 0 || port > 65534 ) {
		return 1;
	}

	if( minutes < 0 ) {
		lifetime = LONG_MAX;
	} else {
		// Round up to multiple of 30 minutes
		minutes = (30 * (minutes / 30 + 1));
		lifetime = (time_now_sec() + (minutes * 60));
	}

	if( kad_announce( hostname, port, lifetime ) >= 0 ) {
#ifdef FWD
		// Add port forwarding
		if( port != 0 ) {
			fwd_add( port, lifetime );
		}
#endif
		if( minutes < 0 ) {
			r_printf( r ,"Start regular announcements for the entire run time (port %d).\n", port );
		} else {
			r_printf( r ,"Start regular announcements for %d minutes (port %d).\n", minutes, port );
		}
	} else {
		r_printf( r ,"Invalid port or query too long.\n" );
		return 1;
	}

	return 0;
}

// Match a format string with only %n at the end
int match( const char input[], const char fmt[] ) {
	int n = -1;
	sscanf( input, fmt, &n );
	return (n > 0 && input[n] == '\0');
}

int cmd_exec( struct reply_t *r, const char input[] ) {
	struct value_t *value;
	int minutes;
	IP addrs[16];
	char hostname[256];
	int count;
	int port;
	size_t i;
	int rc = 0;

	if( sscanf( input, " ping %255s ", hostname ) == 1 ) {
		rc = cmd_ping( r, hostname );
	} else if( sscanf( input, " lookup %255s ", hostname ) == 1 ) {
		// Check searches for node
		rc = kad_lookup( hostname, addrs, N_ELEMS(addrs) );

		if( rc > 0 ) {
			for( i = 0; i < rc; ++i ) {
				r_printf( r, "%s\n", str_addr( &addrs[i] ) );
			}
		} else if( rc < 0 ) {
			r_printf( r ,"Some error occured.\n" );
			rc = 1;
		} else if( rc == 0 ) {
			r_printf( r ,"Search in progress.\n" );
			rc = 1;
		} else {
			r_printf( r ,"Search started.\n" );
			rc = 1;
		}
	} else if( match( input, " status %n" ) ) {
		// Print node id and statistics
		cmd_print_status( r );
	} else if( match( input, " announce %n" ) ) {
		// Announce all values
		count = 0;
		value = announces_get();
		while( value ) {
			kad_announce_once( value->id, value->port );
			count++;
			value = value->next;
		}
		r_printf( r, "%d announcements started.\n", count );
	} else if( sscanf( input, " announce %255[^:] ", hostname ) == 1 ) {
		rc = cmd_announce( r, hostname, 0, -1 );
	} else if( sscanf( input, " announce %255[^:] %d ", hostname, &minutes) == 2 ) {
		rc = cmd_announce( r, hostname, 0, minutes );
	} else if( sscanf( input, " announce %255[^:]:%d %d ", hostname, &port, &minutes) == 3 ) {
		rc = cmd_announce( r, hostname, port, minutes );
	} else if( match( input, " blacklist %255[^:]%n" ) ) {
		rc = cmd_blacklist( r, hostname );
	} else if( match( input, " list %*s %n" ) && r->allow_debug ) {
		if( gconf->is_daemon == 1 ) {
			r_printf( r ,"The 'list' command is not available while KadNode runs as daemon.\n" );
			rc = 1;
		} else if( match( input, " list nodes %n" )) {
			rc = cmd_debug_nodes( r );
		} else if( match( input, " list blacklist %n" )) {
			kad_debug_blacklist( STDOUT_FILENO );
		} else if( match( input, " list buckets %n" )) {
			kad_debug_buckets( STDOUT_FILENO );
		} else if( match( input, " list constants %n" )) {
			kad_debug_constants( STDOUT_FILENO );
#ifdef FWD
		} else if( match( input, " list forwardings %n" )) {
			fwd_debug( STDOUT_FILENO );
#endif
#ifdef BOB
		} else if( match( input, " list keys %n" )) {
			bob_debug_keys( STDOUT_FILENO );
#endif
		} else if( match( input, " list results %n" )) {
			searches_debug( STDOUT_FILENO );
		} else if( match( input, " list searches %n" )) {
			kad_debug_searches( STDOUT_FILENO );
		} else if( match( input, " list storage %n" )) {
			kad_debug_storage( STDOUT_FILENO );
		} else if( match( input, " list announcements %n" )) {
			announces_debug( STDOUT_FILENO );
		} else {
			dprintf( STDERR_FILENO, "Unknown command.\n" );
			rc = 1;
		}
		//r_printf( r ,"\nOutput send to console.\n" );
	} else {
		// Print usage
		r_printf( r, cmd_usage );
		if( r->allow_debug ) {
			r_printf( r, cmd_usage_debug );
		}
		rc = 1;
	}

	return rc;
}

void cmd_remote_handler( int rc, int sock ) {
	IP clientaddr;
	socklen_t addrlen;
	char request[1500];
	struct reply_t reply;

	addrlen = sizeof(IP);
	rc = recvfrom( sock, request, sizeof(request) - 1, 0, (struct sockaddr*)&clientaddr, &addrlen );
	if( rc <= 0 ) {
		return;
	} else {
		request[rc] = '\0';
	}

	// Initialize reply and reserve room for return status
	r_init( &reply, false );
	r_printf( &reply, "_" );

	// Execute command line
	rc = cmd_exec( &reply, request );

	// Insert return code
	reply.data[0] = (rc == 0) ? '0' : '1';

	addrlen = addr_len( &clientaddr );
	rc = sendto( sock, reply.data, reply.size, 0, (struct sockaddr *)&clientaddr, addrlen );
}

void cmd_console_handler( int rc, int fd ) {
	char request[512];
	struct reply_t reply;
	char *req;

	if( rc == 0 ) {
		return;
	}

	// Read line
	req = fgets( request, sizeof(request), stdin );

	if( req == NULL ) {
		return;
	}

	// Initialize reply
	r_init( &reply, true );

	// Execute command line
	rc = cmd_exec( &reply, request );

	fprintf( rc ? stderr : stdout, "%.*s\n", (int) reply.size, reply.data );
}

void cmd_setup( void ) {
	int sock;

	if( str_isZero( gconf->cmd_port ) ) {
		return;
	}

	sock = net_bind( "CMD", "::1", gconf->cmd_port, NULL, IPPROTO_UDP, AF_UNSPEC );
	net_add_handler( sock, &cmd_remote_handler );

	if( gconf->is_daemon == 0 && gconf->cmd_disable_stdin == 0 ) {
		// Wait for other messages to be displayed
		sleep( 1 );

		fprintf( stdout, "Press Enter for help.\n" );
		net_add_handler( STDIN_FILENO, &cmd_console_handler );
	}
}

void cmd_free( void ) {
	// Nothing to do
}
