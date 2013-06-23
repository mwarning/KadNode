
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "main.h"
#include "log.h"
#include "utils.h"
#include "conf.h"


/* Global object variables */
struct obj_gstate *gstate = NULL;

const char *version = "KadNode v"MAIN_VERSION" ( "
"Features:"
#ifdef CMD
" cmd"
#endif
#ifdef DNS
" dns"
#endif
#ifdef NSS
" nss"
#endif
#ifdef WEB
" web"
#endif
" )\n\n";

const char *usage = "KadNode - A P2P name resolution daemon (IPv4/IPv6)\n"
"A Wrapper for the Kademlia implementation of a Distributed Hash Table (DHT)\n"
"with several interfaces for DNS, an interactive command line, web and NSS.\n"
"\n"
"Usage: kadnode [OPTIONS]*\n"
"\n"
" --id		Set the node id.\n"
"		Default: <random>\n\n"
" --user		Change the UUID after start.\n\n"
" --port		Bind to this port.\n"
"		Default: "DHT_PORT"\n\n"
" --mcast-addr4	Use IPv4 multicast address for bootstrapping.\n"
"		Default: "DHT_ADDR4_MCAST"\n\n"
" --mcast-addr6	Use IPv6 multicast address for bootstrapping.\n"
"		Default: "DHT_ADDR6_MCAST"\n\n"
" --ifce		Bind to this interface.\n"
"		Default: <any>\n\n"
" --daemon	Run the node in background.\n\n"
" --verbosity	Verbosity level: quiet, verbose or debug.\n"
"		Default: verbose\n\n"
" --pidfile	Write process pid to a file.\n\n"
#ifdef CMD
" --cmd-port	Bind the remote control interface to this local port.\n"
"		Default: "CMD_PORT"\n\n"
#endif
#ifdef DNS
" --dns-port	Bind the DNS server to this local port.\n"
"		Default: "DNS_PORT"\n\n"
#endif
#ifdef NSS
" --nss-port	Bind the Network Service Switch to this local port.\n"
"		Default: "NSS_PORT"\n\n"
#endif
#ifdef WEB
" --web-port	Bind the web server to this local port.\n"
"		Default: "WEB_PORT"\n\n"
#endif
" --ipv4-only\n"
" --ipv6-only\n"
"		Use IPv4 or IPv6 only for the DHT.\n\n"
" -h, --help	Print this help.\n\n"
" -v, --version	Print program version.\n\n";

void conf_init() {
	gstate = (struct obj_gstate *) malloc( sizeof(struct obj_gstate) );

	memset( gstate, '\0', sizeof(struct obj_gstate) );

	id_random( gstate->node_id, SHA_DIGEST_LENGTH );

	gstate->sock4 = -1;
	gstate->sock6 = -1;

	gstate->is_running = 1;
	gstate->verbosity = VERBOSITY_VERBOSE;

	gstate->dht_port = strdup( DHT_PORT );
	gstate->mcast_addr4 = strdup( DHT_ADDR4_MCAST );
	gstate->mcast_addr6 = strdup( DHT_ADDR6_MCAST );

#ifdef CMD
	gstate->cmd_port = strdup( CMD_PORT );
#endif

#ifdef DNS
	gstate->dns_port = strdup( DNS_PORT );
#endif

#ifdef NSS
	gstate->nss_port = strdup( NSS_PORT );
#endif

#ifdef WEB
	gstate->web_port = strdup( WEB_PORT );
#endif
}

void conf_check() {
	char hexbuf[HEX_LEN+1];

	log_info( "Starting KadNode v"MAIN_VERSION"." );
	log_info( "Own ID: %s", str_id( gstate->node_id, hexbuf ) );

	if( gstate->is_daemon ) {
		log_info( "Mode: Daemon" );
	} else {
		log_info( "Mode: Foreground" );
	}

	switch( gstate->verbosity ) {
		case VERBOSITY_QUIET:
			log_info( "Verbosity: Quiet" );
			break;
		case VERBOSITY_VERBOSE:
			log_info( "Verbosity: Verbose" );
			break;
		case VERBOSITY_DEBUG:
			log_info( "Verbosity: Debug" );
			break;
		default:
			log_err( "Invalid verbosity level." );
	}

	if( gstate->ipv4_only && gstate->ipv4_only ) {
		log_err( "Cannot disable both IPv4 and IPv6 support." );
	} else if( gstate->ipv4_only ) {
		log_info( "IPv4 only mode." );
	} else if( gstate->ipv6_only ){
		log_info( "IPv6 only mode." );
	} else {
		log_info( "IPv6/IPv4 dual mode." );
	}
}

void conf_free() {

	free( gstate->user );
	free( gstate->pid_file );
	free( gstate->dht_port );
	free( gstate->dht_ifce );
	free( gstate->mcast_addr4 );
	free( gstate->mcast_addr6 );

#ifdef CMD
	free( gstate->cmd_port );
#endif
#ifdef DNS
	free( gstate->dns_port );
#endif
#ifdef NSS
	free( gstate->nss_port );
#endif
#ifdef WEB
	free( gstate->web_port );
#endif

	free( gstate );
}

void conf_arg_expected( const char *var ) {
	log_err( "CFG: Argument expected for option %s.", var );
}

void conf_no_arg_expected( const char *var ) {
	log_err( "CFG: No argument expected for option %s.", var );
}

/* free the old string and set the new */
void conf_str( char *var, char** dst, char *src ) {
	if( src == NULL ) {
		conf_arg_expected( var );
	}

	free( *dst );
	*dst = strdup( src );
}

void conf_handle( char *var, char *val ) {

	if( match( var, "--id" ) ) {
		/* Compute node id */
		id_compute( gstate->node_id, val );
	} else if( match( var, "--pidfile" ) ) {
		conf_str( var, &gstate->pid_file, val );
	} else if( match( var, "--verbosity" ) ) {
		if( match( val, "quiet" ) ) {
			gstate->verbosity = VERBOSITY_QUIET;
		} else if( match( val, "verbose" ) ) {
			gstate->verbosity = VERBOSITY_VERBOSE;
		} else if( match( val, "debug" ) ) {
			gstate->verbosity = VERBOSITY_DEBUG;
		} else {
			log_err( "CFG: Invalid verbosity argument." );
		}
#ifdef CMD
	} else if( match( var, "--cmd-port" ) ) {
		conf_str( var, &gstate->cmd_port, val );
#endif
#ifdef DNS
	} else if( match( var, "--dns-port" ) ) {
		conf_str( var, &gstate->dns_port, val );
#endif
#ifdef NSS
	} else if( match( var, "--nss-port" ) ) {
		conf_str( var, &gstate->nss_port, val );
#endif
#ifdef WEB
	} else if( match( var, "--web-port" ) ) {
		conf_str( var, &gstate->web_port, val );
#endif
	} else if( match( var, "--ipv4-only" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( var );
		} else {
			gstate->ipv4_only = 1;
		}
	} else if( match( var, "--ipv6-only" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( var );
		} else {
			gstate->ipv6_only = 1;
		}
	} else if( match( var, "--port" ) ) {
		conf_str( var, &gstate->dht_port, val );
	} else if( match( var, "--mcast-addr4" ) ) {
		conf_str( var, &gstate->mcast_addr4, val );
	} else if( match( var, "--mcast-addr6" ) ) {
		conf_str( var, &gstate->mcast_addr6, val );
	} else if( match( var, "--disable-multicast" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( var );
		} else {
			memset( &gstate->time_mcast4, 0xFF, sizeof(time_t) );
			memset( &gstate->time_mcast6, 0xFF, sizeof(time_t) );
		}
	} else if( match( var, "--ifce" ) ) {
		conf_str( var, &gstate->dht_ifce, val );
	} else if( match( var, "--user" ) ) {
		conf_str( var, &gstate->user, val );
	} else if( match( var, "--daemon" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( var );
		} else {
			gstate->is_daemon = 1;
		}
	} else if( match( var, "-h" ) || match( var, "--help" ) ) {
		printf( "%s", usage );
		exit( 0 );
	} else if( match( var, "-v" ) || match( var, "--version" ) ) {
		printf( "%s", version );
		exit( 0 );
	} else {
		log_err( "CFG: Unknown command line option '%s'", var );
	}
}

void conf_load( int argc, char **argv ) {
	unsigned int i;

	if( argv == NULL ) {
		return;
	}

	for( i = 1; i < argc; i++ ) {
		if( argv[i][0] == '-' ) {
			if( i+1 < argc && argv[i+1][0] != '-' ) {
				/* -x abc */
				conf_handle( argv[i], argv[i+1] );
				i++;
			} else {
				/* -x -y => -x */
				conf_handle( argv[i], NULL );
			}
		} else {
			/* x */
			conf_handle( argv[i], NULL );
		}
	}
}
