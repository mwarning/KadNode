
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#include "main.h"
#include "log.h"
#include "utils.h"
#include "conf.h"
#include "values.h"
#ifdef FWD
#include "forwardings.h"
#endif


/* Global object variables */
struct obj_gstate *gstate = NULL;

const char *version = "KadNode v"MAIN_VERSION" ( "
"Features:"
#ifdef CMD
" cmd"
#endif
#ifdef DEBUG
" debug"
#endif
#ifdef DNS
" dns"
#endif
#ifdef FWD_NATPMP
" natpmp"
#endif
#ifdef NSS
" nss"
#endif
#ifdef FWD_UPNP
" upnp"
#endif
#ifdef WEB
" web"
#endif
" )\n";

const char *usage = "KadNode - A P2P name resolution daemon (IPv4/IPv6)\n"
"A Wrapper for the Kademlia implementation of a Distributed Hash Table (DHT)\n"
"with several optional interfaces (check -v).\n"
"\n"
"Usage: kadnode [OPTIONS]*\n"
"\n"
" --node-id <id>			Set the node id. Use --value-id to announce values.\n"
"				Default: <random>\n\n"
" --value-id <id>[:<port>]	Add a value to be announced every 30 minutes.\n"
"				This option can occur multiple times.\n\n"
" --peerfile <file>		Import/Export files from and to a file.\n\n"
" --user <user>			Change the UUID after start.\n\n"
" --port	<port>			Bind to this port.\n"
"				Default: "DHT_PORT"\n\n"
" --mcast-addr <addr>		Use multicast address for bootstrapping.\n"
"				Default: "DHT_ADDR4_MCAST" / "DHT_ADDR6_MCAST"\n\n"
" --ifce <interface>		Bind to this interface.\n"
"				Default: <any>\n\n"
" --daemon			Run the node in background.\n\n"
" --verbosity <level>		Verbosity level: quiet, verbose or debug.\n"
"				Default: verbose\n\n"
" --pidfile <file>		Write process pid to a file.\n\n"
" --mode <ipv4|ipv6>		Enable IPv4 or IPv6 mode for the DHT.\n"
"				Default: ipv4\n\n"
#ifdef CMD
" --cmd-port <port>		Bind the remote control interface to this local port.\n"
"				Default: "CMD_PORT"\n\n"
#endif
#ifdef DNS
" --dns-port <port>		Bind the DNS server to this local port.\n"
"				Default: "DNS_PORT"\n\n"
#endif
#ifdef NSS
" --nss-port <port>		Bind the Network Service Switch to this local port.\n"
"				Default: "NSS_PORT"\n\n"
#endif
#ifdef WEB
" --web-port <port>		Bind the web server to this local port.\n"
"				Default: "WEB_PORT"\n\n"
#endif
#ifdef FWD
" --disable-forwarding		Disable UPnP/NAT-PMP to forward router ports.\n\n"
#endif
" --disable-multicast		Disable multicast to discover local nodes.\n\n"
" -h, --help			Print this help.\n\n"
" -v, --version			Print program version.\n\n";

void conf_init() {
	gstate = (struct obj_gstate *) malloc( sizeof(struct obj_gstate) );

	memset( gstate, '\0', sizeof(struct obj_gstate) );

	id_random( gstate->node_id, SHA_DIGEST_LENGTH );

	gstate->mcast_addr = NULL;
	gstate->is_running = 1;

#ifdef DEBUG
	gstate->verbosity = VERBOSITY_DEBUG;
#else
	gstate->verbosity = VERBOSITY_VERBOSE;
#endif

	gstate->af = AF_INET;
	gstate->dht_port = strdup( DHT_PORT );

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
	char addrbuf[FULL_ADDSTRLEN+1];
	IP mcast_addr;
	UCHAR octet;

	log_info( "Starting KadNode v"MAIN_VERSION );
	log_info( "Own ID: %s", str_id( gstate->node_id, hexbuf ) );
	log_info( "Kademlia mode: %s", (gstate->af == AF_INET) ? "IPv4" : "IPv6");

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

	log_info( "Peerfile: %s", gstate->peerfile ? gstate->peerfile : "None" );

	if( gstate->mcast_addr == NULL ) {
		/* Set default multicast address string */
		if( gstate->af == AF_INET ) {
			gstate->mcast_addr = strdup( DHT_ADDR4_MCAST );
		} else {
			gstate->mcast_addr = strdup( DHT_ADDR6_MCAST );
		}
	}

	/* Parse multicast address string */
	if( addr_parse( &mcast_addr, gstate->mcast_addr, DHT_PORT_MCAST, gstate->af ) != 0 ) {
		log_err( "CFG: Failed to parse IP address for '%s'.", gstate->mcast_addr );
	}

	/* Verifiy multicast address */
	if( gstate->af == AF_INET ) {
		octet = ((UCHAR *) &((IP4 *)&mcast_addr)->sin_addr)[0];
		if( octet != 224 && octet != 239 ) {
			log_err( "CFG: Multicast address expected: %s", str_addr( &mcast_addr, addrbuf ) );
		}
	} else {
		octet = ((UCHAR *)&((IP6 *)&mcast_addr)->sin6_addr)[0];
		if( octet != 0xFF ) {
			log_err( "CFG: Multicast address expected: %s", str_addr( &mcast_addr, addrbuf ) );
		}
	}

	log_info("Multicast: %s", (gstate->disable_multicast == 0) ? str_addr( &mcast_addr, addrbuf ) : "Disabled" );

	/* Store startup time */
	gettimeofday( &gstate->time_now, NULL );
	gstate->startup_time = time_now_sec();
}

void conf_free() {

	free( gstate->user );
	free( gstate->pidfile );
	free( gstate->dht_port );
	free( gstate->dht_ifce );
	free( gstate->mcast_addr );

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
void conf_str( const char *var, char **dst, const char *src ) {
	if( src == NULL ) {
		conf_arg_expected( var );
	}

	free( *dst );
	*dst = strdup( src );
}

void conf_add_value( char *var, char *val ) {
	UCHAR value_id[SHA_DIGEST_LENGTH];
	char hexbuf[HEX_LEN+1];
	unsigned short port;
	char *delim;

	if( val == NULL ) {
		conf_arg_expected( var );
	}

	/* Split identifier and optional port */
	delim = strchr( val, ':' );
	if( delim ) {
		*delim = '\0';
		port = atoi( delim + 1 );
	} else {
		port = 1;
	}

	if( port < 1 || port > 65535 ) {
		log_err( "CFG: Invalid port used for value: %s", val );
	}

	/* Add new value */
	id_compute( value_id, val );

	values_add( value_id, port, LONG_MAX );
#ifdef FWD
	forwardings_add( port, LONG_MAX );
#endif
}

void conf_handle( char *var, char *val ) {

	if( match( var, "--node-id" ) ) {
		/* Compute node id */
		id_compute( gstate->node_id, val );
	} else if( match( var, "--value-id" ) ) {
		conf_add_value( var, val );
	} else if( match( var, "--pidfile" ) ) {
		conf_str( var, &gstate->pidfile, val );
	} else if( match( var, "--peerfile" ) ) {
		conf_str( var, &gstate->peerfile, val );
	} else if( match( var, "--verbosity" ) ) {
		if( match( val, "quiet" ) ) {
			gstate->verbosity = VERBOSITY_QUIET;
		} else if( match( val, "verbose" ) ) {
			gstate->verbosity = VERBOSITY_VERBOSE;
		} else if( match( val, "debug" ) ) {
			gstate->verbosity = VERBOSITY_DEBUG;
		} else {
			log_err( "CFG: Invalid argument for %s.", var );
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
	} else if( match( var, "--mode" ) ) {
		if( val && match( val, "ipv4" ) ) {
			gstate->af = AF_INET;
		} else if( val && match( val, "ipv6" ) ) {
			gstate->af = AF_INET6;
		} else {
			log_err("CFG: Invalid argument for %s. Use 'ipv4' or 'ipv6'.", var );
		}
	} else if( match( var, "--port" ) ) {
		conf_str( var, &gstate->dht_port, val );
	} else if( match( var, "--mcast-addr" ) ) {
		conf_str( var, &gstate->mcast_addr, val );
	} else if( match( var, "--disable-multicast" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( var );
		} else {
			gstate->disable_multicast = 1;
		}
	} else if( match( var, "--disable-forwarding" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( var );
		} else {
			gstate->disable_forwarding = 1;
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
