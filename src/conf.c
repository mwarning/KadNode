
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <errno.h>

#include "main.h"
#include "log.h"
#include "utils.h"
#include "conf.h"
#include "values.h"
#ifdef AUTH
#include "ext-auth.h"
#endif
#ifdef FWD
#include "forwardings.h"
#endif

/* Global object variables */
struct gconf_t *gconf = NULL;

const char *version = "KadNode v"MAIN_VERSION" ( "
"Features:"
#ifdef AUTH
" auth"
#endif
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
" --config <file>		Provide a configuration file with one command line\n"
"				option on each line. Comments start after '#'.\n\n"
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
#ifdef AUTH
" --auth-gen-keys		Generate a new public/secret key pair and exit.\n\n"
" --public-key [<pat>:]<pkey>	Assign a public key to all values that match the pattern.\n"
"				It is used to verifiy that the other side has the secret\n"
"				key when queries of the given pattern are requested.\n\n"
" --secret-key [<pat>:]<skey>	Assign a secret key to all values that match the pattern.\n"
"				It is used to prove that you own the domain provided\n"
"				the other side knows the public key.\n\n"
#endif
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
	gconf = (struct gconf_t *) malloc( sizeof(struct gconf_t) );

	memset( gconf, '\0', sizeof(struct gconf_t) );

	bytes_random( gconf->node_id, SHA1_BIN_LENGTH );

	gconf->mcast_addr = NULL;
	gconf->is_running = 1;

#ifdef DEBUG
	gconf->verbosity = VERBOSITY_DEBUG;
#else
	gconf->verbosity = VERBOSITY_VERBOSE;
#endif

	gconf->af = AF_INET;
	gconf->dht_port = strdup( DHT_PORT );

#ifdef CMD
	gconf->cmd_port = strdup( CMD_PORT );
#endif

#ifdef DNS
	gconf->dns_port = strdup( DNS_PORT );
#endif

#ifdef NSS
	gconf->nss_port = strdup( NSS_PORT );
#endif

#ifdef WEB
	gconf->web_port = strdup( WEB_PORT );
#endif
}

void conf_check() {
	char hexbuf[SHA1_HEX_LENGTH+1];
	char addrbuf[FULL_ADDSTRLEN+1];
	IP mcast_addr;
	UCHAR octet;

	log_info( "Starting KadNode v"MAIN_VERSION );
	log_info( "Own ID: %s", str_id( gconf->node_id, hexbuf ) );
	log_info( "Kademlia mode: %s", (gconf->af == AF_INET) ? "IPv4" : "IPv6");

	if( gconf->is_daemon ) {
		log_info( "Mode: Daemon" );
	} else {
		log_info( "Mode: Foreground" );
	}

	switch( gconf->verbosity ) {
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

	log_info( "Peerfile: %s", gconf->peerfile ? gconf->peerfile : "None" );

	if( gconf->mcast_addr == NULL ) {
		/* Set default multicast address string */
		if( gconf->af == AF_INET ) {
			gconf->mcast_addr = strdup( DHT_ADDR4_MCAST );
		} else {
			gconf->mcast_addr = strdup( DHT_ADDR6_MCAST );
		}
	}

	if( port_parse( gconf->dht_port, -1 ) < 1 ) {
		log_err( "CFG: Invalid DHT port '%s'.", gconf->dht_port );
	}

#ifdef CMD
	if( port_parse( gconf->cmd_port, -1 ) < 0 ) {
		log_err( "CFG: Invalid CMD port '%s'.", gconf->cmd_port );
	}
#endif

#ifdef DNS
	if( port_parse( gconf->dns_port, -1 ) < 0 ) {
		log_err( "CFG: Invalid DNS port '%s'.", gconf->dns_port );
	}
#endif

#ifdef NSS
	if( port_parse( gconf->nss_port, -1 ) < 0 ) {
		log_err( "CFG: Invalid NSS port '%s'.", gconf->nss_port );
	}
#endif

#ifdef WEB
	if( port_parse( gconf->web_port, -1 ) < 0 ) {
		log_err( "CFG: Invalid WEB port '%s'.", gconf->web_port );
	}
#endif

	/* Parse multicast address string */
	if( addr_parse( &mcast_addr, gconf->mcast_addr, DHT_PORT_MCAST, gconf->af ) != 0 ) {
		log_err( "CFG: Failed to parse IP address for '%s'.", gconf->mcast_addr );
	}

	/* Verifiy multicast address */
	if( gconf->af == AF_INET ) {
		octet = ((UCHAR *) &((IP4 *)&mcast_addr)->sin_addr)[0];
		if( octet != 224 && octet != 239 ) {
			log_err( "CFG: Multicast address expected: %s", str_addr( &mcast_addr, addrbuf ) );
		}
	} else {
		octet = ((UCHAR *) &((IP6 *)&mcast_addr)->sin6_addr)[0];
		if( octet != 0xFF ) {
			log_err( "CFG: Multicast address expected: %s", str_addr( &mcast_addr, addrbuf ) );
		}
	}

	log_info("Multicast: %s", (gconf->disable_multicast == 0) ? str_addr( &mcast_addr, addrbuf ) : "Disabled" );

	/* Store startup time */
	gettimeofday( &gconf->time_now, NULL );
	gconf->startup_time = time_now_sec();
}

void conf_free() {

	free( gconf->user );
	free( gconf->pidfile );
	free( gconf->peerfile );
	free( gconf->dht_port );
	free( gconf->dht_ifce );
	free( gconf->mcast_addr );

#ifdef CMD
	free( gconf->cmd_port );
#endif
#ifdef DNS
	free( gconf->dns_port );
#endif
#ifdef NSS
	free( gconf->nss_port );
#endif
#ifdef WEB
	free( gconf->web_port );
#endif

	free( gconf );
}

void conf_arg_expected( const char *var ) {
	log_err( "CFG: Argument expected for option %s.", var );
}

void conf_no_arg_expected( const char *var ) {
	log_err( "CFG: No argument expected for option %s.", var );
}

/* Free the old string and set the new */
void conf_str( const char *var, char **dst, const char *src ) {
	if( src == NULL ) {
		conf_arg_expected( var );
	}

	free( *dst );
	*dst = strdup( src );
}

void conf_add_value( char *var, char *val ) {
	struct value_t *value;
	int is_random_port;
	int port;
	char *p;

	if( val == NULL ) {
		conf_arg_expected( var );
	}

	is_random_port = 0;

	/* Find <id>:<port> delimiter */
	p = strchr( val, ':' );
	if( p ) {
		*p = '\0';
	}

#ifdef AUTH
	if( auth_is_skey( val ) ) {
		if( p ) {
			log_err( "No port expected. Auth requests will be expected on the DHT port." );
			exit( 1 );
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
			is_random_port = 1;
		}
#ifdef AUTH
	}
#endif

	value = values_add( val, port, LONG_MAX );
	if( value == NULL ) {
		log_err( "CFG: Invalid port for value annoucement: %d", port );
		exit( 1 );
	} else {
#ifdef FWD
		if( !is_random_port ) {
			forwardings_add( port, LONG_MAX );
		}
#endif
	}
}

void read_conf_file( const char *filename ) {
	char line[1000];
	size_t n;
	FILE *file;
	char *var;
	char *val;
	char *p;

	n = 0;
	file = fopen( filename, "rt" );
	if( file == NULL ) {
		log_err( "CFG: Cannot open file '%s': %s\n", filename, strerror( errno ) );
		exit( 1 );
	}

	while( fgets( line, sizeof(line), file ) != NULL ) {
		n++;
		var = NULL;
		val = NULL;

		/* End line early at '#' */
		if( (p = strchr( line, '#' )) != NULL ) {
			*p =  '\0';
		}

		char *pch = strtok( line," \t\n" );
		while( pch != NULL ) {
			if( var == NULL ) {
				var = pch;
			} else if( val == NULL ) {
				val = pch;
			} else {
				fclose( file );
				log_err( "CFG: Too many arguments in line %ld.", n );
				exit( 1 );
			}
			pch = strtok( NULL, " \t\n" );
		}

		if( var == NULL  ) {
			continue;
		}

		if( strcmp( var, "--config" ) == 0 ) {
			log_err( "CFG: Recursive configuration in line %ld.", n );
			exit( 1 );
		}
		conf_handle( var, val );
	}

	fclose( file );
}

void conf_handle( char *var, char *val ) {

	if( match( var, "--node-id" ) ) {
		if( val == NULL ) {
			conf_arg_expected( var );
		}
		if( strlen( val ) != SHA1_HEX_LENGTH || !str_isHex( val, SHA1_HEX_LENGTH ) ) {
			log_err( "CFG: Invalid hex string for --node-id." );
		}
		bytes_from_hex( gconf->node_id, val, SHA1_HEX_LENGTH );
	} else if( match( var, "--value-id" ) ) {
		conf_add_value( var, val );
	} else if( match( var, "--pidfile" ) ) {
		conf_str( var, &gconf->pidfile, val );
	} else if( match( var, "--peerfile" ) ) {
		conf_str( var, &gconf->peerfile, val );
	} else if( match( var, "--verbosity" ) ) {
		if( match( val, "quiet" ) ) {
			gconf->verbosity = VERBOSITY_QUIET;
		} else if( match( val, "verbose" ) ) {
			gconf->verbosity = VERBOSITY_VERBOSE;
		} else if( match( val, "debug" ) ) {
			gconf->verbosity = VERBOSITY_DEBUG;
		} else {
			log_err( "CFG: Invalid argument for %s.", var );
		}
#ifdef CMD
	} else if( match( var, "--cmd-port" ) ) {
		conf_str( var, &gconf->cmd_port, val );
#endif
#ifdef DNS
	} else if( match( var, "--dns-port" ) ) {
		conf_str( var, &gconf->dns_port, val );
#endif
#ifdef NSS
	} else if( match( var, "--nss-port" ) ) {
		conf_str( var, &gconf->nss_port, val );
#endif
#ifdef WEB
	} else if( match( var, "--web-port" ) ) {
		conf_str( var, &gconf->web_port, val );
#endif
#ifdef AUTH
	} else if( match( var, "--auth-gen-keys" ) ) {
		exit( auth_generate_key_pair() );
	} else if( match( var, "--secret-key" ) ) {
		if( val == NULL ) {
			conf_arg_expected( var );
		}
		if( values_get() ) {
			log_err( "CFG: --secret-key options need to be specifed before any --value-id option." );
		}
		auth_add_skey( val );
	} else if( match( var, "--public-key" ) ) {
		if( val == NULL ) {
			conf_arg_expected( var );
		}
		if( values_get() ) {
			log_err( "CFG: --public-key options need to be specifed before any --value-id option." );
		}
		auth_add_pkey( val );
#endif
	} else if( match( var, "--config" ) ) {
		if( val == NULL ) {
			conf_arg_expected( var );
		}
		read_conf_file( val );
	} else if( match( var, "--mode" ) ) {
		if( val && match( val, "ipv4" ) ) {
			gconf->af = AF_INET;
		} else if( val && match( val, "ipv6" ) ) {
			gconf->af = AF_INET6;
		} else {
			log_err("CFG: Invalid argument for %s. Use 'ipv4' or 'ipv6'.", var );
		}
	} else if( match( var, "--port" ) ) {
		conf_str( var, &gconf->dht_port, val );
	} else if( match( var, "--mcast-addr" ) ) {
		conf_str( var, &gconf->mcast_addr, val );
	} else if( match( var, "--disable-multicast" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( var );
		} else {
			gconf->disable_multicast = 1;
		}
	} else if( match( var, "--disable-forwarding" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( var );
		} else {
			gconf->disable_forwarding = 1;
		}
	} else if( match( var, "--ifce" ) ) {
		conf_str( var, &gconf->dht_ifce, val );
	} else if( match( var, "--user" ) ) {
		conf_str( var, &gconf->user, val );
	} else if( match( var, "--daemon" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( var );
		} else {
			gconf->is_daemon = 1;
		}
	} else if( match( var, "-h" ) || match( var, "--help" ) ) {
		printf( "%s", usage );
		exit( 0 );
	} else if( match( var, "-v" ) || match( var, "--version" ) ) {
		printf( "%s", version );
		exit( 0 );
	} else {
		log_err( "CFG: Unknown command line option '%s'", var ? var : val );
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
			conf_handle( NULL, argv[i] );
		}
	}
}
