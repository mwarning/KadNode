
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
#include "kad.h"
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
" --auth-add-pkey [<pat>:]<pkey>	Assign a public key to all values that match the pattern.\n"
"				It is used to verifiy that the other side has the secret\n"
"				key when queries of the given pattern are requested.\n\n"
" --auth-add-skey [<pat>:]<skey>	Assign a secret key to all values that match the pattern.\n"
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

void conf_arg_expected( const char *opt ) {
	log_err( "CFG: Argument expected for option %s.", opt );
}

void conf_no_arg_expected( const char *opt ) {
	log_err( "CFG: No argument expected for option %s.", opt );
}

/* Free the old string and set the new */
void conf_str( const char *opt, char **dst, const char *src ) {
	if( src == NULL ) {
		conf_arg_expected( opt );
	}

	free( *dst );
	*dst = strdup( src );
}

void conf_add_value( char *opt, char *val ) {
	int port;
	int rc;
	char *p;

	if( val == NULL ) {
		conf_arg_expected( opt );
	}

#ifdef FWD
	int is_random_port = 0;
#endif

	/* Find <id>:<port> delimiter */
	p = strchr( val, ':' );

	if( p ) {
		*p = '\0';
		port = port_parse( p + 1, -1 );
	} else {
		/* Preselect a random port */
		port = port_random();
#ifdef FWD
		is_random_port = 1;
#endif
	}

	rc = kad_announce( val, port, LONG_MAX );
	if( rc < 0 ) {
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
	char *option;
	char *value;
	char *p;

	n = 0;
	file = fopen( filename, "rt" );
	if( file == NULL ) {
		log_err( "CFG: Cannot open file '%s': %s\n", filename, strerror( errno ) );
		exit( 1 );
	}

	while( fgets( line, sizeof(line), file ) != NULL ) {
		n++;
		option = NULL;
		value = NULL;

		/* End line early at '#' */
		if( (p = strchr( line, '#' )) != NULL ) {
			*p =  '\0';
		}

		if( strchr( line, '\"' ) || strchr( line, '\"' ) ) {
			log_err( "CFG: Quotation marks cannot be used in configuration file, line %ld.", n );
		}

		/* Parse "--option [<value>]" */
		char *pch = strtok( line," \t\n" );
		while( pch != NULL ) {
			if( option == NULL ) {
				option = pch;
			} else if( value == NULL ) {
				value = pch;
			} else {
				fclose( file );
				log_err( "CFG: Too many arguments in line %ld.", n );
			}
			pch = strtok( NULL, " \t\n" );
		}

		if( option == NULL  ) {
			continue;
		}

		if( strcmp( option, "--config" ) == 0 ) {
			log_err( "CFG: Recursive configuration in line %ld.", n );
			exit( 1 );
		}
		conf_handle( option, value );
	}

	fclose( file );
}

void conf_handle( char *opt, char *val ) {

	if( match( opt, "--node-id" ) ) {
		if( val == NULL ) {
			conf_arg_expected( opt );
		}
		if( strlen( val ) != SHA1_HEX_LENGTH || !str_isHex( val, SHA1_HEX_LENGTH ) ) {
			log_err( "CFG: Invalid hex string for --node-id." );
		}
		bytes_from_hex( gconf->node_id, val, SHA1_HEX_LENGTH );
	} else if( match( opt, "--value-id" ) ) {
		conf_add_value( opt, val );
	} else if( match( opt, "--pidfile" ) ) {
		conf_str( opt, &gconf->pidfile, val );
	} else if( match( opt, "--peerfile" ) ) {
		conf_str( opt, &gconf->peerfile, val );
	} else if( match( opt, "--verbosity" ) ) {
		if( match( val, "quiet" ) ) {
			gconf->verbosity = VERBOSITY_QUIET;
		} else if( match( val, "verbose" ) ) {
			gconf->verbosity = VERBOSITY_VERBOSE;
		} else if( match( val, "debug" ) ) {
			gconf->verbosity = VERBOSITY_DEBUG;
		} else {
			log_err( "CFG: Invalid argument for %s.", opt );
		}
#ifdef CMD
	} else if( match( opt, "--cmd-port" ) ) {
		conf_str( opt, &gconf->cmd_port, val );
#endif
#ifdef DNS
	} else if( match( opt, "--dns-port" ) ) {
		conf_str( opt, &gconf->dns_port, val );
#endif
#ifdef NSS
	} else if( match( opt, "--nss-port" ) ) {
		conf_str( opt, &gconf->nss_port, val );
#endif
#ifdef WEB
	} else if( match( opt, "--web-port" ) ) {
		conf_str( opt, &gconf->web_port, val );
#endif
#ifdef AUTH
	} else if( match( opt, "--auth-gen-keys" ) ) {
		exit( auth_generate_key_pair() );
	} else if( match( opt, "--auth-add-skey" ) ) {
		if( val == NULL ) {
			conf_arg_expected( opt );
		}
		if( values_get() ) {
			log_err( "CFG: --auth-add-skey options need to be specifed before any --value-id option." );
		}
		auth_add_skey( val );
	} else if( match( opt, "--auth-add-pkey" ) ) {
		if( val == NULL ) {
			conf_arg_expected( opt );
		}
		if( values_get() ) {
			log_err( "CFG: --auth-add-pkey options need to be specifed before any --value-id option." );
		}
		auth_add_pkey( val );
#endif
	} else if( match( opt, "--config" ) ) {
		if( val == NULL ) {
			conf_arg_expected( opt );
		}
		read_conf_file( val );
	} else if( match( opt, "--mode" ) ) {
		if( val && match( val, "ipv4" ) ) {
			gconf->af = AF_INET;
		} else if( val && match( val, "ipv6" ) ) {
			gconf->af = AF_INET6;
		} else {
			log_err("CFG: Invalid argument for %s. Use 'ipv4' or 'ipv6'.", opt );
		}
	} else if( match( opt, "--port" ) ) {
		conf_str( opt, &gconf->dht_port, val );
	} else if( match( opt, "--mcast-addr" ) ) {
		conf_str( opt, &gconf->mcast_addr, val );
	} else if( match( opt, "--disable-multicast" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( opt );
		} else {
			gconf->disable_multicast = 1;
		}
	} else if( match( opt, "--disable-forwarding" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( opt );
		} else {
			gconf->disable_forwarding = 1;
		}
	} else if( match( opt, "--ifce" ) ) {
		conf_str( opt, &gconf->dht_ifce, val );
	} else if( match( opt, "--user" ) ) {
		conf_str( opt, &gconf->user, val );
	} else if( match( opt, "--daemon" ) ) {
		if( val != NULL ) {
			conf_no_arg_expected( opt );
		} else {
			gconf->is_daemon = 1;
		}
	} else if( match( opt, "-h" ) || match( opt, "--help" ) ) {
		printf( "%s", usage );
		exit( 0 );
	} else if( match( opt, "-v" ) || match( opt, "--version" ) ) {
		printf( "%s", version );
		exit( 0 );
	} else {
		log_err( "CFG: Unknown command line option '%s'", opt ? opt : val );
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
