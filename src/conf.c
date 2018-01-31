
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>

#include "main.h"
#include "log.h"
#include "utils.h"
#include "conf.h"
#include "peerfile.h"
#include "kad.h"
#ifdef TLS
#include "ext-tls-client.h"
#include "ext-tls-server.h"
#endif
#ifdef BOB
#include "ext-bob.h"
#endif
#ifdef FWD
#include "ext-fwd.h"
#endif
#ifdef __CYGWIN__
#include "windows.h"
#endif

// Global object variables
struct gconf_t *gconf = NULL;

static const char *g_announce_args[64] = { 0 };
#ifdef TLS
static const char *g_tls_client_args[16] = { 0 };
static const char *g_tls_server_args[16] = { 0 };
#endif

const char *kadnode_version_str = "KadNode v"MAIN_VERSION" ("
#ifdef BOB
" bob"
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
#ifdef LPD
" lpd"
#endif
#ifdef FWD_NATPMP
" natpmp"
#endif
#ifdef NSS
" nss"
#endif
#ifdef TLS
" tls"
#endif
#ifdef FWD_UPNP
" upnp"
#endif
" )";

static const char *kadnode_usage_str =
"KadNode is a small decentralized DNS resolver.\n"
"\n"
"Usage: kadnode [OPTIONS]*\n"
"\n"
" --announce <name>:<port>		Announce a name and port.\n\n"
" --peerfile <file>			Import/Export peers from and to a file.\n\n"
" --peer <addr>				Add a static peer address.\n"
"					This option may occur multiple times.\n\n"
" --user <user>				Change the UUID after start.\n\n"
" --port	<port>				Bind DHT to this port.\n"
"					Default: "STR(DHT_PORT)"\n\n"
" --config <file>			Provide a configuration file with one command line\n"
"					option on each line. Comments start after '#'.\n\n"
" --ifname <interface>			Bind to this interface.\n"
"					Default: <any>\n\n"
" --daemon				Run the node in background.\n\n"
" --verbosity <level>			Verbosity level: quiet, verbose or debug.\n"
"					Default: verbose\n\n"
" --pidfile <file>			Write process pid to a file.\n\n"
" --ipv4, -4, --ipv6, -6			Enable IPv4 or IPv6 only mode.\n"
"					Default: IPv4+IPv6\n\n"
" --query-tld <domain>			Top level domain to be handled by KadNode.\n"
"					Default: "QUERY_TLD_DEFAULT"\n\n"
#ifdef LPD
" --lpd-disable				Disable multicast to discover local peers.\n\n"
#endif
#ifdef BOB
" --bob-create-key <file>		Write a new secp256r1 secret key in PEM format to the file.\n"
"					The public key will be printed to the terminal before exit.\n\n"
" --bob-load-key <file>			Read a secret key in PEM format and announce the public key.\n"
"					This option may occur multiple times.\n\n"
#endif
#ifdef CMD
" --cmd-disable-stdin			Disable the local control interface.\n\n"
" --cmd-port <port>			Bind the remote control interface to this local port.\n"
"					Default: "STR(CMD_PORT)"\n\n"
#endif
#ifdef DNS
" --dns-port <port>			Bind the DNS server interface to this local port.\n"
"					Default: "STR(DNS_PORT)"\n\n"
" --dns-proxy-enable			Enable DNS proxy mode. The proxy reads /etc/resolv.conf by default.\n\n"
" --dns-proxy-server <ip-addr>		Use IP address of an external DNS server instead of resolv.conf.\n\n"
#endif
#ifdef NSS
" --nss-port <port>			Bind the Network Service Switch to this local port.\n"
"					Default: "STR(NSS_PORT)"\n\n"
#endif
#ifdef FWD
" --fwd-disable				Disable UPnP/NAT-PMP to forward router ports.\n\n"
#endif
#ifdef TLS
" --tls-client-cert <path>		Path to file or folder of CA root certificates.\n"
"					This option may occur multiple times.\n\n"
" --tls-server-cert <path>,<path>	Add a comma separated tuple of server certificate file and key.\n"
"					This option may occur multiple times.\n"
"					Example: kadnode.crt,kadnode.key\n\n"
#endif
#ifdef __CYGWIN__
" --service-start			Start, install and remove KadNode as Windows service.\n"
" --service-install			KadNode will be started/shut down along with Windows\n"
" --service-remove			or on request by using the Service Control Manager.\n\n"
#endif
" -h, --help				Print this help.\n\n"
" -v, --version				Print program version.\n";


void conf_init( void ) {
	gconf = (struct gconf_t*) calloc( 1, sizeof(struct gconf_t) );
	*gconf = ((struct gconf_t) {
		.dht_port = -1,
		.af = AF_UNSPEC,
#ifdef CMD
		.cmd_port = -1,
#endif
#ifdef DNS
		.dns_port = -1,
#endif
#ifdef NSS
		.nss_port = -1,
#endif
#ifdef DEBUG
		.verbosity = VERBOSITY_DEBUG
#else
		.verbosity = VERBOSITY_VERBOSE
#endif
	});
}

// Set default if setting was not set and validate settings
void conf_defaults( void ) {

	if( gconf->af == 0 ) {
		gconf->af = AF_UNSPEC;
	}

	if( gconf->query_tld == NULL ) {
		gconf->query_tld = strdup( QUERY_TLD_DEFAULT );
	}

	if( gconf->dht_port < 0 ) {
		gconf->dht_port = DHT_PORT;
	}

#ifdef CMD
	if( gconf->cmd_port < 0 ) {
		gconf->cmd_port = CMD_PORT;
	}
#endif

#ifdef DNS
	if( gconf->dns_port < 0 ) {
		gconf->dns_port = DNS_PORT;
	}
#endif

#ifdef NSS
	if( gconf->nss_port < 0 ) {
		gconf->nss_port = NSS_PORT;
	}
#endif

	time_t now = time( NULL );
	gconf->time_now = now;
	gconf->startup_time = now;
	gconf->is_running = 1;
}

const char *verbosity_str( int verbosity ) {
	switch( verbosity ) {
		case VERBOSITY_QUIET: return "quiet";
		case VERBOSITY_VERBOSE: return "verbose";
		case VERBOSITY_DEBUG: return "debug";
		default:
			log_err( "Invalid verbosity: %d", verbosity );
			exit( 1 );
	}
}

void conf_info( void ) {
	log_info( "Starting %s", kadnode_version_str );
	log_info( "Net Mode: %s", str_af( gconf->af ) );
	log_info( "Run Mode: %s", gconf->is_daemon ? "daemon" : "foreground" );

	if( gconf->configfile ) {
		log_info( "Configuration File: %s", gconf->configfile );
	}

	log_info( "Verbosity: %s", verbosity_str( gconf->verbosity ) );
	log_info( "Query TLD: %s", gconf->query_tld );
	log_info( "Peer File: %s", gconf->peerfile ? gconf->peerfile : "none" );
#ifdef LPD
	log_info( "Local Peer Discovery: %s", gconf->lpd_disable ? "disabled" : "enabled" );
#endif
#ifdef DNS
	if( gconf->dns_proxy_enable ) {
		if( gconf->dns_proxy_server ) {
			log_info( "DNS proxy enabled: %s", gconf->dns_proxy_server );
		} else {
			log_info( "DNS proxy enabled: /etc/resolv.conf" );
		}
	}
#endif
}

void conf_free( void ) {
	free( gconf->query_tld );
	free( gconf->user );
	free( gconf->pidfile );
	free( gconf->peerfile );
	free( gconf->dht_ifname );
	free( gconf->configfile );

#ifdef DNS
	free( gconf->dns_proxy_server );
#endif

	free( gconf );
}

// Enumerate all options to keep binary size smaller
enum OPCODE {
	oAnnounce,
	oQueryTld,
	oPidFile,
	oPeerFile,
	oPeer,
	oVerbosity,
	oCmdDisableStdin,
	oCmdPort,
	oDnsPort,
	oDnsProxyEnable,
	oDnsProxyServer,
	oNssPort,
	oTlsClientCert,
	oTlsServerCert,
	oConfig,
	oIpv4,
	oIpv6,
	oPort,
	oLpdAddr,
	oLpdDisable,
	oFwdDisable,
	oServiceInstall,
	oServiceRemove,
	oServiceStart,
	oBobCreateKey,
	oBobLoadKey,
	oIfname,
	oUser,
	oDaemon,
	oHelp,
	oVersion
};

struct option_t {
	const char *name;
	uint16_t num_args;
	uint16_t code;
};

static struct option_t options[] = {
	{"--announce", 1, oAnnounce},
	{"--query-tld", 1, oQueryTld},
	{"--pidfile", 1, oPidFile},
	{"--peerfile", 1, oPeerFile},
	{"--peer", 1, oPeer},
	{"--verbosity", 1, oVerbosity},
#ifdef CMD
	{"--cmd-disable-stdin", 0, oCmdDisableStdin},
	{"--cmd-port", 1, oCmdPort},
#endif
#ifdef DNS
	{"--dns-port", 1, oDnsPort},
	{"--dns-proxy-enable", 0, oDnsProxyEnable},
	{"--dns-proxy-server", 1, oDnsProxyServer},
#endif
#ifdef NSS
	{"--nss-port", 1, oNssPort},
#endif
#ifdef TLS
	{"--tls-client-cert", 1, oTlsClientCert},
	{"--tls-server-cert", 1, oTlsServerCert},
#endif
	{"--config", 1, oConfig},
	{"--port", 1, oPort},
	{"--ipv4", 0, oIpv4},
	{"-4", 0, oIpv4},
	{"--ipv6", 0, oIpv6},
	{"-6", 0, oIpv6},
#ifdef LPD
	{"--lpd-addr", 1, oLpdAddr},
	{"--lpd-disable", 0, oLpdDisable},
#endif
#ifdef FWD
	{"--fwd-disable", 0, oFwdDisable},
#endif
#ifdef __CYGWIN__
	{"--service-install", 0, oServiceInstall},
	{"--service-remove", 0, oServiceRemove},
	{"--service-start", 0, oServiceStart},
#endif
#ifdef BOB
	{"--bob-create-key", 1, oBobCreateKey},
	{"--bob-load-key", 1, oBobLoadKey},
#endif
	{"--ifname", 1, oIfname},
	{"--user", 1, oUser},
	{"--daemon", 0, oDaemon},
	{"-h", 0, oHelp},
	{"--help", 0, oHelp},
	{"-v", 0, oVersion},
	{"--version", 0, oVersion},
};

static const struct option_t *find_option( const char name[] ) {
	int i;

	for( i = 0; i < ARRAY_SIZE(options); i++) {
		if( strcmp( name, options[i].name ) == 0 ) {
			return &options[i];
		}
	}

	return NULL;
}

// Set a string once - error when already set
static int conf_str( const char opt[], char *dst[], const char src[] ) {
	if( *dst != NULL ) {
		log_err( "Value was already set for %s: %s", opt, src );
		return 1;
	}

	*dst = strdup( src );
	return 0;
}

static int conf_port( const char opt[], int *dst, const char src[] ) {
	int n = port_parse( src, -1 );

	if( n < 0 ) {
		log_err( "Invalid port for %s: %s", opt, src );
		return 1;
	}

	if( *dst >= 0 ) {
		log_err( "Value was already set for %s: %s", opt, src );
		return 1;
	}

	*dst = n;
	return 0;
}

static int conf_load_file( const char path[] ) {
	char line[256];
	char option[32];
	char value[128];
	char dummy[4];
	char *last;
	struct stat s;
	int ret;
	FILE *file;
	size_t nline;

	if( stat( path, &s ) == 0 && !(s.st_mode & S_IFREG) ) {
		log_err( "File expected: %s", path );
		return 1;
	}

	nline = 0;
	file = fopen( path, "r" );
	if( file == NULL ) {
		log_err( "Cannot open file: %s (%s)", path, strerror( errno ) );
		return 1;
	}

	while( fgets( line, sizeof(line), file ) != NULL ) {
		nline += 1;

		// Cut off comments
		last = strchr( line, '#' );
		if( last ) {
			*last = '\0';
		}

		if( line[0] == '\n' || line[0] == '\0' ) {
			continue;
		}

		ret = sscanf( line, " %31s %127s %3s", option, value, dummy );

		if( ret == 1 || ret == 2 ) {
			// Prevent recursive inclusion
			if( strcmp( option, "--config " ) == 0 ) {
				fclose( file );
				log_err( "Option '--config' not allowed inside a configuration file, line %ld.", nline );
				return 1;
			}

			// --option value / --option
			ret = conf_set( option, (ret == 2) ? value : NULL );
			if( ret != 0 ) {
				fclose( file );
				return 1;
			}
		} else {
			fclose( file );
			log_err( "Invalid line in config file: %s (%d)", path, nline );
			return 1;
		}
	}

	fclose( file );
	return 0;
}

// Append to an array (assumes there is alway enough space ...)
void array_append( const char **array, const char *element ) {
	while( *array ) {
		array += 1;
	}

	*array = strdup( element );
}

// Free array elements
void array_free( const char **array ) {
	while( *array ) {
		free( (void*) *array );
		array += 1;
	}
}

int conf_set( const char opt[], const char val[] ) {
	const struct option_t *option;

	option = find_option( opt );

	if( option == NULL ) {
		log_err( "Unknown parameter: %s", opt );
		return 1;
	}

	if( option->num_args == 1 && val == NULL ) {
		log_err( "Argument expected for option: %s", opt );
		return 1;
	}

	if( option->num_args == 0 && val != NULL ) {
		log_err( "No argument expected for option: %s", opt );
		return 1;
	}

	switch( option->code ) {
		case oAnnounce:
			array_append( &g_announce_args[0], val );
			return 0;
		case oQueryTld:
			return conf_str( opt, &gconf->query_tld, val );
		case oPidFile:
			return conf_str( opt, &gconf->pidfile, val );
		case oPeerFile:
			return conf_str( opt, &gconf->peerfile, val );
		case oPeer:
			return peerfile_add_peer( val );
		case oVerbosity:
			if( strcmp( val, "quiet" ) == 0 ) {
				gconf->verbosity = VERBOSITY_QUIET;
			} else if( strcmp( val, "verbose" ) == 0 ) {
				gconf->verbosity = VERBOSITY_VERBOSE;
			} else if( strcmp( val, "debug" ) == 0 ) {
				gconf->verbosity = VERBOSITY_DEBUG;
			} else {
				log_err( "Invalid argument for %s", opt );
				return 1;
			}
			return 0;
#ifdef CMD
		case oCmdDisableStdin:
			gconf->cmd_disable_stdin = 1;
			return 0;
		case oCmdPort:
			return conf_port( opt, &gconf->cmd_port, val );
#endif
#ifdef DNS
		case oDnsPort:
			return conf_port( opt, &gconf->dns_port, val );
		case oDnsProxyEnable:
			gconf->dns_proxy_enable = 1;
			return 0;
		case oDnsProxyServer:
			return conf_str( opt, &gconf->dns_proxy_server, val );
#endif
#ifdef NSS
		case oNssPort:
			return conf_port( opt, &gconf->nss_port, val );
#endif
#ifdef TLS
		case oTlsClientCert:
			array_append( &g_tls_client_args[0], val );
			return 0;
		case oTlsServerCert:
			array_append( &g_tls_server_args[0], val );
			return 0;
#endif
		case oConfig:
		{
			int rc = conf_str( opt, &gconf->configfile, val );
			if( rc != 0 ) {
				return 0;
			}
			return conf_load_file( gconf->configfile );
		}
		case oIpv4:
		case oIpv6:
			if( gconf->af != AF_UNSPEC ) {
				log_err( "IPv4 or IPv6 mode already set: %s", opt );
				return 1;
			}

			gconf->af = (option->code == oIpv6) ? AF_INET6 : AF_INET;
			return 0;
		case oPort:
			return conf_port( opt, &gconf->dht_port, val );
#ifdef LPD
		case oLpdDisable:
			gconf->lpd_disable = 1;
			return 0;
#endif
#ifdef FWD
		case oFwdDisable:
			gconf->fwd_disable = 1;
			return 0;
#endif
#ifdef __CYGWIN__
		case oServiceInstall:
			windows_service_install();
			exit( 0 );
		case oServiceRemove:
			windows_service_remove();
			exit( 0 );
		case oServiceStart:
			gconf->service_start = 1;
			return 0;
#endif
		case oIfname:
			return conf_str( opt, &gconf->dht_ifname, val );
		case oUser:
			return conf_str( opt, &gconf->user, val );
		case oDaemon:
			gconf->is_daemon = 1;
			return 0;
		case oHelp:
			printf( "%s\n", kadnode_usage_str );
			exit( 0 );
		case oVersion:
			printf( "%s\n", kadnode_version_str );
			exit( 0 );
#ifdef BOB
		case oBobCreateKey:
			exit( bob_create_key( val ) < 0 );
		case oBobLoadKey:
			return bob_load_key( val );
#endif
		default:
			log_err( "Unhandled parameter: %s", opt );
			return 1;
	}
}

// Load some values that depend on proper settings
void conf_load( void ) {
	const char **args;
	int rc = 0;

	args = g_announce_args;
	while( rc == 0 && *args ) {
		uint16_t port = gconf->dht_port;
		char name[QUERY_MAX_SIZE] = { 0 };

		int n = sscanf( *args, "%254[^:]:%hu", name, &port );
		if( n == 1 || n == 2 ) {
			rc = kad_announce( name, port, LONG_MAX );
		} else {
			log_err( "Invalid announcement: %s", *args );
			rc = 1;
		}
		args += 1;
	}

#ifdef TLS
	args = g_tls_client_args;
	while( rc == 0 && *args ) {
		// Add Certificate Authority (CA) entries for the TLS client
		rc = tls_client_add_ca( *args );
		args += 1;
	}

	args = g_tls_server_args;
	while( rc == 0 && *args ) {
		// Add SNI entries for the TLS server (e.g. my.cert,my.key)
		char crt_file[128];
		char key_file[128];

		if( sscanf( *args, "%127[^,],%127[^,]", crt_file, key_file ) == 2 ) {
			rc = tls_server_add_sni( crt_file, key_file );
		} else {
			log_err( "Invalid cert/key tuple: %s", *args );
			rc = 1;
		}
		args += 1;
	}
#endif

	array_free( &g_announce_args[0] );
#ifdef TLS
	array_free( &g_tls_client_args[0] );
	array_free( &g_tls_server_args[0] );
#endif

	if( rc != 0 ) {
		exit( 1 );
	}
}

void conf_setup( int argc, char **argv ) {
	int rc;
	int i;

	for( i = 1; i < argc; ++i ) {
		const char *opt = argv[i];
		const char *val = argv[i + 1];

		if( val && val[0] != '-' ) {
			// -x abc
			rc = conf_set( opt, val );
			i += 1;
		} else {
			// -x
			rc = conf_set( opt, NULL );
		}

		if( rc != 0 ) {
			exit( rc );
		}
	}

	// Set defaults for unset settings
	conf_defaults();
}
