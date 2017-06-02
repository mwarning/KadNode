
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#ifdef __CYGWIN__
#include <windows.h>
#endif

#include "main.h"
#include "conf.h"
#include "log.h"
#include "kad.h"
#include "utils.h"
#include "unix.h"
#include "net.h"
#include "values.h"
#include "results.h"
#include "peerfile.h"
#ifdef __CYGWIN__
#include "windows.h"
#endif

#ifdef LPD
#include "ext-lpd.h"
#endif
#ifdef BOB
#include "ext-bob.h"
#endif
#ifdef DNS
#include "ext-dns.h"
#endif
#ifdef WEB
#include "ext-web.h"
#endif
#ifdef NSS
#include "ext-nss.h"
#endif
#ifdef CMD
#include "ext-cmd.h"
#endif
#ifdef FWD
#include "ext-fwd.h"
#endif
#ifdef TLS
#include "ext-tls.h"
#endif


// Cleanup resources on any non crash program exit
void main_cleanup( void ) {
	static volatile int clean_in_progress = 0;

	// Prevent recursive calls
	if( clean_in_progress ) {
		return;
	} else {
		clean_in_progress = 1;
	}

#ifdef CMD
	cmd_free();
#endif
#ifdef NSS
	nss_free();
#endif
#ifdef WEB
	web_free();
#endif
#ifdef DNS
	dns_free();
#endif
#ifdef BOB
	bob_free();
#endif
#ifdef LPD
	lpd_free();
#endif
#ifdef TLS
	tls_free();
#endif

	peerfile_free();

	results_free();

	values_free();

	kad_free();

#ifdef FWD
	fwd_free();
#endif

	conf_free();

	net_free();
}

int main_start( void ) {

	atexit( main_cleanup );

	// Setup port-forwarding
#ifdef FWD
	fwd_setup();
#endif

	// Setup the Kademlia DHT
	kad_setup();

	// Setup handler to announce values
	values_setup();

	// Setup handler to expire results
	results_setup();

	// Setup import of peerfile
	peerfile_setup();

	// Setup extensions
#ifdef LPD
	lpd_setup();
#endif
#ifdef BOB
	bob_setup();
#endif
#ifdef DNS
	dns_setup();
#endif
#ifdef WEB
	web_setup();
#endif
#ifdef NSS
	nss_setup();
#endif
#ifdef TLS
	tls_setup();
#endif
#ifdef CMD
	cmd_setup();
#endif

//for testing
if(strcmp(gconf->dht_addr, "127.0.0.1") == 0)
{
	printf("start search");
	IP addr_array[3];
	size_t addr_num = 3;

//public key: 53e2e30f2c01cfd823b30a07d5ad0b9072e2b3db2e28ebffc70b16694cc637f0
//secret key: 6392c538eac4dd6e5eec23ecde855160334135df93e47cc56b68b41cf3215dde53e2e30f2c01cfd823b30a07d5ad0b9072e2b3db2e28ebffc70b16694cc637f0

	int i = kad_lookup_value( "53e2e30f2c01cfd823b30a07d5ad0b9072e2b3db2e28ebffc70b16694cc637f0.p2p", &addr_array[0], &addr_num );
	printf("lookup test: %d\n", i);

	IP addr;
	addr_parse( &addr, "127.0.0.2", gconf->dht_port, AF_INET );
	struct results_t **results = results_get();
	results_add_addr( *results, &addr);
}


	// Loop over all sockets and file descriptors
	net_loop();

	// Export peers if a file is provided
	peerfile_export();

	return 0;
}

#ifdef __CYGWIN__
int main( int argc, char **argv ) {

	conf_init();
	conf_load_args( argc, argv );

	if( gconf->service_start ) {
		gconf->use_syslog = 1;

		// Get kadnode.exe binary lcoation
		char cmd[MAX_PATH], path[MAX_PATH], *p;
		if( GetModuleFileNameA( NULL, path, sizeof(path) ) && (p = strrchr( path, '\\' )) ) {
			*(p+1) = 0;
		} else {
			log_err( "MAIN: Can not get location of KadNode binary." );
			exit( 1 );
		}

		// Set DNS server to localhost
		sprintf( cmd, "cmd.exe /c \"%s\\dns_setup.bat\"", path );
		windows_exec( cmd );

		int rc = windows_service_start( (void (*)()) main_start );

		// Reset DNS settings to DHCP
		sprintf( cmd, "cmd.exe /c \"%s\\dns_reset.bat\"", path );
		windows_exec( cmd );

		return rc;
	}

	if( gconf->is_daemon ) {
		gconf->use_syslog = 1;

		// Fork before any threads are started
		unix_fork();

		// Change working directory to C:\ directory or disk equivalent
		char path[MAX_PATH], *p;
		if( GetModuleFileNameA( NULL, path, sizeof(path) ) && (p = strchr( path, '\\' )) ) {
			*(p+1) = 0;
			SetCurrentDirectoryA( path );
		}

		// Close pipes
		fclose( stderr );
		fclose( stdout );
		fclose( stdin );
	} else {
		conf_info();
	}

	// Catch signals
	windows_signals();

	// Write pid file
	if( gconf->pidfile ) {
		unix_write_pidfile( GetCurrentProcessId(), gconf->pidfile );
	}

	// Drop privileges
	unix_dropuid0();

	return main_start();
}
#else
int main( int argc, char **argv ) {

	conf_init();
	conf_load_args( argc, argv );

	if( gconf->is_daemon ) {
		gconf->use_syslog = 1;

		// Fork before any threads are started
		unix_fork();

		if( chdir( "/" ) != 0 ) {
			log_err( "UNX: Changing working directory to / failed: %s", strerror( errno ) );
			exit( 1 );
		}

		// Close pipes
		fclose( stderr );
		fclose( stdout );
		fclose( stdin );
	} else {
		conf_info();
	}

	// Catch signals
	unix_signals();

	// Write pid file
	if( gconf->pidfile ) {
		unix_write_pidfile( getpid(), gconf->pidfile );
	}

	// Drop privileges
	unix_dropuid0();

	return main_start();
}
#endif
