#define _GNU_SOURCE


#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "kad.h"
#include "utils.h"
#include "unix.h"
#include "net.h"
#include "values.h"
#include "results.h"

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
#include "forwardings.h"
#endif


void main_export_peers( void ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	IP addrs[32];
	int i, num;
	FILE * fp;
	const char *filename;

	filename = gstate->peerfile;
	if( filename == NULL ) {
		return;
	}

	num = N_ELEMS(addrs);
	if( kad_export_nodes( addrs, &num ) != 0 ) {
		log_warn("MAIN: Failed to export nodes.");
		return;
	}

	/* No peers to export */
	if( num == 0 ) {
		log_info( "MAIN: No peers to export." );
		return;
	}

	if( gstate->time_now.tv_sec - gstate->startup_time < (5 * 60) ) {
		log_info( "MAIN: No peers exported. Programm needs to run at least 5 minutes." );
		return;
	}

	fp = fopen( filename, "w" );
	if( fp == NULL ) {
		log_err( "MAIN: Cannot open file '%s' for peer export: %s", filename, strerror( errno ) );
		return;
	}

	/* Write peers to file */
	for( i = 0; i < num; ++i ) {
		if( fprintf( fp, "%s\n", str_addr( &addrs[i], addrbuf ) ) < 0 ) {
			break;
		}
	}

	fclose( fp );

	log_info( "MAIN: Exported %d peers to: %s", i, filename );
}

void main_import_peers( void ) {
	char linebuf[256];
	FILE *fp;
	int num;
	IP addr;
	const char *filename;

	filename = gstate->peerfile;
	if( filename == NULL ) {
		return;
	}

	fp = fopen( filename, "r" );
	if( fp == NULL ) {
		log_err( "MAIN: Cannot open file '%s' for peer import: %s", filename, strerror( errno ) );
	}

	num = 0;
	while( fgets( linebuf, sizeof(linebuf), fp ) != NULL ) {
		linebuf[strcspn( linebuf, "\n" )] = '\0';
		if( linebuf[0] == '\0' ) {
			continue;
		}

		if( addr_parse_full( &addr, linebuf, DHT_PORT, gstate->af ) == ADDR_PARSE_SUCCESS ) {
			if( kad_ping( &addr ) == 0 ) {
				num++;
			} else {
				fclose( fp );
				log_err( "MAIN: Cannot ping peers: %s", strerror( errno ) );
				return;
			}
		}
	}

	fclose( fp );

	log_info( "MAIN: Imported %d peers from: %s", num, filename );
}

int main( int argc, char **argv ) {

	conf_init();
	conf_load( argc, argv );
	conf_check();

    if( gstate->is_daemon == 1 ) {

		/* Close pipes */
		fclose( stderr );
		fclose( stdout );
		fclose( stdin );

		if( chdir( "/" ) != 0 ) {
			log_err( "UNX: Changing working directory to / failed: %s", strerror( errno ) );
		}

		/* Fork before any threads are started */
		unix_fork();
	}

	/* Catch SIG INT */
	unix_signal();

	/* Write a pid file */
	unix_write_pidfile( getpid() );

	/* Drop privileges */
	unix_dropuid0();

	/* Setup the Kademlia DHT */
	kad_setup();

	/* Setup handler to announce values */
	values_setup();

	/* Setup handler to expire results */
	results_setup();

	/* Setup port-forwarding */
#ifdef FWD
	forwardings_setup();
#endif

	/* Setup interfaces */
#ifdef DNS
	dns_setup();
#endif
#ifdef WEB
	web_setup();
#endif
#ifdef NSS
	nss_setup();
#endif
#ifdef CMD
	cmd_setup();
#endif

	/* Loop over all sockets and FDs */
	net_loop();

	/* Export peers if a file is provided */
	main_export_peers();

	conf_free();

	return 0;
}
