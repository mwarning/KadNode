
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#include "peerfile.h"


/* Next time to import peers from peer file */
static time_t peerfile_import_time = 0;

/* Next time to export peers to peer file  */
static time_t peerfile_export_time = 0;


void peerfile_export( void ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	const char *filename;
	IP addrs[150];
	size_t i, num;
	FILE * fp;

	filename = gconf->peerfile;
	if( filename == NULL ) {
		return;
	}

	num = N_ELEMS(addrs);
	if( kad_export_nodes( addrs, &num ) != 0 ) {
		log_warn("PEERFILE: Failed to export nodes.");
		return;
	}

	/* No peers to export */
	if( num == 0 ) {
		log_info( "PEERFILE: No peers to export." );
		return;
	}

	if( (time_now_sec() - gconf->startup_time) < (5 * 60) ) {
		log_info( "PEERFILE: No peers exported. KadNode needs to run at least 5 minutes." );
		return;
	}

	fp = fopen( filename, "w" );
	if( fp == NULL ) {
		log_warn( "PEERFILE: Cannot open file '%s' for peer export: %s", filename, strerror( errno ) );
		return;
	}

	/* Write peers to file */
	for( i = 0; i < num; ++i ) {
#ifdef __CYGWIN__
		if( fprintf( fp, "%s\r\n", str_addr( &addrs[i], addrbuf ) ) < 0 ) {
			break;
		}
#else
		if( fprintf( fp, "%s\n", str_addr( &addrs[i], addrbuf ) ) < 0 ) {
			break;
		}
#endif
	}

	fclose( fp );

	log_info( "PEERFILE: %d peers exported: %s", i, filename );
}

void peerfile_import( void ) {
	char linebuf[256];
	const char *filename;
	FILE *fp;
	int num;
	int rc;
	IP addr;

	filename = gconf->peerfile;
	if( filename == NULL ) {
		return;
	}

	fp = fopen( filename, "r" );
	if( fp == NULL ) {
		log_warn( "PEERFILE: Cannot open file '%s' for peer import: %s", filename, strerror( errno ) );
		return;
	}

	num = 0;
	while( fgets( linebuf, sizeof(linebuf), fp ) != NULL && gconf->is_running ) {
		linebuf[strcspn( linebuf, "\n\r" )] = '\0';

		if( linebuf[0] == '\0' || linebuf[0] == '#' ) {
			continue;
		}

		if( (rc = addr_parse_full( &addr, linebuf, DHT_PORT, gconf->af )) == 0 ) {
			if( kad_ping( &addr ) == 0 ) {
				num++;
			} else {
				log_warn( "PEERFILE: Cannot ping address '%s': %s", linebuf, strerror( errno ) );
				goto end;
			}
		} else if( rc == -1 ) {
			log_warn( "PEERFILE: Cannot parse address: '%s'", linebuf );
		} else {
			log_warn( "PEERFILE: Cannot resolve address: '%s'", linebuf );
		}
	}

	log_info( "PEERFILE: Imported %d peers from: '%s'", num, filename );

	end:;
	fclose( fp );
}

void peerfile_handle_peerfile( int _rc, int _sock ) {

	if( peerfile_import_time <= time_now_sec() && kad_count_nodes( 0 ) == 0 ) {
		/* Ping peers from peerfile, if present */
		peerfile_import();

		/* Try again in ~5 minutes */
		peerfile_import_time = time_add_min( 5 );
	}

	if( peerfile_export_time <= time_now_sec() && kad_count_nodes( 1 ) != 0 ) {
		/* Export peers */
		peerfile_export();

		/* Try again in 24 hours */
		peerfile_export_time = time_add_hour( 24 );
	}
}

void peerfile_setup( void ) {
	peerfile_import_time = time_now_sec() + 10;
	peerfile_export_time = time_now_sec();
	net_add_handler( -1 , &peerfile_handle_peerfile );
}

void peerfile_free( void ) {
	/* Nothing to do */
}
