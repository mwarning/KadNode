
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#include "peerfile.h"


struct peer {
	struct peer *next;
	char* addr_str;
};

// Next time to import peers from peer file
static time_t peerfile_import_time = 0;

// Next time to export peers to peer file
static time_t peerfile_export_time = 0;

// A list of static peers, given by --peer argument
static struct peer *g_peers = NULL;


void peerfile_export( void ) {
	const char *filename;
	FILE *fp;
	int num;

	filename = gconf->peerfile;
	if( filename == NULL ) {
		return;
	}

	if( (time_now_sec() - gconf->startup_time) < (5 * 60) ) {
		log_info( "PEERFILE: No peers exported. KadNode needs to run at least 5 minutes." );
		return;
	}

	fp = fopen( filename, "w" );
	if( fp == NULL ) {
		log_warning( "PEERFILE: Cannot open file '%s' for peer export: %s", filename, strerror( errno ) );
		return;
	}

	num = kad_export_nodes(fp);
	fclose(fp);

	// No peers to export
	if( num <= 0 ) {
		log_info( "PEERFILE: No peers to export." );
		return;
	}

	log_info( "PEERFILE: %d peers exported: %s", num, filename );
}

static int peerfile_import_peer( const char addr_str[] ) {
	IP addr;
	int rc;

	if( (rc = addr_parse_full( &addr, addr_str, STR(DHT_PORT), gconf->af ) ) == 0 ) {
		if( kad_ping( &addr ) == 0 ) {
			return 1;
		} else {
			log_warning( "PEERFILE: Cannot ping address '%s': %s", addr_str, strerror( errno ) );
			return 0;
		}
	} else {
		log_warning( "PEERFILE: Cannot resolve address '%s': %s", addr_str, gai_strerror(rc) );
	}

	return 0;
}

static void peerfile_import( void ) {
	const char *filename;
	char linebuf[256];
	FILE *fp;
	int num;

	filename = gconf->peerfile;
	if( filename == NULL ) {
		return;
	}

	fp = fopen( filename, "r" );
	if( fp == NULL ) {
		log_warning( "PEERFILE: Cannot open file '%s' for peer import: %s", filename, strerror( errno ) );
		return;
	}

	num = 0;
	while( fgets( linebuf, sizeof(linebuf), fp ) != NULL && gconf->is_running ) {
		linebuf[strcspn( linebuf, "\n\r" )] = '\0';

		if( linebuf[0] == '\0' || linebuf[0] == '#' ) {
			continue;
		}

		num += peerfile_import_peer( linebuf );
	}

	fclose( fp );

	log_info( "PEERFILE: Imported %d peers from: '%s'", num, filename );
}

static void peerfile_import_static( const struct peer *peers ) {
	int num;

	num = 0;
	while( peers ) {
		num += peerfile_import_peer( peers->addr_str );
		peers = peers->next;
	}

	if( num ) {
		log_info( "PEERFILE: Imported %d static peers.", num );
	}
}

int peerfile_add_peer( const char addr_str[] ) {
	struct peer *new;

	new = (struct peer *) malloc( sizeof(struct peer) );
	new->addr_str = strdup( addr_str );
	new->next = g_peers;
	g_peers = new;

	return 0;
}

static void peerfile_handle_peerfile( int _rc, int _sock ) {

	if( peerfile_import_time <= time_now_sec() && kad_count_nodes( 0 ) == 0 ) {
		// Ping peers from peerfile, if present
		peerfile_import();

		// Import static peers
		peerfile_import_static( g_peers );

		// Try again in ~5 minutes
		peerfile_import_time = time_add_mins( 5 );
	}

	if( peerfile_export_time <= time_now_sec() && kad_count_nodes( 1 ) != 0 ) {
		// Export peers
		peerfile_export();

		// Try again in 24 hours
		peerfile_export_time = time_add_hours( 24 );
	}
}

void peerfile_setup( void ) {
	peerfile_import_time = time_add_secs( 10 );
	peerfile_export_time = time_add_hours( 24 );
	net_add_handler( -1 , &peerfile_handle_peerfile );
}

void peerfile_free( void ) {
	struct peer *next;
	struct peer *p;

	p = g_peers;
	while( p ) {
		next = p->next;
		free( p->addr_str );
		free( p );
		p = next;
	}
}
