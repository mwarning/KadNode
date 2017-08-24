
#include "conf.h"
#include "kad.h"
#include "net.h"
#include "main.h"
#include "peerfile.h"

#include "libkadnode.h"


int kadnode_init( void ) {
	if( gconf == NULL ) {
		// Setup gconf
		conf_init();
		return 0;
	} else {
		return 1;
	}
}

void kadnode_stop( void ) {
	if( gconf ) {
		gconf->is_running = 0;
	}
}

int kadnode_set( const char opt[], const char val[] ) {
	if( gconf && !gconf->is_running ) {
		return conf_set( opt, val );
	} else {
		return 1;
	}
}

void kadnode_loop( void ) {
	if( gconf && gconf->is_running == 0 ) {
		conf_check();

		main_setup();

		// Loop over all sockets and file descriptors
		net_loop();

		// Export peers if a file is provided
		peerfile_export();

		main_free();

		conf_free();
	}
}

int kadnode_lookup( const char query[], struct sockaddr_storage addr_array[], size_t addr_num ) {
	if( gconf && gconf->is_running ) {
		return kad_lookup( query, addr_array, addr_num );
	} else {
		return 1;
	}
}
