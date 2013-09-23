
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
#include "bootstrap.h"

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

	/* Setup handler to find nodes for bootstrapping */
	bootstrap_setup();

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
	bootstrap_export_peerfile();

	conf_free();

	return 0;
}
