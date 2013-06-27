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

	/* Init the Kademlia DHT */
	kad_init();

	/* Start interfaces */
#ifdef DNS
	dns_start();
#endif
#ifdef WEB
	web_start();
#endif
#ifdef NSS
	nss_start();
#endif
#ifdef CMD
	cmd_start();
#endif

	kad_start();

	#ifdef CMD
    if( gstate->is_daemon == 0 ) {
		/* Wait for other messages to be displayed */
		sleep(1);
		cmd_console_loop();
	}
	#endif

	/* Stop interfaces */
#ifdef DNS
	dns_stop();
#endif
#ifdef WEB
	web_stop();
#endif
#ifdef NSS
	nss_stop();
#endif
#ifdef CMD
	cmd_stop();
#endif

	kad_stop();

	conf_free();

	return 0;
}
