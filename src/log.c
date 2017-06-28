
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>

#include "main.h"
#include "conf.h"
#include "log.h"


#ifdef DEBUG
// Program start time
static struct timespec log_start = { 0, 0 };

char *log_time() {
	struct timespec now = { 0, 0 };
	clock_gettime( CLOCK_MONOTONIC_COARSE, &now );

	static char buf[16];
	sprintf( buf, "%.5f",
		((double) now.tv_sec + 1.0e-9 * now.tv_nsec) -
		((double) log_start.tv_sec + 1.0e-9 * log_start.tv_nsec)
	);

	return buf;
}
#endif

void log_print( int priority, const char format[], ... ) {
	char buf[512];
	const char *prefix;
	va_list vlist;

	va_start( vlist, format );
	vsnprintf( buf, sizeof(buf) - 1, format, vlist );
	va_end( vlist );

	// Select a prefix to quickly distinguish messages
	switch( priority ) {
		case LOG_INFO:
			prefix = "(I)";
			break;
		case LOG_DEBUG:
			prefix = "(D)";
			break;
		case LOG_WARNING:
			prefix = "(W)";
			break;
		case LOG_ERR:
			prefix = "(E)";
			break;
		default:
			prefix = "(?)";
	}

	if( gconf->use_syslog ) {
		// Write messages to e.g. /var/log/syslog
		openlog( MAIN_SRVNAME, LOG_PID | LOG_CONS, LOG_USER | LOG_PERROR );
		syslog( priority, "%s %s", prefix, buf );
		closelog();
	} else {
		fprintf( stderr, "%s %s\n", prefix, buf );
	}
}

void log_setup( void ) {
#ifdef DEBUG
	clock_gettime( CLOCK_MONOTONIC_COARSE, &log_start );
#endif
}

void log_free( void ) {
	// Nothing to do
}
