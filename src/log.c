
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>

#include "main.h"
#include "conf.h"
#include "log.h"


int _log_check( int priority ) {
	if( (gconf->verbosity == VERBOSITY_QUIET) &&
			(priority == LOG_INFO || priority == LOG_DEBUG) ) {
		return 0;
	}

	if( (gconf->verbosity == VERBOSITY_VERBOSE) &&
			(priority == LOG_DEBUG) ) {
		return 0;
	}

	return 1;
}

void _log_print( int priority, const char *format, ... ) {
	char buffer[512];
	const char *prefix;
	va_list vlist;

	va_start( vlist, format );
	vsnprintf( buffer, sizeof(buffer) - 1, format, vlist );
	va_end( vlist );

	/* Select a prefix to quickly distinguish messages */
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
		case LOG_CRIT:
			prefix = "(C)";
			break;
		default:
			prefix = "(?)";
	}

	if( gconf->use_syslog ) {
		/* Write messages to e.g. /var/log/syslog */
		openlog( MAIN_SRVNAME, LOG_PID | LOG_CONS, LOG_USER | LOG_PERROR );
		syslog( priority, "%s %s", prefix, buffer );
		closelog();
	} else {
		fprintf( stderr, "%s %s\n", prefix, buffer );
	}

	if( priority == LOG_CRIT || priority == LOG_ERR ) {
		exit( 1 );
	}
}
