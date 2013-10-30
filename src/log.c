
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>

#include "main.h"
#include "conf.h"
#include "log.h"


void _log( const char *filename, int line, int priority, const char *format, ... ) {
	char buffer[512];
	const char *prefix;
	va_list vlist;

	if( (gstate->verbosity == VERBOSITY_QUIET) &&
		(priority == LOG_INFO || priority == LOG_DEBUG) ) {
		return;
	}

	if( (gstate->verbosity == VERBOSITY_VERBOSE) &&
		(priority == LOG_DEBUG) ) {
		return;
	}

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

	if( gstate->use_syslog ) {
		/* Write messages to e.g. /var/log/syslog */
		openlog( MAIN_SRVNAME, LOG_PID|LOG_CONS, LOG_USER|LOG_PERROR );
		if( filename ) {
			syslog( priority, "%s (%s:%d) %s", prefix, filename, line, buffer );
		} else {
			syslog( priority, "%s %s", prefix, buffer );
		}
		closelog();
	} else {
		if( filename ) {
			fprintf( stderr, "%s (%s:%d) %s\n", prefix, filename, line, buffer );
		} else {
			fprintf( stderr, "%s %s\n", prefix, buffer );
		}
	}

	if( priority == LOG_CRIT || priority == LOG_ERR ) {
		exit( 1 );
	}
}
