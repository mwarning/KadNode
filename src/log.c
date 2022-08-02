
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

const char *log_time()
{
	static char buf[16];
	struct timespec now = { 0, 0 };

	clock_gettime(CLOCK_MONOTONIC, &now);

	// Initialize clock
	if (log_start.tv_sec == 0 && log_start.tv_nsec == 0) {
		clock_gettime(CLOCK_MONOTONIC, &log_start);
	}

	sprintf(buf, "[%8.2f] ",
		((double) now.tv_sec + 1.0e-9 * (double)now.tv_nsec) -
		((double) log_start.tv_sec + 1.0e-9 * (double)log_start.tv_nsec)
	);

	return buf;
}

#endif

void log_print(int priority, const char format[], ...)
{
	char buf[1024];
	const char *time;
	va_list vlist;

	va_start(vlist, format);
	vsnprintf(buf, sizeof(buf), format, vlist);
	va_end(vlist);

#ifdef DEBUG
	time = log_time();
#else
	time = "";
#endif

	if (gconf != NULL && gconf->use_syslog) {
		// Write messages to e.g. /var/log/syslog
		openlog(MAIN_SRVNAME, LOG_PID | LOG_CONS, LOG_USER | LOG_PERROR);
		syslog(priority, "%s%s", time, buf);
		closelog();
	} else {
		FILE *out = (priority == LOG_ERR) ? stderr : stdout;
		fprintf(out, "%s%s\n", time, buf);
	}
}
