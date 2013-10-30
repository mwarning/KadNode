
#ifndef _LOG_H_
#define _LOG_H_

#include <syslog.h>

#include "main.h"

#define SHA1_HEX_LENGTH (2 * SHA1_BIN_LENGTH)
/* IPv6 address length including port, e.g. [::1]:12345 */
#define FULL_ADDSTRLEN (INET6_ADDRSTRLEN + 8)

/* Verbosity levels */
#define VERBOSITY_QUIET 0
#define VERBOSITY_VERBOSE 1
#define VERBOSITY_DEBUG 2

#define log_crit(...) _log(NULL, 0, LOG_CRIT, __VA_ARGS__)
#define log_err(...) _log(NULL, 0, LOG_ERR, __VA_ARGS__)
#define log_info(...) _log(NULL, 0, LOG_INFO, __VA_ARGS__)
#define log_warn(...) _log(NULL, 0, LOG_WARNING, __VA_ARGS__)
#define log_debug(...) _log(NULL, 0, LOG_DEBUG, __VA_ARGS__)


void _log( const char *filename, int line, int priority, const char *format, ... );

#endif /* _LOG_H_ */
