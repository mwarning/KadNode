
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

#define log_crit(...) if(_log_check(LOG_CRIT)) {_log_print(LOG_CRIT, __VA_ARGS__);}
#define log_err(...) if(_log_check(LOG_ERR)) {_log_print(LOG_ERR, __VA_ARGS__);}
#define log_info(...) if(_log_check(LOG_INFO)) {_log_print(LOG_INFO, __VA_ARGS__);}
#define log_warn(...) if(_log_check(LOG_WARNING)) {_log_print(LOG_WARNING, __VA_ARGS__);}
#define log_debug(...) if(_log_check(LOG_DEBUG)) {_log_print(LOG_DEBUG, __VA_ARGS__);}


int _log_check( int priority );
void _log_print( int priority, const char *format, ... );

#endif /* _LOG_H_ */
