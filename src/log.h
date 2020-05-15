
#ifndef _LOG_H_
#define _LOG_H_


#include <syslog.h>

// Verbosity levels
enum {
  VERBOSITY_DEBUG,
  VERBOSITY_VERBOSE,
  VERBOSITY_QUIET
};

#define log_error(...) \
  log_print(LOG_ERR, __VA_ARGS__);

#define log_info(...)                          \
  do {                                         \
    if (gconf->verbosity != VERBOSITY_QUIET)   \
      log_print(LOG_INFO, __VA_ARGS__);        \
  } while (0)

#define log_warning(...)                       \
  do {                                         \
    if (gconf->verbosity != VERBOSITY_QUIET)   \
      log_print(LOG_WARNING, __VA_ARGS__);     \
  } while (0)

#ifdef DEBUG
  #define log_debug(...)                       \
    do {                                       \
      if (gconf->verbosity == VERBOSITY_DEBUG) \
        log_print(LOG_DEBUG, __VA_ARGS__);     \
    } while (0)
#else
  #define log_debug(...) // Exclude debug messages from debug build
#endif

// Print a log message
void log_print(int priority, const char format[], ...);

#endif // _LOG_H_
