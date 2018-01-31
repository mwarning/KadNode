
#ifndef _LOG_H_
#define _LOG_H_


#include <syslog.h>

// Verbosity levels
#define VERBOSITY_DEBUG LOG_DEBUG
#define VERBOSITY_VERBOSE LOG_INFO
#define VERBOSITY_QUIET LOG_WARNING


#define log_error(...) \
  log_print(LOG_ERR, __VA_ARGS__);

#define log_info(...)                   \
  do {                                  \
    if (g_config.verbosity >= LOG_INFO) \
      log_print(LOG_INFO, __VA_ARGS__); \
  } while (0)

#define log_warning(...)                   \
  do {                                     \
    if (g_config.verbosity >= LOG_WARNING) \
      log_print(LOG_WARNING, __VA_ARGS__); \
  } while (0)

#ifdef DEBUG
  #define log_debug(...)                   \
    do {                                   \
      if (g_config.verbosity >= LOG_DEBUG) \
        log_print(LOG_DEBUG, __VA_ARGS__); \
    } while (0)
#else
  #define log_debug(...) // Exclude debug messages from debug build
#endif

// Print a log message
void log_print(int priority, const char format[], ...);

#endif // _LOG_H_
