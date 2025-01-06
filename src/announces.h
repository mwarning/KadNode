
#ifndef _EXT_ANNOUNCES_H_
#define _EXT_ANNOUNCES_H_

#include <sys/time.h>
#include <stdio.h>

#include "searches.h"

/*
* Announce a value id / port pair in regular
* intervals until the lifetime expires.
*/

struct announcement_t {
    struct announcement_t *next;
    uint8_t id[ID_BINARY_LENGTH];
    char query[QUERY_MAX_SIZE];
    int port;
    enum AUTH_TYPE auth_type;
    time_t lifetime; // Keep entry refreshed until the lifetime expires
    time_t refresh; // Next time the entry need to be refreshed
};

void announces_setup(void);
void announces_free(void);

struct announcement_t* announces_get(void);
struct announcement_t* announces_find(const uint8_t id[]);
void announces_remove(FILE *fp, const char query[]);

// List all entries
void announces_print(FILE *fp);

// Add a value id / port that will be announced until lifetime is exceeded
struct announcement_t *announces_add(FILE *fp, const char query[], time_t lifetime);


#endif // _EXT_ANNOUNCES_H_
