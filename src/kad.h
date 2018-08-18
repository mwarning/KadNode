
#ifndef _KAD_H_
#define _KAD_H_

#include "searches.h"

/*
* Interface to interact with the DHT implementation.
* Negative return values indicate an error, success otherwise.
*/


int kad_setup(void);
void kad_free(void);

// Ping this node to add it to the node table
int kad_ping(const IP *addr);

// Blacklist a specific address
int kad_blacklist(const IP* addr);

/*
* Lookup the addresses of the nodes who have announced value id.
* The first call will start the search.
*/
const struct search_t *kad_lookup(const char query[]);

// Export good nodes
int kad_export_nodes(FILE *fp);

// Print status information
void kad_status(FILE *fp);

// Count good or all known peers
int kad_count_nodes(int good);

/*
* Announce that the resource identified by id can
* be served by this computer using the given port.
*/
int kad_announce_once(const uint8_t id[], int port);

// Announce query until lifetime expires.
int kad_announce(const char query[], int port, time_t lifetime);

// Various debug functions
void kad_debug_buckets(FILE *fp);
void kad_debug_searches(FILE *fp);
void kad_debug_storage(FILE *fp);
void kad_debug_blacklist(FILE *fp);
void kad_debug_constants(FILE *fp);

#endif // _KAD_H_
