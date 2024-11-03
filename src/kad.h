
#ifndef _KAD_H_
#define _KAD_H_

#include "searches.h"

/*
* Interface to interact with the DHT implementation.
* Negative return values indicate an error, success otherwise.
*/


bool kad_setup(void);
void kad_free(void);

// Ping this node to add it to the node table
bool kad_ping(const IP *addr);

// Blacklist a specific address
bool kad_blacklist(const IP* addr);

/*
* Lookup the addresses of the nodes who have announced value id.
* The first call will start the search.
*/
const struct search_t *kad_lookup(const char query[]);

// Block a specific address
bool kad_block(const IP* addr);

// Export good nodes
int kad_export_peers(FILE *fp);

// Print status information
void kad_status(FILE *fp);

// Count good or all known peers
int kad_count_nodes(bool good);

/*
* Announce that the resource identified by id can
* be served by this computer using the given port.
*/
int kad_announce_once(const uint8_t id[], int port);

// Announce query until lifetime expires.
int kad_announce(const char query[], int port, time_t lifetime);

// Various debug functions
void kad_print_buckets(FILE *fp);
void kad_print_searches(FILE *fp);
void kad_print_storage(FILE *fp);
void kad_print_blocklist(FILE *fp);
void kad_print_constants(FILE *fp);

#endif // _KAD_H_
