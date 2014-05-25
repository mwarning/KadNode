
#ifndef _KAD_H_
#define _KAD_H_

/*
* Interface to interact with the DHT implementation.
* Negative return values indicate an error, success otherwise.
*/


/* Setup the DHT */
void kad_setup( void );

/* Ping this node to add it to the node table */
int kad_ping( const IP *addr );

/* Blacklist a specific address */
int kad_blacklist( const IP* addr );

/*
* Lookup the address of the node whose node id matches id.
* The lookup will be performed on the results of kad_lookup_value().
*/
int kad_lookup_node( const char query[], IP *addr_return );

/*
* Lookup the addresses of the nodes who have announced value id.
* The first call will start the search.
*/
int kad_lookup_value( const char query[], IP addr_array[], size_t *addr_num );

/* Export good nodes */
int kad_export_nodes( IP addr_array[], size_t *addr_num );

/* Print status information */
int kad_status( char *buf, int len );

/* Count good or all known peers */
int kad_count_nodes( int good );

/*
* Announce that the resource identified by id can
* be served by this computer using the given port.
*/
int kad_announce_once( const UCHAR id[], int port );

/* Announce query until lifetime expires. */
int kad_announce( const char query[], int port, time_t lifetime );

/* Various debug functions */
void kad_debug_buckets( int fd );
void kad_debug_searches( int fd );
void kad_debug_storage( int fd );
void kad_debug_blacklist( int fd );
void kad_debug_constants( int fd );

#endif /* _KAD_H_ */
