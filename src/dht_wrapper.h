#ifndef _DHT_WRAPPER_H_
#define _DHT_WRAPPER_H_


void kad_init( void );

/* Start/Stop the DHT thread */
void kad_start( void );
void kad_stop( void );

/* Ping this node for bootstrapping */
void kad_ping( const IP *addr );

/* Blacklist a specific address */
int kad_blacklist( const IP* addr );

/* Start a search for a node id */
int kad_search( int af, const UCHAR *id );

/*
* Lookup the address of the node whose node id matches id.
* The Lookup will be performed on the search result.
*/
int kad_lookup_node( int af, const UCHAR* id, IP *addr_return );

/*
* Lookup the addresses of the nodes who have announced id.
* The Lookup will be performed on the search result.
*/
int kad_lookup_values( int af, const UCHAR* id, IP addr_array[], int *addr_num );

/* Export good nodes */
int kad_export_nodes( int af, IP addr_array[], int *addr_num );

/* Print status information */
int kad_status( char *buf, int len );

#ifdef DEBUG
/* Print DHT data structures */
void kad_debug( int fd );
#endif

/* 
* Announce that the resource identified by id can
* be served by this computer using the given port.
*/
int kad_announce( int af, const UCHAR *id, unsigned short port );


#endif /* _DHT_WRAPPER_H_ */
