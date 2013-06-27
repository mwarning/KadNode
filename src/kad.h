#ifndef _KAD_H_
#define _KAD_H_


void kad_init( void );

/* Start/Stop the DHT thread */
void kad_start( void );
void kad_stop( void );

/* Ping this node for bootstrapping */
void kad_ping( const IP *addr );

/* Blacklist a specific address */
int kad_blacklist( const IP* addr );

/* Start a search for a node id */
int kad_search( const UCHAR *id );

/*
* Lookup the address of the node whose node id matches id.
* The Lookup will be performed on the search results.
*/
int kad_lookup_node( const UCHAR* id, IP *addr_return );

/*
* Lookup the addresses of the nodes who have announced value id.
* The Lookup will be performed on the search results.
*/
int kad_lookup_value( const UCHAR* id, IP addr_array[], int *addr_num );

/* Export good nodes */
int kad_export_nodes( IP addr_array[], int *addr_num );

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
int kad_announce( const UCHAR *id, int port );


#endif /* _KAD_H_ */
