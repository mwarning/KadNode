
#ifndef _KAD_H_
#define _KAD_H_


/* Setup the DHT */
void kad_setup( void );

/* Ping this node for bootstrapping */
int kad_ping( const IP *addr );

/* Blacklist a specific address */
int kad_blacklist( const IP* addr );

/*
* Lookup the address of the node whose node id matches id.
* The lookup will be performed on the results of kad_lookup_value().
*/
int kad_lookup_node( const UCHAR* id, IP *addr_return );

/*
* Lookup the addresses of the nodes who have announced value id.
* The first call will start the search.
*/
int kad_lookup_value( const UCHAR* id, IP addr_array[], int *addr_num );

/* Export good nodes */
int kad_export_nodes( IP addr_array[], int *addr_num );

/* Print status information */
int kad_status( char *buf, int len );

/* Count all nodes in the given bucket */
int kad_count_nodes( void );

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
