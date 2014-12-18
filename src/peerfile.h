
#ifndef _PEERFILE_H
#define _PEERFILE_H


/*
* Ping nodes from a given peerfile as long as no nodes are known.
* Good nodes need also be written back to a peerfile on shutdown.
*/

/* Setup callbacks */
void peerfile_setup( void );
void peerfile_free( void );

/* Write peers to peerfile */
void peerfile_export( void );

/* Ping peers from peerfile */
void peerfile_import( void );


#endif /* _PEERFILE_H */
