
#ifndef _BOOTSTRAP_H
#define _BOOTSTRAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Boostrapping consists of two mechanism,
The first is to ping nodes from a given peerfile
as long as no nodes are known.
The second mechanism is to send multicast
messages until another node is known.
Good nodes need also be written bakc to a peerfile
on shutdown.
*/

/* Setup callbacks */
void bootstrap_setup( void );

/* Write peers to peerfile */
void bootstrap_export_peerfile( void );

/* Ping peers from peerfile */
void bootstrap_import_peerfile( void );


#endif /* _BOOTSTRAP_H */
