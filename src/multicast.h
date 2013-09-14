
#ifndef _MULTICAST_H
#define _MULTICAST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int multicast_join( int sock, IP *addr );
int multicast_leave( int sock, IP *addr );

#endif /* _MULTICAST_H */
