
#ifndef _LPD_H
#define _LPD_H

/*
* Send multicast messages to discover
* new nodes if no other nodes are known.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int lpd_setup(void);
void lpd_free(void);

#endif // _LPD_H
