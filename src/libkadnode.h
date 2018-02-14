
#ifndef _LIBKADNODE_H_
#define _LIBKADNODE_H_

/*
* KadNode as a library.
*
* Not yet finished!
*/

int kadnode_init(void);
int kadnode_set(const char opt[], const char val[]);
int kadnode_lookup(const char query[], struct sockaddr_storage addr_array[], size_t addr_num);
void kadnode_stop(void);

#endif // _LIBKADNODE_H_
