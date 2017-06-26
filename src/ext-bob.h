
#ifndef _EXT_BOB_H_
#define _EXT_BOB_H_

#include "results.h"


// Decide if the query is meant to be authorized via BOB
int bob_get_id( uint8_t id[], size_t len, const char query[] );
void bob_trigger_auth( struct search_t *results );

// .. for kad.c - remove?
int bob_handler( int sock, uint8_t buf[], uint32_t buflen, IP *from );

// Add secret key
void bob_add_skey( const char arg[] );

// Print secret/public keys to file descriptor
void bob_debug_keys( int fd );

// Generate a public/secret key pair and print it to stdout
int bob_generate_key_pair( void );

void bob_setup( void );
void bob_free( void );

#endif // _EXT_BOB_H_
