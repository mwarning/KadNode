
#ifndef _EXT_AUTH_H_
#define _EXT_AUTH_H_

#include "results.h"


int bob_decide_auth( const char query[] );
void bob_trigger_auth( struct results_t *results );
int bob_handler( int sock, uint8_t buf[], uint32_t buflen, IP *from );

/*
* Add secret key.
*/
void bob_add_skey( const char arg[] );

/*
* Print secret/public keys to stdout.
*/
void bob_debug_skeys( int fd );
void bob_debug_pkeys( int fd );

/* Functions that are hooked up the DHT socket */
//void bob_send_challenges( int sock );
//int bob_handle_challenges( int sock, uint8_t buf[], size_t buflen, IP *from );

/* Generate a public/secret key pair and print it to stdout */
int bob_generate_key_pair( void );

void bob_setup( void );
void bob_free( void );

#endif /* _EXT_AUTH_H_ */
