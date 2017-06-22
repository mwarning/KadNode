
#ifndef _EXT_TLS_CLIENT_H_
#define _EXT_TLS_CLIENT_H_

#include "results.h"


void tls_client_add_ca( const char ca_path[] );

int tls_decide_auth( const char query[] );
void tls_trigger_auth( struct results_t *results );

void tls_client_setup( void );
void tls_client_free( void );


#endif /* _EXT_TLS_CLIENT_H_ */
