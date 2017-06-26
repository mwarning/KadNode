
#ifndef _EXT_TLS_CLIENT_H_
#define _EXT_TLS_CLIENT_H_

#include "searches.h"


// Add Certifiacte Authorities (CAs)
void tls_client_add_ca( const char ca_path[] );

// Decide if the query is meant to be authorized via an CA
int tls_client_get_id( uint8_t id[], size_t len, const char query[] );

// Trigger the authorisation of the results
// May be called multiple times for the same search
void tls_client_trigger_auth( struct search_t *search );

void tls_client_setup( void );
void tls_client_free( void );


#endif // _EXT_TLS_CLIENT_H_
