
#ifndef _EXT_TLS_SERVER_H_
#define _EXT_TLS_SERVER_H_

#include "results.h"


void tls_add_sni_entry( const char name[], const char crt_file[], const char key_file[] );

void tls_server_setup( void );
void tls_server_free( void );

#endif /* _EXT_TLS_SERVER_H_ */
