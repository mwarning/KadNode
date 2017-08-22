
#ifndef _EXT_TLS_SERVER_H_
#define _EXT_TLS_SERVER_H_

#include <kadnode/searches.h>

// Add domain via cert and key file
int tls_server_add_sni( const char crt_file[], const char key_file[] );

void tls_server_setup( void );
void tls_server_free( void );


#endif /* _EXT_TLS_SERVER_H_ */
