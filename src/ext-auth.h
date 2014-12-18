
#ifndef _EXT_AUTH_H_
#define _EXT_AUTH_H_

/*
* Add keys from command line arguments:
* "[<string_pattern>:]<hex_key>"
*/
void auth_add_pkey( const char arg[] );
void auth_add_skey( const char arg[] );

/*
* Get key and id based on query.
* Returns a pointer to the key - if found.
*/
UCHAR *auth_handle_skey( UCHAR skey[], UCHAR id[], const char query[] );
UCHAR *auth_handle_pkey( UCHAR pkey[], UCHAR id[], const char query[] );

/*
* Print secret/public keys to stdout.
*/
void auth_debug_skeys( int );
void auth_debug_pkeys( int );

/* Functions that are hooked up the DHT socket */
void auth_send_challenges( int sock );
int auth_handle_challenges( int sock, UCHAR buf[], size_t buflen, IP *from );

/* Generate a public/secret key pair and print it to stdout */
int auth_generate_key_pair( void );

void auth_setup( void );
void auth_free( void );

#endif /* _EXT_AUTH_H_ */
