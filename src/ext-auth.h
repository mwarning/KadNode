
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
* Returns a pointer to key if a key was found.
*/
UCHAR *auth_handle_skey( UCHAR skey[], UCHAR id[], const char *query );
UCHAR *auth_handle_pkey( UCHAR pkey[], UCHAR id[], const char *query );

/*
* Print secret/public keys to s.
*/
void auth_debug_skeys( void );
void auth_debug_pkeys( void );

/* Check if a query has the secret/public key format */
//int auth_is_pkey( const char query[] );
int auth_is_skey( const char query[] );

/* Function that is hooked up the DHT socket */
int auth_handle_packet( int sock, UCHAR buf[], size_t buflen, IP *from );

/* Generate a public/secret key pair and print it to stdout */
int auth_generate_key_pair( void );

void auth_setup( void );

#endif /* _EXT_AUTH_H_ */
