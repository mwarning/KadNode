
#ifndef _EXT_AUTH_H_
#define _EXT_AUTH_H_


char *auth_str_skey( char *buf, const UCHAR skey[] );
char *auth_str_pkey( char *buf, const UCHAR pkey[] );
char *auth_str_challenge( char *buf, const UCHAR challenge[] );

/* Check if a query has the secret/public key format */
int auth_is_pkey( const char query[] );
int auth_is_skey( const char query[] );

/* Function that is hooked up the DHT socket */
int auth_handle_packet( int sock, UCHAR buf[], size_t buflen, IP *from );

/*
* Allocate and parse a public key if the query
* is of the form '<hex-public-key>[.<...>]'.
* Everything after and including the last dot is ignored.
*/
UCHAR *auth_parse_pkey( const char query[] );

/*
* Allocate and parse a secret key if the query
* is of the form '<hex-secret-key>[.<...>]'.
* Everything after and including the last dot is ignored.
*/
UCHAR *auth_parse_skey( const char query[] );

/* Generate a public/secret key pair and print it to stdout */
int auth_generate_key_pair( void );

void auth_setup( void );

#endif /* _EXT_AUTH_H_ */
