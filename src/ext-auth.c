
#define _WITH_DPRINTF
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include <sodium.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "values.h"
#include "results.h"
#include "ext-auth.h"


/* Maximum packets to process per second */
#define MAX_AUTH_REQUESTS 100
/* Maximum retries to send the challenge per address */
#define MAX_AUTH_CHALLENGE_SEND 10


struct key_t {
	char* pattern;
	UCHAR* keybytes;
	size_t keysize;
	struct key_t *next;
};

static struct key_t *g_secret_keys = NULL;
static struct key_t *g_public_keys = NULL;

static time_t g_send_challenges = 0;
static size_t g_request_counter = 0;
static time_t g_request_counter_started = 0;


/*
* Use secret key to create the corresponding public key.
*
* The public key is the second half of the secret key
* for the implemnetation used in libsodium.
*/
void auth_skey_to_pkey( const UCHAR skey[], UCHAR pkey[] ) {
	memcpy( pkey, skey + crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES, crypto_sign_PUBLICKEYBYTES );
}

/* Generate a new key pair and print it to stdout. */
int auth_generate_key_pair( void ) {
	UCHAR pk[crypto_sign_PUBLICKEYBYTES];
	UCHAR sk[crypto_sign_SECRETKEYBYTES];
	char pkhexbuf[2*crypto_sign_PUBLICKEYBYTES+1];
	char skhexbuf[2*crypto_sign_SECRETKEYBYTES+1];

	if( crypto_sign_keypair( pk, sk ) == 0) {
		fprintf( stdout, "public key: %s\n", bytes_to_hex( pkhexbuf, pk, sizeof(pk) ) );
		fprintf( stdout, "secret key: %s\n", bytes_to_hex( skhexbuf, sk, sizeof(sk) ) );
		return 0;
	} else {
		fprintf( stderr, "Failed to generate keys." );
		return 1;
	}
}

int auth_is_pkey( const char str[] ) {
	size_t size;

	size = strlen( str );
	if( size != 2*crypto_sign_PUBLICKEYBYTES ) {
		return 0;
	}

	return str_isHex( str, size );
}

int auth_is_skey( const char str[] ) {
	size_t size;

	size = strlen( str );
	if( size != 2*crypto_sign_SECRETKEYBYTES ) {
		return 0;
	}

	return str_isHex( str, size );
}

void auth_debug_skeys( int fd ) {
	const struct key_t *cur;
	char skeyhex[2*crypto_sign_SECRETKEYBYTES+1];
	int count;

	dprintf( fd, "All secret keys:\n" );
	count = 0;
	cur = g_secret_keys;
	while( cur ) {
		bytes_to_hex( skeyhex, cur->keybytes, cur->keysize );

		dprintf( fd, "  pattern: '%s'\n", cur->pattern );
		dprintf( fd, "   secret key: %s\n", skeyhex );

		count++;
		cur = cur->next;
	}

	dprintf( fd, " Found %d secret keys.\n", count );
}

void auth_debug_pkeys( int fd ) {
	const struct key_t *cur;
	char pkeyhex[2*crypto_sign_PUBLICKEYBYTES+1];
	int count;

	dprintf( fd, "All public keys:\n" );
	count = 0;
	cur = g_public_keys;
	while( cur ) {
		bytes_to_hex( pkeyhex, cur->keybytes, crypto_sign_PUBLICKEYBYTES );

		dprintf( fd, "  pattern: '%s'\n", cur->pattern );
		dprintf( fd, "   public key: %s\n", pkeyhex );

		count++;
		cur = cur->next;
	}

	dprintf( fd, " Found %d public keys.\n", count );
}

int is_pattern_conflict( const char p1[], const char p2[] ) {
	if( p1[0] == '*' && p2[0] == '*' ) {
		return (is_suffix( p1+1, p2+1 ) || is_suffix( p2+1, p1+1 ));
	} else if( p1[0] == '*' ) {
		return is_suffix( p2, p1+1 );
	} else if( p2[0] == '*' ) {
		return is_suffix( p1, p2+1 );
	} else {
		return (strcmp( p1, p2 ) == 0);
	}
}

int auth_find_key( UCHAR key[], const char query[], const struct key_t *keys ) {
	const struct key_t *cur;

	cur = keys;
	while( cur ) {
		/* Match query against pattern */
		if( (cur->pattern[0] == '*') && is_suffix( query, cur->pattern + 1 ) ) {
			memcpy( key, cur->keybytes, cur->keysize );
			return 1;
		} else if( strcmp( query, cur->pattern ) == 0 ) {
			memcpy( key, cur->keybytes, cur->keysize );
			return 1;
		}

		cur = cur->next;
	}

	return 0;
}

void free_key( struct key_t *key ) {
	/* Secure erase */
	memset( key->keybytes, '\0', key->keysize );

	free( key->keybytes );
	free( key->pattern );
	free( key );
}

/*
* Parse "[<pattern>:]<hex-key>" from the command line.
*/
int auth_parse_key( char pattern[], size_t patternsize, UCHAR key[], size_t keysize, const char arg[] ) {
	const char* colon;
	char hexkey[512];

	/* Parse arg string into key string and pattern string */
	colon = strchr( arg, ':' );
	if( colon == NULL ) {
		snprintf( pattern, patternsize, "%s", "*" );
		snprintf( hexkey, sizeof(hexkey), "%s", arg );
	} else {
		snprintf( pattern, patternsize, "%.*s", (int) (colon - arg), arg );
		snprintf( hexkey, sizeof(hexkey), "%s", colon + 1 );
	}

	/* Lower case query and cut off .p2p  */
	query_sanitize( pattern, patternsize, pattern );

	/* Validate key string format */
	if( strlen( hexkey ) != 2*keysize ) {
		log_err( "AUTH: Invalid key length. %d hex characters expected: %s", 2*keysize, hexkey );
		return 1;
	}

	if( !str_isHex( hexkey, 2*keysize ) ) {
		log_err( "AUTH: Invalid key format. Only hex characters expected: %s", hexkey );
		return 1;
	}

	if( strchr( pattern+1, '*' ) ) {
		log_err( "AUTH: The '*' is only allowed at the front of a pattern: '%s'", pattern );
		return 1;
	}

	bytes_from_hex( key, hexkey, strlen( hexkey ) );

	return 0;
}

void auth_add_key( const char pattern[], const UCHAR key[], size_t keysize, struct key_t **g_key_list ) {
	struct key_t* item;

	/* Check for conflicting patterns */
	item = *g_key_list;
	while( item ) {
		if( is_pattern_conflict( item->pattern, pattern ) ) {
			log_err( "AUTH: conflicting patterns: '%s' <=> '%s'", pattern, item->pattern );
			return;
		}
		item = item->next;
	}

	/* Create key item */
	item = (struct key_t*) calloc( 1, sizeof(struct key_t) );
	item->pattern = strdup( pattern );
	item->keybytes = memdup( key, keysize );
	item->keysize = keysize;

	/* Prepend to list */
	item->next = *g_key_list;
	*g_key_list = item;
}

void auth_add_pkey( const char arg[] ) {
	UCHAR pkey[crypto_sign_PUBLICKEYBYTES];
	char pattern[512];

	if( auth_parse_key( pattern, sizeof(pattern), pkey, sizeof(pkey), arg ) == 0 ) {
		auth_add_key( pattern, pkey, sizeof(pkey), &g_public_keys );
	}
}

void auth_add_skey( const char arg[] ) {
	UCHAR skey[crypto_sign_SECRETKEYBYTES];
	UCHAR pkey[crypto_sign_PUBLICKEYBYTES];
	char pattern[512];

	if( auth_parse_key( pattern, sizeof(pattern), skey, sizeof(skey), arg ) == 0 ) {
		auth_add_key( pattern, skey, sizeof(skey), &g_secret_keys );

		/* Also add public key entry for each secret key */
		auth_skey_to_pkey( skey, pkey );
		auth_add_key( pattern, pkey, sizeof(pkey), &g_public_keys );
	}
}

/*
* Parse a sanitized query (e.g. foo) and get the secret key if a match is found.
* Also compute the identifier.
*/
UCHAR *auth_handle_skey( UCHAR skey[], UCHAR id[], const char query[] ) {
	char pkeyhex[2*crypto_sign_PUBLICKEYBYTES+1];
	UCHAR pkey[crypto_sign_PUBLICKEYBYTES];

	if( auth_is_skey( query ) ) {
		/* The query to announce is a secret key */
		bytes_from_hex( skey, query, 2*crypto_sign_SECRETKEYBYTES );
		auth_skey_to_pkey( skey, pkey );
		bytes_to_hex( pkeyhex, pkey, crypto_sign_PUBLICKEYBYTES );

		id_compute( id, pkeyhex );
		return skey;
	} else if( auth_find_key( skey, query, g_secret_keys ) ) {
		/* There is a secret key registered for this query */
		auth_skey_to_pkey( skey, pkey );
		bytes_to_hex( pkeyhex, pkey, crypto_sign_PUBLICKEYBYTES );

		/* We use the public key as salt for the query */
		char *str = malloc( strlen( pkeyhex ) + strlen( query ) +1 );
		sprintf( str, "%s%s", pkeyhex, query );
		id_compute( id, str );
		free( str );

		return skey;
	} else {
		id_compute( id, query );
		return NULL;
	}
}

/*
* Parse a sanitized query and get the public key if a match is found.
* Also computes the identifier.
*/
UCHAR *auth_handle_pkey( UCHAR pkey[], UCHAR id[], const char query[] ) {
	char pkeyhex[2*crypto_sign_PUBLICKEYBYTES+1];

	if( auth_is_pkey( query ) ) {
		bytes_from_hex( pkey, query, 2*crypto_sign_PUBLICKEYBYTES );
		id_compute( id, query );
		return pkey;
	} else if( auth_find_key( pkey, query, g_public_keys ) ) {
		bytes_to_hex( pkeyhex, pkey, crypto_sign_PUBLICKEYBYTES );

		char *str = malloc( strlen( pkeyhex ) + strlen( query ) + 1 );
		sprintf( str, "%s%s", pkeyhex, query );
		id_compute( id, str );
		free( str );

		return pkey;
	} else {
		id_compute( id, query );
		return NULL;
	}
}

/* Send challenges */
void auth_send_challenges( int sock ) {
	UCHAR buf[4+SHA1_BIN_LENGTH+CHALLENGE_BIN_LENGTH];
	char addrbuf[FULL_ADDSTRLEN+1];
	struct results_t *results;
	struct result_t *result;
	time_t now;

	now = time_now_sec();

	/* Send out challenges every second */
	if( g_send_challenges < now ) {
		g_send_challenges = now;
	} else {
		return;
	}

	results = results_get();
	while( results ) {
		result = results->entries;
		while( result ) {
			if( result->challenge && result->challenges_send < MAX_AUTH_CHALLENGE_SEND ) {
				memcpy( buf, "AUTH", 4 );
				memcpy( buf+4, results->id, SHA1_BIN_LENGTH );
				memcpy( buf+4+SHA1_BIN_LENGTH, result->challenge, CHALLENGE_BIN_LENGTH );

				log_debug( "AUTH: Send challenge: %s", str_addr( &result->addr, addrbuf ) );
				sendto( sock, buf, sizeof(buf), 0, (struct sockaddr*) &result->addr, sizeof(IP) );

				result->challenges_send++;
			}
			result = result->next;
		}
		results = results->next;
	}
}

/* Receive a solved challenge and verify it */
void auth_verify_challenge( int sock, UCHAR buf[], size_t buflen, IP *addr, time_t now ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	UCHAR m[CHALLENGE_BIN_LENGTH+crypto_sign_BYTES];
	unsigned long long smlen;
	unsigned long long mlen;
	struct results_t *results;
	struct result_t *result;
	UCHAR *id;
	UCHAR *sm;

	if( buflen < (4+SHA1_BIN_LENGTH) ) {
		return;
	}

	id = buf+4;
	sm = buf+4+SHA1_BIN_LENGTH;
	smlen = buflen - (4+SHA1_BIN_LENGTH);

	results = results_find( id );
	if( results == NULL || results->pkey == NULL ) {
		log_debug( "AUTH: No results bucket or public key found." );
		return;
	}

	result = results->entries;
	while( result ) {
		if( addr_equal( addr, &result->addr ) ) {
			break;
		}
		result = result->next;
	}

	if( result == NULL ) {
		log_debug( "AUTH: Unknown source address for challenge response." );
		return;
	}

	if( result->challenge == NULL ) {
		log_debug( "AUTH: No challenge response expected from source address." );
		return;
	}

	if( crypto_sign_open( m, &mlen, sm, smlen, results->pkey ) != 0 ) {
		log_debug(  "AUTH: Challenge response does not verify: %s", str_addr( addr, addrbuf ) );
		return;
	}

	/* Check challenge */
	if( mlen != CHALLENGE_BIN_LENGTH || memcmp( m, result->challenge, CHALLENGE_BIN_LENGTH ) != 0 ) {
		log_debug(  "AUTH: Challenge response is invalid: %s", str_addr( addr, addrbuf ) );
		return;
	}

	log_debug( "AUTH: Challenge response is valid: %s", str_addr(addr, addrbuf ) );

	/* Mark result as verified (no challenge set) */
	free( result->challenge );
	result->challenge = NULL;
}

/* Receive a challenge and solve it using a secret key */
void auth_receive_challenge( int sock, UCHAR buf[], size_t buflen, IP *addr, time_t now ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	UCHAR outbuf[1500];
	UCHAR sm[CHALLENGE_BIN_LENGTH+crypto_sign_BYTES];
	UCHAR *m;
	unsigned long long smlen;
	unsigned long long mlen;
	struct value_t *value;
	UCHAR *id;

	/* Check if the challenge is too long */
	if( buflen != (4+SHA1_BIN_LENGTH+CHALLENGE_BIN_LENGTH) ) {
		return;
	}

	id = buf + 4;
	m = buf + 4 + SHA1_BIN_LENGTH;
	mlen = CHALLENGE_BIN_LENGTH;

	value = values_find( id );
	if( value == NULL || value->skey == NULL ) {
		log_debug( "AUTH: No value or secret key found for received challenge." );
		return;
	}

	/* Solve the challenge */
	if( crypto_sign( sm, &smlen, m, mlen, value->skey ) != 0 ) {
		return;
	}

	memcpy( outbuf, "AUTH", 4 );
	memcpy( outbuf+4, id, SHA1_BIN_LENGTH );
	memcpy( outbuf+4+SHA1_BIN_LENGTH, sm, smlen );

	log_debug( "AUTH: Received challenge from %s and send back response.", str_addr(addr, addrbuf ) );
	sendto( sock, outbuf, 4+SHA1_BIN_LENGTH+smlen, 0, (struct sockaddr*) addr, sizeof(IP) );
}

/*
* Handle authorization packets. This function is hooked
* up to the DHT socket and is called for every packet.
*/
int auth_handle_challenges( int sock, UCHAR buf[], size_t buflen, IP *from ) {
	time_t now;

	/* Detect authorization packets */
	if( buflen < 4 || memcmp( buf, "AUTH", 4 ) != 0 ) {
		/* The received packet is meant for the DHT */
		return 1;
	}

	g_request_counter++;
	now = time_now_sec();

	/* Reset counter every second */
	if( now > g_request_counter_started ) {
		g_request_counter_started = now;
		g_request_counter = 0;
	}

	/* Too many challenges */
	if( g_request_counter > MAX_AUTH_REQUESTS ) {
		return 0;
	}

	if( buflen == (4+SHA1_BIN_LENGTH+CHALLENGE_BIN_LENGTH) ) {
		/* Receive plaintext challenge / request */
		auth_receive_challenge( sock, buf, buflen, from, now );
	} else {
		/* Receive encrypted challenge / reply */
		auth_verify_challenge( sock, buf, buflen, from, now );
	}

	return 0;
}

void auth_setup( void ) {
	/* Nothing to do */
}

void auth_free( void ) {
	struct key_t *cur;
	struct key_t *next;

	cur = g_secret_keys;
	while( cur ) {
		next = cur->next;
		free_key( cur );
		cur = next;
	}
	g_secret_keys = NULL;

	cur = g_public_keys;
	while( cur ) {
		next = cur->next;
		free_key( cur );
		cur = next;
	}
	g_public_keys = NULL;
}
