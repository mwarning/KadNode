
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

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


static time_t g_send_challenges = 0;
static size_t g_request_counter = 0;
static time_t g_request_counter_started = 0;


char *auth_str_skey( char *buf, const UCHAR skey[] ) {
	if( skey ) {
		return bytes_to_hex( buf, skey, crypto_sign_SECRETKEYBYTES );
	}
	return NULL;
}

char *auth_str_pkey( char *buf, const UCHAR pkey[] ) {
	if( pkey ) {
		return bytes_to_hex( buf, pkey, crypto_sign_PUBLICKEYBYTES );
	}
	return NULL;
}

char *auth_str_challenge( char *buf, const UCHAR challenge[] ) {
	if( challenge ) {
		return bytes_to_hex( buf, challenge, CHALLENGE_BIN_LENGTH );
	}
	return NULL;
}

int auth_is_pkey( const char query[] ) {
	size_t size;
	char *end;

	/* Find the first dot */
	end = strchr( query, '.' );
	if( end == NULL ) {
		size = strlen( query );
	} else {
		size = end - query;
	}

	if( size != 2*crypto_sign_PUBLICKEYBYTES ) {
		return 0;
	}

	return str_isHex( query, size );
}

int auth_is_skey( const char query[] ) {
	size_t size;
	char *end;

	/* Find the first dot */
	end = strchr( query, '.' );
	if( end == NULL ) {
		size = strlen( query );
	} else {
		size = end - query;
	}

	if( size != 2*crypto_sign_SECRETKEYBYTES ) {
		return 0;
	}

	return str_isHex( query, size );
}

UCHAR *auth_create_pkey( const char query[] ) {
	UCHAR *skey;

	if( !auth_is_pkey( query ) ) {
		return NULL;
	}

	skey = malloc( crypto_sign_PUBLICKEYBYTES );
	bytes_from_hex( skey, query, 2*crypto_sign_PUBLICKEYBYTES );

	log_debug( "AUTH: Add new public key from %s", query );
	return skey;
}

UCHAR *auth_create_skey( const char query[] ) {
	UCHAR *skey;

	if( !auth_is_skey( query ) ) {
		return NULL;
	}

	skey = malloc( crypto_sign_SECRETKEYBYTES );
	bytes_from_hex( skey, query, 2*crypto_sign_SECRETKEYBYTES );

	log_debug( "AUTH: Add new secret key from %s", query );
	return skey;
}

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

/* Send challenges */
void auth_send_challenges( int sock ) {
	UCHAR buf[4+SHA1_BIN_LENGTH+CHALLENGE_BIN_LENGTH];
	char addrbuf[FULL_ADDSTRLEN+1];
	struct results_t *results;
	struct result_t *result;

	results = results_get();
	while( results ) {
		result = results->entries;
		while( result ) {
			if( result->challenge && result->challenges_send < MAX_AUTH_CHALLENGE_SEND ) {
				memcpy( buf, "AUTH", 4 );
				memcpy( buf+4, results->id, SHA1_BIN_LENGTH );
				memcpy( buf+4+SHA1_BIN_LENGTH, result->challenge, CHALLENGE_BIN_LENGTH );
	
				log_debug( "AUTH: Send challenge to %s", str_addr( &result->addr, addrbuf ) );
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
		log_debug( "AUTH: No result entry found." );
		return;
	}

	if( result->challenge == NULL ) {
		log_debug( "AUTH: Challenge was not set or already solved." );
		return;
	}

	if( crypto_sign_open( m, &mlen, sm, smlen, results->pkey ) != 0 ) {
		log_debug(  "AUTH: Signature does not verify for %s", str_addr( addr, addrbuf ) );
		return;
	}

	/* Check challenge */
	if( mlen != CHALLENGE_BIN_LENGTH || memcmp( m, result->challenge, CHALLENGE_BIN_LENGTH ) != 0 ) {
		log_debug(  "AUTH: Challenge does not match for %s", str_addr( addr, addrbuf ) );
		return;
	}

	log_debug( "AUTH: Verified encrypted challenge send back by %s", str_addr(addr, addrbuf ) );

	/* Mark result as verified (no challenge set) */
	free( result->challenge );
	result->challenge = NULL;
}

/* Receive a challenge and solve it using a secret key */
void auth_receive_challenge( int sock, UCHAR buf[], size_t buflen, IP *addr, time_t now ) {
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
		log_debug( "AUTH: No value or secret key found." );
		return;
	}

	/* Solve the challenge */
	if( crypto_sign( sm, &smlen, m, mlen, value->skey ) != 0 ) {
		return;
	}

	memcpy( outbuf, "AUTH", 4 );
	memcpy( outbuf+4, id, SHA1_BIN_LENGTH );
	memcpy( outbuf+4+SHA1_BIN_LENGTH, sm, smlen );

	sendto( sock, outbuf, 4+SHA1_BIN_LENGTH+smlen, 0, (struct sockaddr*) addr, sizeof(IP) );
}

int auth_handle_packet( int sock, UCHAR buf[], size_t buflen, IP *from ) {
	time_t now;

	now = time_now_sec();

	/* Send out challenges every second */
	if( g_send_challenges < now ) {
		auth_send_challenges( sock );

		g_send_challenges = now;
	}

	if( buflen < 4 || memcmp( buf, "AUTH", 4 ) != 0 ) {
		/* The received packet was not meant for this extension */
		return 1;
	}

	g_request_counter++;

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
		/* Receive plaintext challenge */
		auth_receive_challenge( sock, buf, buflen, from, now );
	} else {
		/* Receive encrypted challenge */
		auth_verify_challenge( sock, buf, buflen, from, now );
	}

	return 0;
}

void auth_setup( void ) {
	/* Nothing to do */
}
