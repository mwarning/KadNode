
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
#include "ext-bob.h"


/*
* This is an experimental/naive authentication scheme. Hence called Bob.
* Random byte strings (called challenges) are send to all peers.
* The peer is expected to encrypt the challenge with the private key.
* If the challenge can be decrypted by the public key we have,
* we know that the peer has the private key.
*
* Request: "AUTH" + PUBLICKEY + CHALLENGE
* Response: "AUTH" + PUBLICKEY + ENCRYPTED_CHALLENGE
*/

// Maximum retries per address to send the challenge
#define MAX_AUTH_CHALLENGE_SEND 3


struct key_t {
	struct key_t *next;
	uint8_t pkey[crypto_sign_PUBLICKEYBYTES];
	uint8_t skey[crypto_sign_SECRETKEYBYTES];
};

struct bob_resource {
	struct search_t *search;
	struct result_t *result;
	uint8_t pkey[crypto_sign_PUBLICKEYBYTES];
	uint8_t challenge[CHALLENGE_BIN_LENGTH];
	uint8_t challenges_send;
};

static int bob_test_socket = -1;
static struct key_t *g_keys = NULL;
static time_t g_send_challenges = 0;
static struct bob_resource g_bob_resources[8];


int bob_get_id( uint8_t id[], size_t len, const char query[] ) {
	size_t query_len;

	query_len = strlen( query );
	if( (query_len & 1) || !str_isHex( query, query_len ) ) {
		return 1;
	}

	memset( id, 0, len );
	bytes_from_hex( id, query, query_len );

	return 0;
}

static struct bob_resource *bob_find_resource( IP *addr, uint8_t pkey[] ) {
	struct bob_resource *resource;
	int i;

    for( i = 0; i < N_ELEMS(g_bob_resources); i++ ) {
    	resource = &g_bob_resources[i];
        if( resource->result
        	&& memcmp( pkey, &resource->pkey, crypto_sign_PUBLICKEYBYTES) == 0
        	&& addr_equal( addr, &resource->result->addr ) ) {
            return resource;
        }
    }

    return NULL;
}

// Find a resource instance that is currently not in use
static struct bob_resource *bob_next_resource( void ) {
    int i;

    for( i = 0; i < N_ELEMS(g_bob_resources); i++ ) {
        if( g_bob_resources[i].result == NULL ) {
            return &g_bob_resources[i];
        }
    }

    return NULL;
}

struct result_t *bob_next_result( struct search_t *search ) {
	struct result_t *result;

	result = search->results;
	while( result ) {
		if( result->state == AUTH_WAITING ) {
			return result;
		}
		result = result->next;
	}

	return NULL;
}

void bob_send_challenge( int sock, struct bob_resource *resource ) {
	uint8_t buf[4 + crypto_sign_PUBLICKEYBYTES + CHALLENGE_BIN_LENGTH];
	struct result_t *result = resource->result;

	memcpy( buf, "AUTH", 4 );
	memcpy( buf + 4, &resource->pkey, crypto_sign_PUBLICKEYBYTES );
	memcpy( buf + 4 + crypto_sign_PUBLICKEYBYTES, &resource->challenge, CHALLENGE_BIN_LENGTH );

	log_debug( "AUTH: Send challenge: %s (%d)", str_addr( &result->addr ), resource->challenges_send );
	sendto( sock, buf, sizeof(buf), 0, (struct sockaddr*) &result->addr, sizeof(IP) );

	resource->challenges_send++;
}

// Start auth procedure for result bucket and utilize all resources
void bob_trigger_auth( struct search_t *search ) {
	struct bob_resource *resource;
	struct result_t *result;

	result = search->results;
	while( result ) {
		resource = bob_next_resource();
		if( resource == NULL ) {
			break;
		}

		result = bob_next_result( search );
		if( result == NULL ) {
			break;
		}

		printf("create resource\n");
		result->state = AUTH_PROGRESS;
		bytes_from_hex( resource->pkey, search->query, 2 * crypto_sign_PUBLICKEYBYTES );
		resource->result = result;
		resource->search = search;
		resource->challenges_send = 0;
		bytes_random( resource->challenge, CHALLENGE_BIN_LENGTH );

		bob_send_challenge( bob_test_socket, resource );
	}
}

void bob_auth_end(struct bob_resource *resource, int state) {
	struct search_t *search;
	struct result_t *result;

	search = resource->search;
	result = resource->result;

	// Mark resource as free
	resource->search = NULL;
	resource->result = NULL;

	// Update authentication state
	result->state = state;

	if( state == AUTH_OK ) {
		search->callback = NULL;

		while( result ) {
			if( result->state == AUTH_PROGRESS ) {
				result->state = AUTH_SKIP;
			}
			result = result->next;
		}
	} else {
		// Look for next address
		bob_trigger_auth( search );
	}
}

int bob_is_pkey( const char str[] ) {
	size_t size;

	size = strlen( str );
	if( size != 2 * crypto_sign_PUBLICKEYBYTES ) {
		return 0;
	}

	return str_isHex( str, size );
}

int bob_is_skey( const char str[] ) {
	size_t size;

	size = strlen( str );
	if( size != 2 * crypto_sign_SECRETKEYBYTES ) {
		return 0;
	}

	return str_isHex( str, size );
}

int bob_decide_auth( const char *query ) {
	return bob_is_pkey( query );
}

/*
* Use secret key to create the corresponding public key.
*
* The public key is the second half of the secret key
* for the implementation used in libsodium.
*/
void bob_skey_to_pkey( const uint8_t skey[], uint8_t pkey[] ) {
	memcpy( pkey, skey + crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES, crypto_sign_PUBLICKEYBYTES );
}

// Generate a new key pair and print it to stdout.
int bob_generate_key_pair( void ) {
	uint8_t pkey[crypto_sign_PUBLICKEYBYTES];
	uint8_t skey[crypto_sign_SECRETKEYBYTES];
	char pkeyhex[2 * crypto_sign_PUBLICKEYBYTES + 1];
	char skeyhex[2 * crypto_sign_SECRETKEYBYTES + 1];

	if( crypto_sign_keypair( pkey, skey ) == 0) {
		fprintf( stdout, "public key: %s\n", bytes_to_hex( pkeyhex, pkey, sizeof(pkey) ) );
		fprintf( stdout, "secret key: %s\n", bytes_to_hex( skeyhex, skey, sizeof(skey) ) );
		return 0;
	} else {
		fprintf( stderr, "Failed to generate keys." );
		return 1;
	}
}

void bob_debug_keys( int fd ) {
	char pkeyhex[2 * crypto_sign_PUBLICKEYBYTES + 1];
	char skeyhex[2 * crypto_sign_SECRETKEYBYTES + 1];
	const struct key_t *key;
	uint8_t count;

	dprintf( fd, "All key pairs:\n" );

	count = 0;
	key = g_keys;
	while( key ) {
		bytes_to_hex( pkeyhex, key->pkey, crypto_sign_PUBLICKEYBYTES );
		bytes_to_hex( skeyhex, key->skey, crypto_sign_SECRETKEYBYTES );

		//dprintf( fd, "  pattern: '%s'\n", cur->pattern );
		dprintf( fd, "  secret key: %s\n", skeyhex );
		dprintf( fd, "  public key: %s\n\n", pkeyhex );

		count++;
		key = key->next;
	}

	dprintf( fd, " Found %d key pairs.\n", count );
}

// Add secret key
void bob_add_skey( const char arg[] ) {
	uint8_t skey[crypto_sign_SECRETKEYBYTES];
	uint8_t pkey[crypto_sign_PUBLICKEYBYTES];

	if( !bob_is_skey( arg ) ) {
		log_err( "BOB: Invalid secret key: %s", arg );
		exit( 1 );
	}

	bytes_from_hex( skey, arg, 2 * crypto_sign_SECRETKEYBYTES );

	// Extract public key
	bob_skey_to_pkey( skey, pkey );

	struct key_t *key = (struct key_t*) calloc( 1, sizeof(struct key_t) );
	memcpy( key->pkey, pkey, crypto_sign_PUBLICKEYBYTES );
	memcpy( key->skey, skey, crypto_sign_SECRETKEYBYTES );

	// Prepend to list
	if( g_keys ) {
		key->next = g_keys;
	}

	g_keys = key;
}

uint8_t *find_skey( uint8_t pkey[] ) {
	struct key_t *key;

	key = g_keys;
	while( key ) {
		if( memcmp( key->pkey, pkey, crypto_sign_PUBLICKEYBYTES ) == 0 ) {
			return &key->skey[0];
		}
		key = key->next;	
	}
	return NULL;
}

// Send challenges
void bob_send_challenges( int sock ) {
	struct bob_resource *resource;
	int i;

	// Send one packet per request
	for( i = 0; i < N_ELEMS(g_bob_resources); i++ ) {
		resource = &g_bob_resources[i];
		if( resource->search == NULL ) {
			continue;
		}

		if( resource->challenges_send < MAX_AUTH_CHALLENGE_SEND && resource->result->state == AUTH_PROGRESS ) {
			bob_send_challenge( sock, resource );
		} else {
			bob_auth_end( resource, AUTH_ERROR );
		}
	}
}

// Receive a solved challenge and verify it
void bob_verify_challenge( int sock, uint8_t buf[], size_t buflen, IP *addr ) {
	uint8_t m[CHALLENGE_BIN_LENGTH + crypto_sign_BYTES];
	long long unsigned smlen;
	long long unsigned mlen;
	struct bob_resource *resource;
	uint8_t *pkey;
	uint8_t *sm;

	if( buflen < (4 + crypto_sign_PUBLICKEYBYTES + CHALLENGE_BIN_LENGTH) ) {
		// Data length too small
		return;
	}

	pkey = buf + 4;
	sm = buf + 4 + crypto_sign_PUBLICKEYBYTES;
	smlen = buflen - (4 + crypto_sign_PUBLICKEYBYTES);

	resource = bob_find_resource( addr, pkey );
	if( resource == NULL ) {
		log_debug( "AUTH: Unknown source address for challenge response: %s", str_addr( addr ) );
		return;
	}

	if( crypto_sign_open( m, &mlen, sm, smlen, (const unsigned char *) &resource->pkey ) != 0 ) {
		log_debug(  "AUTH: Challenge response does not verify: %s", str_addr( addr ) );
		bob_auth_end( resource, AUTH_FAILED );
	} else if( mlen != CHALLENGE_BIN_LENGTH || memcmp( m, &resource->challenge, CHALLENGE_BIN_LENGTH ) != 0 ) {
		log_debug(  "AUTH: Challenge response is invalid: %s", str_addr( addr ) );
		bob_auth_end( resource, AUTH_FAILED );
	} else {
		log_debug( "AUTH: Challenge response is valid: %s", str_addr( addr ) );
		bob_auth_end( resource, AUTH_OK );
	}
}

// Receive a challenge and solve it using a secret key
void bob_encrypt_challenge( int sock, uint8_t buf[], size_t buflen, IP *addr ) {
	uint8_t outbuf[512];
	uint8_t sm[CHALLENGE_BIN_LENGTH + crypto_sign_BYTES];
	uint8_t *m;
	long long unsigned smlen;
	long long unsigned mlen;
	uint8_t *pkey;
	uint8_t *skey;

	// Check if the challenge is too long
	if( buflen != (4 + crypto_sign_PUBLICKEYBYTES + CHALLENGE_BIN_LENGTH) ) {
		return;
	}

	pkey = buf + 4;
	m = buf + 4 + crypto_sign_PUBLICKEYBYTES;
	mlen = CHALLENGE_BIN_LENGTH;

	// Find secret key by public key
	skey = find_skey( pkey );
	if( skey == NULL ) {
		log_debug( "AUTH: No secret key found for received challenge." );
		return;
	}

	// Decrypt the challenge 
	if( crypto_sign( sm, &smlen, m, mlen, skey ) != 0 ) {
		return;
	}

	memcpy( outbuf, "AUTH", 4 );
	memcpy( outbuf + 4, pkey, crypto_sign_PUBLICKEYBYTES );
	memcpy( outbuf + 4 + crypto_sign_PUBLICKEYBYTES, sm, smlen );

	log_debug( "AUTH: Received challenge from %s and send back response.", str_addr( addr ) );
	sendto( sock, outbuf, 4 + crypto_sign_PUBLICKEYBYTES + smlen, 0, (struct sockaddr*) addr, sizeof(IP) );
}

int bob_handler( int fd, uint8_t buf[], uint32_t buflen, IP *from ) {
	time_t now;

	if( buflen > 0 ) {
		if( buflen < 4 || memcmp( buf, "AUTH", 4 ) != 0 ) {
			// The received packet is meant for the DHT...
		} else if( buflen == (4 + crypto_sign_PUBLICKEYBYTES + CHALLENGE_BIN_LENGTH) ) {
			// Answer a challenge request
			bob_encrypt_challenge( fd, buf, buflen, from );
		} else {
			// Handle reply to a challenge request
			bob_verify_challenge( fd, buf, buflen, from );
		}
	}

	now = time_now_sec();

	// Send out new challenges every second
	if( g_send_challenges != now ) {
		g_send_challenges = now;
		bob_send_challenges( fd );
	}

	return 1;
}

void bob_setup( void ) {
	// Nothing to do
}

void bob_free( void ) {
	struct key_t *key;
	struct key_t *next;

	key = g_keys;
	while( key ) {
		next = key->next;
		memset( key, 0, sizeof(struct key_t) );
		free( key );
		key = next;
	}
	g_keys = NULL;
}
