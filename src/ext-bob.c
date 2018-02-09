
#define _WITH_DPRINTF
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "announces.h"
#include "searches.h"
#include "ext-bob.h"


/*
* This is an experimental/naive authentication scheme. Hence called Bob.
* Random byte strings (called challenges) are send to all peers.
* The peer is expected to encrypt the challenge with the private key.
* If the challenge can be decrypted by the public key we have,
* we know that the peer has the private key. The ip address will then
* be used as result.
*
* Paket exchange:
* Lookup <public-key>.p2p
* 1. get IP addresses from DHT
* 2. send to every address "BOB" + PUBLICKEY + CHALLENGE
*    - remember IP address and challenge
* 3. get response "BOB" + SIGNED_CHALLENGE
*    - find challenge by sender IP address
* 4. verify signature by public key
*/

#define ECPARAMS MBEDTLS_ECP_DP_SECP256R1
#define ECPARAMS_NAME "secp256r1"
#define ECPARAMS_SIZE 32
#define MAX_AUTH_CHALLENGE_SEND 3
#define CHALLENGE_BIN_LENGTH 32


struct key_t {
	struct key_t *next;
	char *path; // File path the key was loaded from
	mbedtls_pk_context ctx_sign;
};

struct bob_resource {
	mbedtls_pk_context ctx_verify;
	uint8_t challenge[32];
	uint8_t challenges_send;
	char query[QUERY_MAX_SIZE];
	IP addr;
};

static int g_dht_socket = -1;
static struct key_t *g_keys = NULL;
static time_t g_send_challenges = 0;
static struct bob_resource g_bob_resources[8];

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;


// Decompress key since mbedtls does not have this feature.
int mbedtls_ecp_decompress(
	const mbedtls_ecp_group *grp,
	const unsigned char *input, size_t ilen,
	unsigned char *output, size_t *olen, size_t osize
) {
	int ret;
	size_t plen;
	mbedtls_mpi r;
	mbedtls_mpi x;
	mbedtls_mpi n;

	plen = mbedtls_mpi_size( &grp->P );

	*olen = 2 * plen + 1;

	if( osize < *olen )
		return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

	if( ilen != plen + 1 )
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

	if( input[0] != 0x02 && input[0] != 0x03 )
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

	// output will consist of 0x04|X|Y
	memcpy( output, input, ilen );
	output[0] = 0x04;

	mbedtls_mpi_init( &r );
	mbedtls_mpi_init( &x );
	mbedtls_mpi_init( &n );

	// x <= input
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &x, input + 1, plen ) );

	// r = x^2
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &r, &x, &x ) );

	// r = x^2 + a
	if( grp->A.p == NULL ) {
		// Special case where a is -3
		MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &r, &r, 3 ) );
	} else {
		MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &r, &r, &grp->A ) );
	}

	// r = x^3 + ax
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &r, &r, &x ) );

	// r = x^3 + ax + b
	MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &r, &r, &grp->B ) );

	// Calculate quare root of r over finite field P
	// r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)

	// n = P + 1
	MBEDTLS_MPI_CHK( mbedtls_mpi_add_int( &n, &grp->P, 1 ) );

	// n = (P + 1) / 4
	MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &n, 2 ) );

	// r ^ ((P + 1) / 4) (mod p)
	MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &r, &r, &n, &grp->P, NULL ) );

	// Select solution that has the correct "sign" (equals odd/even solution in finite group)
	if( (input[0] == 0x03) != mbedtls_mpi_get_bit( &r, 0 ) ) {
		// r = p - r
		MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &r, &grp->P, &r ) );
	}

	// y => output
	ret = mbedtls_mpi_write_binary( &r, output + 1 + plen, plen );

cleanup:
	mbedtls_mpi_free( &r );
	mbedtls_mpi_free( &x );
	mbedtls_mpi_free( &n );

	return( ret );
}

void bob_auth_end(struct bob_resource *resource, int state) {

	// Set state of result
	searches_set_auth_state( &resource->query[0], &resource->addr, state );

	// Mark resource as free
	resource->query[0] = '\0';

	// Look for next job
	bob_trigger_auth();
}

// Try to create a DHT id from a sanitzed key query
int bob_get_id( uint8_t id[], size_t idlen, const char query[] ) {
	size_t querylen = strlen(query);
	uint8_t bin[32];

	if(0 == bytes_from_base32hex(bin, sizeof(bin), query, querylen)
		|| 0 == bytes_from_base16hex(bin, sizeof(bin), query, querylen)) {
			memcpy(id, bin, idlen);
			return 1;
	}
	return 0;
}

// Find a resource instance that is currently not in use
static struct bob_resource *bob_next_resource( void ) {
	int i;

	for( i = 0; i < ARRAY_SIZE(g_bob_resources); i++ ) {
		if( g_bob_resources[i].query[0] == '\0' ) {
			return &g_bob_resources[i];
		}
	}

	return NULL;
}

static void bob_send_challenge( int sock, struct bob_resource *resource ) {
	uint8_t buf[3 + ECPARAMS_SIZE + CHALLENGE_BIN_LENGTH];
#ifdef DEBUG
	char hexbuf[108 + 1];
#endif

	// Insert marker
	memcpy( buf, "BOB", 3);

	// Append X value of public key
	mbedtls_mpi_write_binary( &mbedtls_pk_ec( resource->ctx_verify )->Q.X, buf + 3, ECPARAMS_SIZE );

	// Append challenge bytes
	memcpy( buf + 3 + ECPARAMS_SIZE, resource->challenge, CHALLENGE_BIN_LENGTH );

	resource->challenges_send += 1;
	log_debug( "Send challenge to %s: %s (try %d)",
		str_addr( &resource->addr ),
		bytes_to_base32hex(hexbuf, sizeof(hexbuf), buf, sizeof(buf)),
		resource->challenges_send
	);

	sendto( sock, buf, sizeof(buf), 0, (struct sockaddr*) &resource->addr, sizeof(IP) );
}

// Start auth procedure for result bucket and utilize all resources
void bob_trigger_auth( void ) {
	uint8_t compressed[33]; // 0x02|X
	uint8_t decompressed[65]; // 0x04|X|Y
	size_t olen;
	struct bob_resource *resource;
	struct result_t *result;
	int ret;

	resource = bob_next_resource();
	if( resource == NULL ) {
		return;
	}

	// Shortcuts
	mbedtls_ecp_keypair *kp = mbedtls_pk_ec( resource->ctx_verify );
	char *query = &resource->query[0];

	// Find new query to authenticate and initialize resource
	if( (result = searches_get_auth_target( query, &resource->addr, &bob_trigger_auth )) != NULL ) {
		result->state = AUTH_PROGRESS;

		// Hex to binary and compressed form (assuming even Y => 0x02)
		compressed[0] = 0x02;

		if (0 != bytes_from_base32hex(compressed + 1, sizeof(compressed) - 1, query, strlen(query))) {
			log_error( "BOB: Unexpected query length: %s", query );
			bob_auth_end( resource, AUTH_ERROR );
			return;
		}

		// Compressed form to decompressed
		if( (ret = mbedtls_ecp_decompress(
				&kp->grp, compressed, sizeof(compressed),
				decompressed, &olen, sizeof(decompressed) )) != 0 ) {
			log_error( "Error in mbedtls_ecp_decompress: %d\n", ret );
			bob_auth_end( resource, AUTH_ERROR );
			return;
		}

		// Decompressed form to Q
		if( (ret = mbedtls_ecp_point_read_binary(
				&kp->grp, &kp->Q,
				decompressed, sizeof(decompressed) )) != 0 ) {
			log_error( "Error in mbedtls_ecp_point_read_binary: %d\n", ret );
			bob_auth_end( resource, AUTH_ERROR );
			return;
		}

		resource->challenges_send = 0;
		bytes_random( resource->challenge, CHALLENGE_BIN_LENGTH );
		bob_send_challenge( g_dht_socket, resource );
	}
}

static int write_pem( const mbedtls_pk_context *key, const char path[] ) {
	FILE *file;
	uint8_t buf[1000];
	size_t len;
	int ret;

	memset( buf, 0, sizeof(buf) );

	if( ( ret = mbedtls_pk_write_key_pem( (mbedtls_pk_context *) key, buf, sizeof(buf) ) ) != 0 ) {
		return ret;
	}

	if( (file = fopen( path, "r" )) != NULL ) {
		fclose( file );
		log_error( "File exists: %s", path );
		return -1;
	}

	if( (file = fopen( path, "wb" )) == NULL ) {
		log_error( "%s %s", path,  strerror( errno ) );
		return -1;
	}

	len = strlen( (char*) buf );
	if( fwrite( buf, 1, len, file ) != len ) {
		fclose( file );
		log_error( "%s: %s", path, strerror( errno ) );
		return -1;
	}

	fclose( file );

	return 0;
}

static const char *get_pkey_base32hex( const mbedtls_pk_context *ctx ) {
	static char hexbuf[52 + 1];
	uint8_t buf[ECPARAMS_SIZE];

	mbedtls_mpi_write_binary( &mbedtls_pk_ec( *ctx )->Q.X, buf, sizeof(buf) );

	return bytes_to_base32hex(hexbuf, sizeof(hexbuf), buf, sizeof(buf));
}

// Generate a new key pair, write the secret key
// to path and print public key to stdout.
int bob_create_key( const char path[] ) {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_pk_context ctx;
	const char *pers = MAIN_SRVNAME;
	int ret;

	mbedtls_pk_init( &ctx );
	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_entropy_init( &entropy );

	//TODO: see gen_key.c example for better seed method
	if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
			(const unsigned char *) pers, strlen( pers ) ) ) != 0 ) {
		printf( "mbedtls_ctr_drbg_seed returned %d\n", ret );
		return -1;
	}

	printf( "Generating %s key pair...\n", ECPARAMS_NAME );

	if( ( ret = mbedtls_pk_setup( &ctx, mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) ) ) != 0 ) {
		printf( "mbedtls_pk_setup returned -0x%04x\n", -ret );
		return -1;
	}

	// Generate key where Y is even (called positive in a prime group)
	// This spares us from transmitting the sign along with the public key
	do {
		if( (ret = mbedtls_ecp_gen_key( ECPARAMS, mbedtls_pk_ec( ctx ),
			mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ) {
			printf( "mbedtls_ecp_gen_key returned -0x%04x\n", -ret );
			return -1;
		}
	} while( mbedtls_mpi_get_bit( &mbedtls_pk_ec( ctx )->Q.Y, 0 ) != 0 );

	if( write_pem( &ctx, path ) != 0 ) {
		return -1;
	}

	printf( "Public key: %s.p2p\n", get_pkey_base32hex( &ctx ) );
	printf( "Wrote secret key to %s\n", path );

	return 0;
}

// Add secret key
int bob_load_key( const char path[] ) {
	mbedtls_pk_context ctx;
	char msg[300];
	int ret;

	mbedtls_pk_init( &ctx );

	if( (ret = mbedtls_pk_parse_keyfile( &ctx, path, NULL )) != 0) {
		mbedtls_pk_free( &ctx );
		mbedtls_strerror( ret, msg, sizeof(msg) );
		log_error( "Error loading %s: %s", path, msg );
		return -1;
	}

	if( mbedtls_pk_ec( ctx )->grp.id != ECPARAMS ) {
		log_error( "Unsupported key type for %s: %s (expected %s)", path,
			mbedtls_ecp_curve_info_from_grp_id( mbedtls_pk_ec( ctx )->grp.id )->name,
			ECPARAMS_NAME
		);
		return -1;
	}

	struct key_t *entry = (struct key_t*) calloc( 1, sizeof(struct key_t) );
	memcpy( &entry->ctx_sign, &ctx, sizeof(ctx) );
	entry->path = strdup( path );

	// Prepend to list
	if( g_keys ) {
		entry->next = g_keys;
	}
	g_keys = entry;

	log_info( "Loaded %s (Public key: %s)", path, get_pkey_base32hex( &ctx ) );

	return 0;
}

// Send challenges
void bob_send_challenges( int sock ) {
	struct bob_resource *resource;
	int i;

	// Send one packet per request
	for( i = 0; i < ARRAY_SIZE(g_bob_resources); ++i ) {
		resource = &g_bob_resources[i];
		if( resource->query[0] == '\0' ) {
			continue;
		}

		if( resource->challenges_send < MAX_AUTH_CHALLENGE_SEND ) {
			bob_send_challenge( sock, resource );
		} else {
			bob_auth_end( resource, AUTH_ERROR );
		}
	}
}

struct bob_resource *bob_find_resource( const IP *addr ) {
	int i;

	for( i = 0; i < ARRAY_SIZE(g_bob_resources); ++i) {
		if( addr_equal( &g_bob_resources[i].addr, addr ) ) {
			return &g_bob_resources[i];
		}
	}

	return NULL;
}

// Receive a solved challenge and verify it
void bob_verify_challenge( int sock, uint8_t buf[], size_t buflen, IP *addr ) {
	struct bob_resource *resource;
	int ret;

	resource = bob_find_resource( addr );

	if( resource ) {
		ret = mbedtls_ecdsa_read_signature( mbedtls_pk_ec(resource->ctx_verify),
			resource->challenge, CHALLENGE_BIN_LENGTH, buf + 3, buflen - 3 );

		bob_auth_end( resource, ret ? AUTH_FAILED : AUTH_OK );
	} else {
		log_warning( "BOB: No session found for address %s", str_addr( addr ) );
	}
}

struct key_t *bob_find_key( const uint8_t pkey[] ) {
	uint8_t epkey[ECPARAMS_SIZE];
	struct key_t *key = g_keys;

	while( key ) {
		mbedtls_mpi_write_binary( &mbedtls_pk_ec( key->ctx_sign )->Q.X, epkey, ECPARAMS_SIZE );
		if( memcmp( epkey, pkey, ECPARAMS_SIZE ) == 0 ) {
			return key;
		}
		key = key->next;
	}

	return key;
}

// Receive a challenge and solve it using a secret key
void bob_encrypt_challenge( int sock, uint8_t buf[], size_t buflen, IP *addr ) {
	struct key_t *key;
	uint8_t sig[200];
#ifdef DEBUG
	char hexbuf[52 + 1];
#endif
	size_t slen;
	int ret;

	uint8_t *pkey = buf + 3;
	uint8_t *challenge = buf + 3 + ECPARAMS_SIZE;

	key = bob_find_key( pkey );
	if( key ) {
		memcpy( sig, "BOB", 3 );
		ret = mbedtls_ecdsa_write_signature(
			mbedtls_pk_ec( key->ctx_sign ), MBEDTLS_MD_SHA256,
			challenge, CHALLENGE_BIN_LENGTH,
			sig + 3, &slen, mbedtls_ctr_drbg_random, &g_ctr_drbg );
		slen += 3;

		if( ret != 0) {
			log_warning( "mbedtls_ecdsa_write_signature returned %d\n", ret );
		} else {
			log_debug( "Received challenge from %s and send back response", str_addr( addr ) );
			sendto( sock, sig, slen, 0, (struct sockaddr*) addr, sizeof(IP) );
		}
	} else {
		log_debug( "BOB: Secret key not found for public key: %s",
			bytes_to_base32hex ( hexbuf, sizeof(hexbuf), pkey, ECPARAMS_SIZE)
		);
	}
}

int bob_handler( int fd, uint8_t buf[], uint32_t buflen, IP *from ) {
	time_t now;

	// Hack to get the DHT socket..
	if( g_dht_socket == -1 ) {
		g_dht_socket = fd;
	}

	if( buflen > 3 && memcmp( buf, "BOB", 3 ) == 0 ) {
		if( buflen == (3 + ECPARAMS_SIZE + CHALLENGE_BIN_LENGTH) ) {
			// Answer a challenge request
			bob_encrypt_challenge( fd, buf, buflen, from );
		} else {
			// Handle reply to a challenge request
			bob_verify_challenge( fd, buf, buflen, from );
		}
		return 0;
	}

	now = time_add_secs( 0 );

	// Send out new challenges every second
	if( g_send_challenges < now ) {
		g_send_challenges = now + 1;
		bob_send_challenges( fd );
	}

	return 1;
}

void bob_debug_keys(FILE *fp) {
	struct key_t *key;

	if (g_keys == NULL) {
		fprintf(fp, "No keys found.\n");
		return;
	}

	key = g_keys;
	while (key) {
		fprintf(fp, "Public key: %s (%s)\n", get_pkey_base32hex(&key->ctx_sign), key->path);
		key = key->next;
	}
}

void bob_setup( void ) {
	struct bob_resource *resource;
	struct key_t *key;
	const char *hkey;
	int i;

	mbedtls_ctr_drbg_init( &g_ctr_drbg );
	mbedtls_entropy_init( &g_entropy );

	// Initialize resources handlers ctx_verify value
	for( i = 0; i < ARRAY_SIZE(g_bob_resources); ++i ) {
		resource = &g_bob_resources[i];
		mbedtls_pk_setup( &resource->ctx_verify, mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) );
		mbedtls_ecp_group_load( &mbedtls_pk_ec( resource->ctx_verify )->grp, ECPARAMS );
	}

	// Anounce keys via DHT
	key = g_keys;
	while( key ) {
		// Start announcing public key for the entire runtime
		hkey = get_pkey_base32hex( &key->ctx_sign );
		announces_add( hkey, gconf->dht_port, LONG_MAX );
		key = key->next;
	}
}

void bob_free( void ) {
	struct key_t *key;
	struct key_t *next;

	mbedtls_ctr_drbg_free( &g_ctr_drbg );
	mbedtls_entropy_free( &g_entropy );

	key = g_keys;
	while( key ) {
		next = key->next;
		// Also zeroes the private key in memory
		mbedtls_pk_free( &key->ctx_sign );
		free( key->path );
		free( key );
		key = next;
	}
	g_keys = NULL;
}
