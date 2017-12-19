
#define _WITH_DPRINTF
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>

#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/sha256.h"

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "searches.h"
#include "ext-tls-client.h"


// SSL structures for parallel connection handling.
struct tls_resource {
	mbedtls_ssl_context ssl;
	mbedtls_net_context fd;
	char query[QUERY_MAX_SIZE];
	IP addr;
};

// Global TLS resources
static mbedtls_x509_crt g_cacert;
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_ssl_config g_conf;
static int g_client_enable = 0;

// Allow two parallel authentications at once
static struct tls_resource g_tls_resources[2];


// Start TLS connection
static int tls_connect_init( mbedtls_ssl_context *ssl, mbedtls_net_context *fd, const char query[], const IP *addr ) {
	int ret;

	mbedtls_ssl_set_bio( ssl, fd, mbedtls_net_send, mbedtls_net_recv, NULL );

	if( ( ret = mbedtls_ssl_set_hostname( ssl, query ) ) != 0 )
	{
		log_err( "TLS-Client: mbedtls_ssl_set_hostname returned -0x%x", -ret );
		return -1;
	}

	fd->fd = socket( addr->ss_family, SOCK_STREAM, IPPROTO_TCP );
	if( fd->fd < 0 )
	{
		log_err( "TLS-Client: Socket creation failed: %s", strerror( errno ) );
		return -1;
	}

	ret = mbedtls_net_set_nonblock( fd );
	if( ret < 0) {
		log_err( "TLS-Client: Failed to set socket non-blocking: %s", strerror( errno ) );
		return -1;
	}

	// Start connection
	ret = connect( fd->fd, (const struct sockaddr *) addr, sizeof(IP) );
	if( ret < 0 && errno != EINPROGRESS ) {
		mbedtls_net_free( fd );
		mbedtls_net_init( fd );
		log_err( "TLS-Client: Connect failed: %s", strerror( errno ) );
		return -1;
	}

	return 0;
}

// Find resource used by socket
static struct tls_resource *tls_find_resource( int fd ) {
	int i;

	for( i = 0; i < N_ELEMS(g_tls_resources); ++i ) {
		if( g_tls_resources[i].fd.fd == fd ) {
			return &g_tls_resources[i];
		}
	}

	return NULL;
}


// Forward declaration
static void tls_handle( int rc, int fd );

static void auth_end( struct tls_resource* resource, int state ) {
	int ret;

	// Done and close connection
	do ret = mbedtls_ssl_close_notify( &resource->ssl );
	while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );

	net_remove_handler( resource->fd.fd, &tls_handle );

	mbedtls_net_free( &resource->fd );
	mbedtls_ssl_session_reset( &resource->ssl );

	// Mark resource as free
	mbedtls_net_init( &resource->fd );

	// Set state of result
	searches_set_auth_state( &resource->query[0], &resource->addr, state );

	// Look for next job
	tls_client_trigger_auth();
}

static void tls_handle( int rc, int fd ) {
	struct tls_resource* resource;
	mbedtls_ssl_context* ssl;
	const char *query;
	uint32_t flags;
	int ret;

	resource = tls_find_resource( fd );
	if( resource == NULL ) {
		// Should not happen..
		close( fd );
		net_remove_handler( fd, &tls_handle);
		return;
	}

	ssl = &resource->ssl;
	query = &resource->query[0];

	if( rc < 0 ) {
		if( errno != EINPROGRESS ) {
			// Failed to create TCP/IP connection.
			log_warn( "TLS-Client: Socket error for '%s': %s", query, strerror( errno ) );
			auth_end( resource, AUTH_ERROR );
		} else {
			// Still connecting.
		}
		return;
	}

	do ret = mbedtls_ssl_handshake( ssl );
	while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );

	if( ret == MBEDTLS_ERR_SSL_WANT_READ ) {
		// TLS handshake in progress
		return;
	}

	if( ret ) {
		// TLS handshake failure.
#ifdef DEBUG
		log_debug( "TLS-Client: mbedtls_ssl_handshake returned -0x%x: %s", -ret, query );
		if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ) {
			log_debug( "TLS-Client: Unable to verify the servers certificate: %s", query );
		}
#endif

		auth_end( resource, AUTH_FAILED );
	} else {
		// TLS handshake done
		log_debug( "TLS-Client: Protocol [%s], Ciphersuite [%s] and fragment length %u: %s",
			mbedtls_ssl_get_version( ssl ), mbedtls_ssl_get_ciphersuite( ssl ),
			(unsigned int) mbedtls_ssl_get_max_frag_len( ssl ), query
		);

		// Verify peer X.509 certificate
		flags = mbedtls_ssl_get_verify_result( ssl );

#ifdef DEBUG
		char buf[MBEDTLS_SSL_MAX_CONTENT_LEN];

		if( flags != 0 ) {
			mbedtls_x509_crt_verify_info( buf, sizeof( buf ), "", flags );
			log_debug( "TLS-Client: Peer verification failed: %s", buf);
		}

		if( mbedtls_ssl_get_peer_cert( ssl ) != NULL ) {
			mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "", mbedtls_ssl_get_peer_cert( ssl ) );
			log_debug( "TLS-Client: Peer certificate information: %s", buf);
		}
#endif
		auth_end( resource, flags == 0 ? AUTH_OK : AUTH_FAILED );
	}
}

// Try to create a DHT id from sanitized domain query
int tls_client_get_id( uint8_t id[], size_t len, const char query[] ) {
	uint8_t hash[32];

	// Match dot in query, e.g. 'example.com'
	if( strchr( query, '.' ) ) {
		mbedtls_sha256_context ctx;
		mbedtls_sha256_init( &ctx );
		mbedtls_sha256_update( &ctx, (uint8_t*) &query[0], strlen( query ) );
		mbedtls_sha256_finish( &ctx, hash );

		memset( id, 0, len );
		memcpy( id, hash, MIN( len, sizeof(hash) ) );

		return 1;
	}

	return 0;
}

// Find a resource instance that is currently not in use
static struct tls_resource *tls_next_resource( void ) {
	int i;

	for( i = 0; i < N_ELEMS(g_tls_resources); ++i ) {
		if( g_tls_resources[i].fd.fd < 0 ) {
			return &g_tls_resources[i];
		}
	}

	return NULL;
}

// Called for every result that need to be authenticated
void tls_client_trigger_auth( void ) {
	struct tls_resource *resource;
	struct result_t *result;

	// Reject query if TLS client disabled
	if( g_client_enable == 0 ) {
		return;
	}

	// Get next free SSL resource
	resource = tls_next_resource();
	if( resource == NULL ) {
		return;
	}

	if( (result = searches_get_auth_target(
			&resource->query[0], &resource->addr,
			&tls_client_trigger_auth )) != NULL ) {

		if( tls_connect_init( &resource->ssl, &resource->fd, &resource->query[0], &result->addr ) < 0 ) {
			// Failed to initiate connection
			result->state = AUTH_ERROR;
		} else {
			// Start authentication process
			result->state = AUTH_PROGRESS;
			net_add_handler( resource->fd.fd, &tls_handle );
		}
	}
}

#if DEBUG

// Verify configuration
static int tls_conf_verify( void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags ) {
	char buf1[MBEDTLS_SSL_MAX_CONTENT_LEN];
	char buf2[MBEDTLS_SSL_MAX_CONTENT_LEN];
	((void) data);

	mbedtls_x509_crt_info( buf1, sizeof( buf1 ), "", crt );

	if ( *flags ) {
		mbedtls_x509_crt_verify_info( buf2, sizeof( buf2 ), "", *flags );
	}

	log_debug( "TLS-Client: Verify requested for (Depth %d)\n%sflags             : %s", depth, buf1,
		*flags ? buf2 : "None\n" );

	return 0;
}
#endif

// Load the trusted CA root certificates
int tls_client_add_ca( const char path[] ) {
	char error_buf[100];
	int ret;

	// Enable client and initialize certs storage
	if( g_client_enable == 0 ) {
		mbedtls_x509_crt_init( &g_cacert );
		g_client_enable = 1;
	}

	if( ((ret = mbedtls_x509_crt_parse_file( &g_cacert, path )) < 0) &&
		((ret = mbedtls_x509_crt_parse_path( &g_cacert, path )) < 0)) {
		mbedtls_strerror( ret, error_buf, sizeof(error_buf) );
		log_warn( "TLS-Client: Failed to load the CA root certificates from %s (%s)", path, error_buf );
		// We do not abort when a path was not loaded
		return 0;
	}

	log_info( "TLS-Client: Loaded certificates from %s (%d skipped)", path, ret );
	return 0;
}

void tls_client_setup( void ) {
	const char *pers = "kadnode";
	int ret;
	int i;

	// Reject query if TLS client disabled
	if (g_client_enable == 0) {
		return;
	}

	if (g_cacert.version <= 0) {
		log_err( "TLS-Client: No root CA certificates found." );
		return;
	}

	//mbedtls_debug_set_threshold( 0 );

	mbedtls_ctr_drbg_init( &g_drbg );
	mbedtls_entropy_init( &g_entropy );

	if( ( ret = mbedtls_ctr_drbg_seed( &g_drbg, mbedtls_entropy_func, &g_entropy,
		(const unsigned char *) pers, strlen( pers ) ) ) != 0 ) {
		log_err( "TLS-Client: mbedtls_ctr_drbg_seed returned -0x%x", -ret );
		exit( 1 );
		return;
	}

	for( i = 0; i < N_ELEMS(g_tls_resources); ++i ) {
		mbedtls_ssl_init( &g_tls_resources[i].ssl );
		mbedtls_net_init( &g_tls_resources[i].fd );
	}

	mbedtls_ssl_config_init( &g_conf );

	// Setup SSL/TLS structure
	if( ( ret = mbedtls_ssl_config_defaults( &g_conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
		log_err( "TLS-Client: mbedtls_ssl_config_defaults returned -0x%x", -ret );
		exit( 1 );
	}

#ifdef DEBUG
	mbedtls_ssl_conf_verify( &g_conf, tls_conf_verify, NULL );
#endif

	mbedtls_ssl_conf_rng( &g_conf, mbedtls_ctr_drbg_random, &g_drbg );
	mbedtls_ssl_conf_read_timeout( &g_conf, 0 );
	mbedtls_ssl_conf_ca_chain( &g_conf, &g_cacert, NULL );

	// Initialize a bunch ob SSL contexts
	for( i = 0; i < N_ELEMS(g_tls_resources); ++i ) {
		if( ( ret = mbedtls_ssl_setup( &g_tls_resources[i].ssl, &g_conf ) ) != 0 ) {
			log_err( "TLS-Client: mbedtls_ssl_setup returned -0x%x", -ret );
			exit( 1 );
		}
	}
}

void tls_client_free( void ) {
	int i;

	for( i = 0; i < N_ELEMS(g_tls_resources); ++i ) {
		mbedtls_ssl_free( &g_tls_resources[i].ssl );
		mbedtls_net_free( &g_tls_resources[i].fd );
	}

	mbedtls_x509_crt_free( &g_cacert );
	mbedtls_ssl_config_free( &g_conf );
	mbedtls_entropy_free( &g_entropy );
	mbedtls_ctr_drbg_free( &g_drbg );
}
