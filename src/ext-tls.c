
#define _WITH_DPRINTF
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h> /* close */

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

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "values.h"
#include "results.h"
#include "ext-tls.h"


// SSL structures for parallel connection handling.
struct tls_resource {
	mbedtls_ssl_context ssl;
	mbedtls_net_context fd;
	struct results_t *results;
	struct result_t *result;
};

// Global TLS resources
mbedtls_x509_crt g_cacert;
mbedtls_entropy_context g_entropy;
mbedtls_ctr_drbg_context g_drbg;
mbedtls_ssl_config g_conf;

// Allow two parallel authentications at once
struct tls_resource g_tls_resources[2];


// Start TLS connection
int tls_connect( mbedtls_ssl_context *ssl, mbedtls_net_context *fd, const char query[], const IP *addr ) {
	int ret;

	mbedtls_ssl_set_bio( ssl, fd, mbedtls_net_send, mbedtls_net_recv, NULL );

	if( ( ret = mbedtls_ssl_set_hostname( ssl, query ) ) != 0 )
	{
		log_err( "TLS: mbedtls_ssl_set_hostname returned %d\n\n", ret );
		return -1;
	}

	fd->fd = socket( addr->ss_family, SOCK_STREAM, IPPROTO_TCP );
	if( fd->fd < 0 )
	{
		log_err( "TLS: Socket creation failed: %s", strerror( errno ) );
		return -1;
	}

	ret = mbedtls_net_set_nonblock( fd );
	if( ret < 0) {
		log_err( "TLS: Failed to set socket non-blocking: %s", strerror( errno ) );
		return -1;
	}

	ret = connect( fd->fd, (const struct sockaddr *) addr, sizeof(IP) );
	if( ret < 0 && errno != EINPROGRESS ) {
		mbedtls_net_free( fd );
		mbedtls_net_init( fd );
		log_err( "TLS: Connect failed: %s", strerror( errno ) );
		return -1;
	}

	return 0;
}

struct tls_resource *tls_find_resource( int fd ) {
	int i;

	for( i = 0; i < N_ELEMS(g_tls_resources); i++ ) {
		if( g_tls_resources[i].fd.fd == fd ) {
			return &g_tls_resources[i];
		}
	}

	return NULL;
}


// forward declartion
void tls_handle( int rc, int fd );

void auth_end( struct tls_resource* resource, int state ) {
	struct results_t *results;
	struct result_t *result;

	log_debug( "TLS: Auth %s for %s", (state == AUTH_OK) ? "success" : "failure", resource->results->query );

	result = resource->result;
	results = resource->results;

	net_remove_handler( resource->fd.fd, &tls_handle );

	resource->result = NULL;
	resource->results = NULL;
	mbedtls_net_free( &resource->fd );
	mbedtls_net_init( &resource->fd );
	mbedtls_ssl_session_reset( &resource->ssl );

	// Update authentication state
	result->state = state;

	if( state == AUTH_OK ) {
		// Stop auth process for this 
		results->callback = NULL;

		result = results->entries;
		while( result ) {
			if( result->state == AUTH_WAITING ) {
				result->state = AUTH_SKIP;
			}
			result = result->next;
		}
	} else {
		// Look for next address
		tls_trigger_auth( resource->results );
	}
}

void tls_handle( int rc, int fd ) {
	struct tls_resource* resource; // = (struct tls_resource*) data;
	mbedtls_ssl_context* ssl; // = &resource->ssl;
	const char *query; // = resource->results->query;
	int ret;

	resource = tls_find_resource( fd );
	if( resource == NULL ) {
		// Should not happen..
		close( fd );
		net_remove_handler( fd, &tls_handle);
		return;
	}

	ssl = &resource->ssl;
	query = resource->results->query;

	printf("tls_handle %s\n", resource->results->query);

	if( rc < 0 ) {
		if( errno != EINPROGRESS ) {
			// Failed to make TCP/IP connection.
			log_warn("TLS: Socket error for '%s': %s", query, strerror( errno ) );
			auth_end( resource, AUTH_ERROR );
		} else {
			// Still connecting.
		}
	} else if( (ret = mbedtls_ssl_handshake( ssl ) ) == 0) {
			// TLS handshake done
		log_debug( "TLS: Protocol [%s], Ciphersuite [%s] and fragment length %u: %s",
			mbedtls_ssl_get_version( ssl ), mbedtls_ssl_get_ciphersuite( ssl ),
			(unsigned int) mbedtls_ssl_get_max_frag_len( ssl ), query
		);

		// Verifying peer X.509 certificate

		uint32_t flags = 0;
		char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];

		if( ( flags = mbedtls_ssl_get_verify_result( ssl ) ) != 0 )
		{
			mbedtls_x509_crt_verify_info( buf, sizeof( buf ), "", flags );
			log_debug( "TLS: Peer verification failed:\n%s\n", buf);
		}

		if( mbedtls_ssl_get_peer_cert( ssl ) != NULL )
		{
			mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "", mbedtls_ssl_get_peer_cert( ssl ) );
			log_debug( "TLS: Peer certificate information:\n%s\n", buf);
		}

		// Done and close connection
		do ret = mbedtls_ssl_close_notify( ssl );
		while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );

		auth_end(resource, flags == 0 ? AUTH_OK : AUTH_FAILED);
	}
	else if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
	{
		// TLS handshake failure.
#ifdef DEBUG 
		log_debug( "TLS: mbedtls_ssl_handshake returned -0x%x: %s", -ret, query );
		if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ) {
			log_debug( "TLS: Unable to verify the server's certificate: %s", query );
		}
#endif

		auth_end(resource, AUTH_FAILED);
	}
	else
	{
		// TLS handshake in progress.
	}
}

int tls_decide_auth( const char query[] ) {
	return 0;
}

// Find a resource instance that is currently not in use
struct tls_resource *tls_next_resource( void ) {
	int i;

	for( i = 0; i < N_ELEMS(g_tls_resources); i++ ) {
		if( g_tls_resources[i].results == NULL ) {
			return &g_tls_resources[i];
		}
	}

	return NULL;
}

struct result_t *tls_next_result( struct results_t *results ) {
	struct result_t *result;

	result = results->entries;
	while( result ) {
		if( result->state == AUTH_WAITING ) {
			return result;
		}
		result = result->next;
	}

	return NULL;
}

// Called for every new address in results
void tls_trigger_auth( struct results_t *results ) {
	struct tls_resource *resource;
	struct result_t *result;

	result = results->entries;
	while( result ) {
		resource = tls_next_resource();
		if( resource == NULL ) {
			// No SSL resources available
			return;
		}

		result = tls_next_result( results );
		if( result == NULL ) {
			// No results to authenticate
			return;
		}

		// Start authentication process
		//printf("tls_start_jobs: %s (%s)\n", results->query, str_addr( &result->addr ) );

		if( tls_connect( &resource->ssl, &resource->fd, results->query, &result->addr ) < 0 ) {
			result->state = AUTH_ERROR;
		} else {
			resource->result = result;
			resource->results = results;

			result->state = AUTH_PROGRESS;
			net_add_handler( resource->fd.fd, &tls_handle );
		}

		result = result->next;
	}
}

// Verifiy configuration
int tls_conf_verify( void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags ) {
	char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
	((void) data);

	mbedtls_x509_crt_info( buf, sizeof( buf ) - 1, "", crt );

	log_info( "TLS: Verify requested for (Depth %d)\n%s\n", depth, buf);

	if ( *flags == 0 ) {
		log_info( "TLS: This certificate has no flags" );
	} else {
		mbedtls_x509_crt_verify_info( buf, sizeof( buf ), "", *flags );
		log_debug( "TLS: %s\n", buf );
	}

	return 0;
}

// Load the trusted CA
void tls_add_ca_entry( const char ca_path[] ) {
	char error_buf[100];
	int ret;

	if( ((ret = mbedtls_x509_crt_parse_file( &g_cacert, ca_path )) < 0) &&
		((ret = mbedtls_x509_crt_parse_path( &g_cacert, ca_path )) < 0)) {
		mbedtls_strerror( ret, error_buf, sizeof(error_buf) );
		log_err( "TLS: Failed to load the CA root certificate(s) from %s - %s", ca_path, error_buf );
		exit(1);
	}

	log_info( "TLS: Loaded certificates from: %s (%d skipped)", ret );
}

int auth_conf( /*const char ca_path[]*/ ) {
	int ret;
	int i;
/*
	if( ca_path == NULL ) {
		ca_path = "/usr/share/ca-certificates/mozilla/";
	}

	// Load the trusted CA
	log_info( "Loading the CA root certificate from: %s", ca_path );

	ret = mbedtls_x509_crt_parse_path( &g_cacert, ca_path );
	log_info( "TLS: Loaded certificates: ok (%d skipped)", ret );
*/
	// Setting up the SSL/TLS structure.
	if( ( ret = mbedtls_ssl_config_defaults( &g_conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
	{
		printf( " failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret );
		return -1;
	}

#ifdef DEBUG
	mbedtls_ssl_conf_verify( &g_conf, tls_conf_verify, NULL );
#endif

	mbedtls_ssl_conf_rng( &g_conf, mbedtls_ctr_drbg_random, &g_drbg );
	mbedtls_ssl_conf_read_timeout( &g_conf, 0 );
	mbedtls_ssl_conf_ca_chain( &g_conf, &g_cacert, NULL );

	for( i = 0; i < N_ELEMS(g_tls_resources); i++ ) {
		if( ( ret = mbedtls_ssl_setup( &g_tls_resources[i].ssl, &g_conf ) ) != 0 )
		{
			log_err( "TLS: mbedtls_ssl_setup returned -0x%x\n\n", -ret );
			return -1;
		}
	}

	return 0;
}

// TODO: create server IP address on the same port as the DHT.
/*
st4 = net_bind( "KAD", DHT_ADDR4, gconf->dht_port, gconf->dht_ifname, IPPROTO_UDP, AF_INET );
st6 = net_bind( "KAD", DHT_ADDR6, gconf->dht_port, gconf->dht_ifname, IPPROTO_UDP, AF_INET6 );
su4 = net_bind( "KAD", DHT_ADDR4, gconf->dht_port, gconf->dht_ifname, IPPROTO_TCP, AF_INET );
su6 = net_bind( "KAD", DHT_ADDR6, gconf->dht_port, gconf->dht_ifname, IPPROTO_TCP, AF_INET6 );
... make global and share between KAD, BOB and TLS

*/
void tls_setup( void ) {
	const char *pers = "kadnode";
	int ret;
	int i;

	mbedtls_debug_set_threshold( 0 );

	mbedtls_ctr_drbg_init( &g_drbg );
	mbedtls_entropy_init( &g_entropy );

	if( ( ret = mbedtls_ctr_drbg_seed( &g_drbg, mbedtls_entropy_func, &g_entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
	{
		log_err( "TLS: mbedtls_ctr_drbg_seed returned -0x%x\n", -ret );
		exit(1);
		return;
	}

	for( i = 0; i < N_ELEMS(g_tls_resources); i++ ) {
		mbedtls_ssl_init( &g_tls_resources[i].ssl );
		mbedtls_net_init( &g_tls_resources[i].fd );
	}

	mbedtls_ssl_config_init( &g_conf );
	mbedtls_x509_crt_init( &g_cacert );

	auth_conf( /*gconf->tls_path*/ );
}

void tls_free( void ) {
	int i;

	for( i = 0; i < N_ELEMS(g_tls_resources); i++ ) {
		mbedtls_ssl_free( &g_tls_resources[i].ssl );
		mbedtls_net_free( &g_tls_resources[i].fd );
	}

	mbedtls_x509_crt_free( &g_cacert );
	mbedtls_ssl_config_free( &g_conf );

	mbedtls_entropy_free( &g_entropy );
	mbedtls_ctr_drbg_free( &g_drbg );
}
