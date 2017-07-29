
#define _WITH_DPRINTF
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "searches.h"
#include "ext-tls-server.h"


/*
* TLS server that closes the connection as soon as the handshake has been done.
* The certificate are selected by Server Name Indication (SNI).
*/

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_ssl_context g_ssl;
static mbedtls_ssl_config g_conf;

static mbedtls_net_context g_listen_fd4;
static mbedtls_net_context g_listen_fd6;
static mbedtls_net_context g_client_fd4;
static mbedtls_net_context g_client_fd6;


// Certificate for each domain we authenticate
struct sni_entry {
	const char *name;
	mbedtls_x509_crt cert;
	mbedtls_pk_context key;
	struct sni_entry *next;
};

static struct sni_entry *g_sni_entries = NULL;


// Forward declaration
void tls_client_handler( int rc, int sock );


void end_client_connection( mbedtls_net_context *client_fd, int result ) {
	int ret;

	net_remove_handler( client_fd->fd, tls_client_handler );

	// Done and close connection
	do ret = mbedtls_ssl_close_notify( &g_ssl );
	while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );

	mbedtls_net_free( client_fd );
	mbedtls_ssl_session_reset( &g_ssl );

	if( result == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED )  {
		log_info( "TLS: Hello verification requested" );
	} else if( result == MBEDTLS_ERR_SSL_CLIENT_RECONNECT ) {
		log_debug( "TLS: Client initiated reconnection from same port" );
	} else if( result != 0 ) {
		char error_buf[100];
		mbedtls_strerror( result, error_buf, 100 );
		log_info( "TLS: Error -0x%x - %s", -result, error_buf );
	} else {
		log_info( "TLS: Authentication successful" );
	}
}

void tls_client_handler( int rc, int sock ) {
	mbedtls_net_context *client_fd;
	int ret;
	int exp;

	log_info( "TLS: tls_client_handler, rc: %d", rc );

	if( sock == g_client_fd4.fd ) {
		client_fd = &g_client_fd4;
	} else {
		client_fd = &g_client_fd6;
	}

	do ret = mbedtls_ssl_handshake( &g_ssl );
	while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
		ret == MBEDTLS_ERR_SSL_WANT_WRITE );
/*
	int ret = mbedtls_ssl_handshake( &g_ssl );
	if( ret == MBEDTLS_ERR_SSL_WANT_READ ||
	   ret == MBEDTLS_ERR_SSL_WANT_WRITE )
	{
		printf("wait\n");
		// retry
		return;
	}
	else*/ if( ret != 0 ) {
#ifdef DEBUG
		if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ) {
			char vrfy_buf[512];
			int flags = mbedtls_ssl_get_verify_result( &g_ssl );
			mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "", flags );

			log_debug( "TLS: Verify failed: %s", vrfy_buf );
		}
#endif
		end_client_connection( client_fd, ret );
	} else {
		// ret == 0
		log_info( "TLS: Protocol is %s, ciphersuite is %s",
			mbedtls_ssl_get_version( &g_ssl ), mbedtls_ssl_get_ciphersuite( &g_ssl ) );

		if( ( exp = mbedtls_ssl_get_record_expansion( &g_ssl ) ) >= 0 ) {
			log_info( "TLS: Record expansion is %d", exp );
		} else {
			log_info( "TLS: Record expansion is unknown (compression)" );
		}

		// All ok
		end_client_connection( client_fd, 0 );
	}
}

void tls_server_handler( int rc, int sock ) {
	unsigned char client_ip[16] = { 0 };
	size_t cliip_len;
	mbedtls_net_context *listen_fd;
	mbedtls_net_context *client_fd;
	int ret;

	if( sock == g_listen_fd6.fd ) {
		listen_fd = &g_listen_fd6;
		client_fd = &g_client_fd6;
	} else {
		listen_fd = &g_listen_fd4;
		client_fd = &g_client_fd4;
	}

	if( rc <= 0 || g_client_fd4.fd > -1 || g_client_fd6.fd > -1 ) {
		// We already got an connection in progress
		return;
	}

	if( ( ret = mbedtls_net_accept( listen_fd, client_fd,
				client_ip, sizeof( client_ip ), &cliip_len ) ) != 0 ) {
		log_warn( "TLS: mbedtls_net_accept returned -0x%x", -ret );
		return;
	}

	log_debug( "TLS: Got incoming connection" );

	ret = mbedtls_net_set_nonblock( client_fd );
	if( ret != 0 ) {
		log_warn( "TLS: net_set_nonblock() returned -0x%x", -ret );
		return;
	}

	mbedtls_ssl_conf_read_timeout( &g_conf, 0 );

	mbedtls_ssl_set_bio( &g_ssl, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

	// New incoming handler connection
	net_add_handler( client_fd->fd, tls_client_handler );
}

/*
 * SNI callback.
 */
int sni_callback( void *p_info, mbedtls_ssl_context *ssl, const unsigned char *name, size_t name_len ) {
	printf("sni_callback for name: %s\n", name);

	struct sni_entry *cur = (struct sni_entry *) p_info;

	while( cur != NULL ) {
		if( name_len == strlen( cur->name ) &&
			memcmp( name, cur->name, name_len ) == 0 ) {
			printf("found\n");
			//Set the data required to verify peer certificate for the current handshake.
			//if( cur->ca != NULL ) {
			//    printf("set sni ca chain\n");
			//    mbedtls_ssl_set_hs_ca_chain( ssl, cur->ca, cur->crl );
			//}

			// auth mode for client
			mbedtls_ssl_set_hs_authmode( ssl, MBEDTLS_SSL_VERIFY_NONE /*MBEDTLS_SSL_VERIFY_REQUIRED*/ );

			// Set own certificate and key for the current handshake.
			return( mbedtls_ssl_set_hs_own_cert( ssl, &cur->cert, &cur->key ) );
		}

		cur = cur->next;
	}

	return -1;
}

void tls_server_add_sni( const char name[], const char crt_file[], const char key_file[] ) {
	char error_buf[100];
	struct sni_entry *new;

	if( (new = calloc( 1, sizeof(struct sni_entry))) == NULL ) {
		log_err( "TLS: Error calling calloc()" );
		exit( 1 );
	}

	new->name = strdup( name );
	mbedtls_x509_crt_init( &new->cert );
	mbedtls_pk_init( &new->key );

	int ret;
	if( (ret = mbedtls_x509_crt_parse_file( &new->cert, crt_file )) != 0 ) {     
		mbedtls_strerror( ret, error_buf, sizeof(error_buf) );
		log_err( "TLS: %s: %s", crt_file, error_buf );
		exit( 1 );
	}

	if( (ret = mbedtls_pk_parse_keyfile( &new->key, key_file, "" /* no password */ )) != 0 ) {
		mbedtls_strerror( ret, error_buf, sizeof(error_buf) );
		log_err( "TLS: %s: %s", key_file, error_buf );
		exit( 1 );
	}

	if( g_sni_entries ) {
		new->next = g_sni_entries;
	}
	g_sni_entries = new;

	log_info( "TLS: Loaded server credentials for %s", name );
}

void tls_server_setup( void ) {
	const char * pers = "kadnode";
	int ret;

	mbedtls_net_init( &g_client_fd4 );
	mbedtls_net_init( &g_listen_fd4 );
	mbedtls_net_init( &g_client_fd6 );
	mbedtls_net_init( &g_listen_fd6 );

	mbedtls_ssl_init( &g_ssl );
	mbedtls_ssl_config_init( &g_conf );
	mbedtls_ctr_drbg_init( &g_drbg );

	mbedtls_debug_set_threshold( 0 );

	mbedtls_entropy_init( &g_entropy );
	if( ( ret = mbedtls_ctr_drbg_seed( &g_drbg, mbedtls_entropy_func, &g_entropy,
		(const unsigned char *) pers, strlen( pers ) ) ) != 0 ) {
		log_err( "TLS: mbedtls_ctr_drbg_seed returned -0x%x", -ret );
		exit( 1 );
	}

	// Without SNI entries, there is no reason to start the TLS server
	if( g_sni_entries ) {
		// May return -1 if protocol not enabled/supported
		g_listen_fd4.fd = net_bind( "TLS", "0.0.0.0", gconf->dht_port, NULL, IPPROTO_TCP, AF_UNSPEC );
		g_listen_fd6.fd = net_bind( "TLS", "::", gconf->dht_port, NULL, IPPROTO_TCP, AF_UNSPEC );

		if( ( ret = mbedtls_ssl_config_defaults( &g_conf,
			MBEDTLS_SSL_IS_SERVER,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
		{
			log_err( "TLS: mbedtls_ssl_config_defaults returned -0x%x", -ret );
			exit( 1 );
		}

		mbedtls_ssl_conf_authmode( &g_conf, MBEDTLS_SSL_VERIFY_REQUIRED );
		mbedtls_ssl_conf_rng( &g_conf, mbedtls_ctr_drbg_random, &g_drbg );
		//mbedtls_ssl_conf_dbg( &g_conf, my_debug, stdout );

		mbedtls_ssl_conf_sni( &g_conf, sni_callback, g_sni_entries );

		if( ( ret = mbedtls_ssl_setup( &g_ssl, &g_conf ) ) != 0 ) {
			log_err( "TLS: mbedtls_ssl_setup returned -0x%x", -ret );
			exit( 1 );
		}

		if( g_listen_fd4.fd > -1 ) {
			mbedtls_net_set_nonblock( &g_listen_fd4 );
			net_add_handler( g_listen_fd4.fd, &tls_server_handler );
		}

		if( g_listen_fd6.fd > -1 ) {
			mbedtls_net_set_nonblock( &g_listen_fd6 );
			net_add_handler( g_listen_fd6.fd, &tls_server_handler );
		}
	}
}

void tls_server_free( void ) {
	// Nothing to do
}
