
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include "mbedtls/version.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/debug.h"
#include "mbedtls/oid.h"
#include "mbedtls/error.h"

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "searches.h"
#include "announces.h"
#include "ext-tls-server.h"


/*
* TLS server that closes the connection as soon as the handshake has been done.
* The certificates are selected by Server Name Indication (SNI).
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
    mbedtls_x509_crt crt;
    mbedtls_pk_context key;
    struct sni_entry *next;
};

static struct sni_entry *g_sni_entries = NULL;


// Forward declaration
static void tls_client_handler(int rc, int sock);


static void end_client_connection(mbedtls_net_context *client_fd, int result)
{
    int ret;

    net_remove_handler(client_fd->fd, &tls_client_handler);

    // Done and close connection
    do ret = mbedtls_ssl_close_notify(&g_ssl);
    while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    mbedtls_net_free(client_fd);
    mbedtls_ssl_session_reset(&g_ssl);

#ifdef DEBUG
    if (result == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED)  {
        log_debug("TLS-Server: Hello verification requested");
    } else if (result == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
        log_debug("TLS-Server: Client initiated reconnection from same port");
    } else if (result != 0) {
        char error_buf[100];
        mbedtls_strerror(result, error_buf, 100);
        log_debug("TLS-Server: Error -0x%x - %s", -result, error_buf);
    } else {
        log_debug("TLS-Server: Authentication successful");
    }
#endif
}

static void tls_client_handler(int rc, int sock)
{
    mbedtls_net_context *client_fd;
    int ret;
    int exp;

    if (sock == g_client_fd4.fd) {
        client_fd = &g_client_fd4;
    } else {
        client_fd = &g_client_fd6;
    }

    do ret = mbedtls_ssl_handshake(&g_ssl);
    while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        // TLS handshake in progress
        return;
    }

    if (ret) {
#ifdef DEBUG
        if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
            char vrfy_buf[512];
            uint32_t flags = mbedtls_ssl_get_verify_result(&g_ssl);
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "", flags);

            log_debug("TLS-Server: Verify failed: %s", vrfy_buf);
        }
#endif
        end_client_connection(client_fd, ret);
    } else {
        log_debug("TLS-Server: Protocol is %s, ciphersuite is %s",
            mbedtls_ssl_get_version(&g_ssl), mbedtls_ssl_get_ciphersuite(&g_ssl));

        if ((exp = mbedtls_ssl_get_record_expansion(&g_ssl)) >= 0) {
            log_debug("TLS-Server: Record expansion is %d", exp);
        } else {
            log_debug("TLS-Server: Record expansion is unknown (compression)");
        }

        // All ok
        end_client_connection(client_fd, 0);
    }
}

static void tls_server_handler(int rc, int sock)
{
    unsigned char client_ip[16] = { 0 };
    mbedtls_net_context *listen_fd;
    mbedtls_net_context *client_fd;
    size_t cliip_len;
    int ret;

    if (rc <= 0 || g_client_fd4.fd > -1 || g_client_fd6.fd > -1) {
        // No data or there is already a connection in progress
        return;
    }

    if (sock == g_listen_fd6.fd) {
        listen_fd = &g_listen_fd6;
        client_fd = &g_client_fd6;
    } else {
        listen_fd = &g_listen_fd4;
        client_fd = &g_client_fd4;
    }

    if ((ret = mbedtls_net_accept(listen_fd, client_fd,
                client_ip, sizeof(client_ip), &cliip_len)) != 0) {
        log_warning("TLS-Server: mbedtls_net_accept returned -0x%x", -ret);
        return;
    }

    log_debug("TLS-Server: Got incoming connection");

    ret = mbedtls_net_set_nonblock(client_fd);
    if (ret != 0) {
        log_warning("TLS-Server: net_set_nonblock() returned -0x%x", -ret);
        return;
    }

    mbedtls_ssl_conf_read_timeout(&g_conf, 0);

    mbedtls_ssl_set_bio(&g_ssl, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // New incoming handler connection
    net_add_handler(client_fd->fd, &tls_client_handler);
}

// Get the CN field of a certificate
static int get_common_name(char buf[], size_t len, const mbedtls_x509_crt *crt)
{
    const mbedtls_x509_name *name;
    const char *short_name;
    int ret;

    name = &crt->subject;
    while (name) {
        if (name->oid.p) {
            ret = mbedtls_oid_get_attr_short_name(&name->oid, &short_name);
            if (ret == 0 && strcmp(short_name, "CN") == 0 && name->val.len < len) {
                memcpy(buf, (char*)name->val.p, name->val.len);
                buf[name->val.len] = '\0';
                return 0;
            }
        }

        name = name->next;
    }

    return 1;
}

// Match common name with domain name
static int match_pattern(const char cname[], const char name[])
{
    if (cname[0] == '*') {
        char *dot = strchr(name, '.');
        return dot && (strcmp(dot, cname + 1) == 0);
    } else {
        return strcmp(cname, name) == 0;
    }
}

// SNI callback. The client submits the domain it is looking for.
// The proper certificate needs to be selected and returned.
static int sni_callback(void *p_info, mbedtls_ssl_context *ssl, const unsigned char *name, size_t name_len)
{
    struct sni_entry *cur;

    log_debug("TLS-Server: Lookup certificate for domain: %s", name);

    cur = (struct sni_entry *) p_info;
    while (cur != NULL) {
        if (match_pattern(cur->name, (const char*) name)) {
            // The client does not need to be authenticated
            mbedtls_ssl_set_hs_authmode(ssl, MBEDTLS_SSL_VERIFY_NONE);

            // Set own certificate and key for the current handshake
            return(mbedtls_ssl_set_hs_own_cert(ssl, &cur->crt, &cur->key));
        }

        cur = cur->next;
    }

    return -1;
}

bool tls_server_add_sni(const char crt_file[], const char key_file[])
{
    char error_buf[100];
    mbedtls_x509_crt crt;
    mbedtls_pk_context key;
    struct sni_entry *new;
    struct sni_entry *cur;
    char name[QUERY_MAX_SIZE];
    int ret;

    mbedtls_x509_crt_init(&crt);
    mbedtls_pk_init(&key);

    if ((ret = mbedtls_x509_crt_parse_file(&crt, crt_file)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        log_error("TLS-Server: %s: %s", crt_file, error_buf);
        return false;
    }

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    ret = mbedtls_pk_parse_keyfile(&key, key_file, "" /* no password */, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE);
#else
    ret = mbedtls_pk_parse_keyfile(&key, key_file, "" /* no password */, mbedtls_ctr_drbg_random, &g_drbg);
#endif
#else
    ret = mbedtls_pk_parse_keyfile(&key, key_file, "" /* no password */);
#endif
    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        log_error("TLS-Server: %s: %s", key_file, error_buf);
        return false;
    }

    // Check if common name is set
    if (get_common_name(name, sizeof(name), &crt) != 0) {
        log_error("TLS-Server: No common name set in %s", crt_file);
        return false;
    }

    // Check for duplicate entries
    cur = g_sni_entries;
    while (cur) {
        if (strcmp(cur->name, name) == 0) {
            log_error("TLS-Server: Duplicate entry %s", name);
            return false;
        }
        cur = cur->next;
    }

    // Create new entry
    if ((new = calloc(1, sizeof(struct sni_entry))) == NULL) {
        log_error("TLS-Server: Error calling calloc()");
        return false;
    }

    new->name = strdup(name);
    memcpy(&new->key, &key, sizeof(key));
    memcpy(&new->crt, &crt, sizeof(crt));

#ifdef DEBUG
    char buf[MBEDTLS_SSL_MAX_CONTENT_LEN];
    mbedtls_x509_crt_info(buf, sizeof(buf), "  ", &new->crt);
    log_debug("%s:\n%s", crt_file, buf);
#endif

    // Prepend entry to list
    if (g_sni_entries) {
        new->next = g_sni_entries;
    }
    g_sni_entries = new;

    log_info("TLS-Server: Loaded server credentials for %s (%s, %s)", name, crt_file, key_file);

    return true;
}

static void tls_announce_all_cnames(void)
{
    struct sni_entry *cur;
    char name[QUERY_MAX_SIZE];

    // Announce cnames
    cur = g_sni_entries;
    while (cur) {
        // Won't announce wildcard domains
        if (query_sanitize(name, sizeof(name), cur->name)) {
            announces_add(NULL, name, LONG_MAX);
        }
        cur = cur->next;
    }
}

bool tls_server_setup(void)
{
    const char *pers = "kadnode";
    int ret;

    // Without SNI entries, there is no reason to start the TLS server
    if (g_sni_entries == NULL) {
        return true;
    }

#ifdef MBEDTLS_USE_PSA_CRYPTO
    psa_crypto_init();
#endif

    // Initialize sockets
    mbedtls_net_init(&g_client_fd4);
    mbedtls_net_init(&g_listen_fd4);
    mbedtls_net_init(&g_client_fd6);
    mbedtls_net_init(&g_listen_fd6);

    mbedtls_ssl_init(&g_ssl);
    mbedtls_ssl_config_init(&g_conf);
    mbedtls_ctr_drbg_init(&g_drbg);

    // Announce all common names from certificates
    tls_announce_all_cnames();

    //mbedtls_debug_set_threshold(0);

    mbedtls_entropy_init(&g_entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
        (const unsigned char *) pers, strlen(pers))) != 0) {
        log_error("TLS-Server: mbedtls_ctr_drbg_seed returned -0x%x", -ret);
        return false;
    }

    // May return -1 if protocol not enabled/supported
    g_listen_fd4.fd = net_bind("TLS", "0.0.0.0", gconf->dht_port, NULL, IPPROTO_TCP);
    g_listen_fd6.fd = net_bind("TLS", "::", gconf->dht_port, NULL, IPPROTO_TCP);

    if ((ret = mbedtls_ssl_config_defaults(&g_conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        log_error("TLS-Server: mbedtls_ssl_config_defaults returned -0x%x", -ret);
        return false;
    }

    mbedtls_ssl_conf_authmode(&g_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&g_conf, mbedtls_ctr_drbg_random, &g_drbg);
    //mbedtls_ssl_conf_dbg(&g_conf, my_debug, stdout);

    mbedtls_ssl_conf_sni(&g_conf, sni_callback, g_sni_entries);

    if ((ret = mbedtls_ssl_setup(&g_ssl, &g_conf)) != 0) {
        log_error("TLS-Server: mbedtls_ssl_setup returned -0x%x", -ret);
        return false;
    }

    if (g_listen_fd4.fd > -1) {
        mbedtls_net_set_nonblock(&g_listen_fd4);
        net_add_handler(g_listen_fd4.fd, &tls_server_handler);
    }

    if (g_listen_fd6.fd > -1) {
        mbedtls_net_set_nonblock(&g_listen_fd6);
        net_add_handler(g_listen_fd6.fd, &tls_server_handler);
    }

    return true;
}

void tls_server_free(void)
{
    // Nothing to do
}
