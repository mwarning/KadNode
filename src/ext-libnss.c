
/* part of this code originate from gnunet-gns */

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdbool.h>
#ifdef __FreeBSD__
#include <nsswitch.h>
#include <stdarg.h>
#include <sys/param.h>
#endif

#include "main.h"
#include "ext-libnss-utils.h"
#include "ext-libnss.h"


#ifdef DEBUG
static void debug(const char format[], ...)
{
    static const char *debug_output = "/tmp/nss_kadnode.log";
    char buf[1024];
    va_list vlist;

    va_start(vlist, format);
    vsnprintf(buf, sizeof(buf), format, vlist);
    va_end(vlist);

    FILE *out = fopen(debug_output, "a");
    if (out) {
        fprintf(out, "%s\n", buf);
        fclose(out);
    } else {
        // fallback...
        fprintf(stderr, "%s\n", buf);
    }
}
#else
#define debug(...) // discard debug output
#endif

static bool _nss_kadnode_lookup(kadnode_nss_response_t *res, const kadnode_nss_request_t *req)
{
    struct sockaddr_un addr = {0};
    const char *path = NSS_PATH;
    struct timeval tv;

    int sock = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }

    // Set the receive timeout to 100ms
    tv.tv_sec = 0;
    tv.tv_usec = 100000;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) < 0) {
        debug("setsockopt(SO_RCVTIMEO) failed for %s", &req->name[0]);
        return false;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval)) < 0) {
        debug("setsockopt(SO_SNDTIMEO) failed for %s", &req->name[0]);
        return false;
    }

    addr.sun_family = AF_LOCAL;
    strcpy(addr.sun_path, path);

    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(sock);
        debug("connect() failed for %s", &req->name[0]);
        return false;
    }

    // Send request
    send(sock, req, sizeof(*req), 0);

    // Receive request
    ssize_t rc = read(sock, res, sizeof(*res));
    close(sock);

    return (rc == sizeof(kadnode_nss_response_t));
}

enum nss_status _nss_kadnode_gethostbyname_impl(const char* name, int af,
                                             kadnode_nss_response_t* res, int* errnop,
                                             int* h_errnop, bool allow_mixed_af) {
    if (af == AF_UNSPEC || af == AF_INET || af == AF_INET6) {
        kadnode_nss_request_t req;
        req.af = af;
        req.allow_mixed_af = allow_mixed_af; // only relevant if af == AF_UNSPEC
        strncpy(&req.name[0], name, QUERY_MAX_SIZE);

        bool ok = _nss_kadnode_lookup(res, &req);

        if (ok) {
            if (res->count == 0) {
                // in progress
                *errnop = ETIMEDOUT;
                *h_errnop = TRY_AGAIN;
                debug("_nss_kadnode_gethostbyname_impl OK NSS_STATUS_UNAVAIL/ETIMEDOUT/TRY_AGAIN for %s", name);
                return NSS_STATUS_UNAVAIL;
            } else if (res->count > 0) {
                debug("_nss_kadnode_gethostbyname_impl OK NSS_STATUS_SUCCESS for %s", name);
                // found results
                return NSS_STATUS_SUCCESS;
            } else {
                // no results found
                *errnop = ETIMEDOUT;
                *h_errnop = HOST_NOT_FOUND;
                debug("_nss_kadnode_gethostbyname_impl OK NSS_STATUS_NOTFOUND/ETIMEDOUT/HOST_NOT_FOUND for %s", name);
                return NSS_STATUS_NOTFOUND;
            }
        } else {
            debug("_nss_kadnode_gethostbyname_impl NOK NSS_STATUS_UNAVAIL/ETIMEDOUT/NO_RECOVERY for %s", name);
            *errnop = ETIMEDOUT;
            *h_errnop = NO_RECOVERY;
            return NSS_STATUS_UNAVAIL;
        }
    } else {
        // KadNode cannot be reached or rejected to process the lookup
        debug("_nss_kadnode_gethostbyname_impl invalid af NSS_STATUS_UNAVAIL/ETIMEDOUT/NO_RECOVERY for %s", name);
        *errnop = ETIMEDOUT;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }
}

#ifndef __FreeBSD__
enum nss_status _nss_kadnode_gethostbyname4_r(const char* name,
                                           struct gaih_addrtuple** pat,
                                           char* buffer, size_t buflen,
                                           int* errnop, int* h_errnop,
                                           int32_t* ttlp) {

    (void)ttlp;

    kadnode_nss_response_t u;
    buffer_t buf;

    debug("_nss_kadnode_gethostbyname4_r %s", name);

    enum nss_status status =
        _nss_kadnode_gethostbyname_impl(name, AF_UNSPEC, &u, errnop, h_errnop, true);
    if (status != NSS_STATUS_SUCCESS) {
        return status;
    }
    buffer_init(&buf, buffer, buflen);
    return convert_kadnode_nss_response_to_addrtuple(&u, name, pat, &buf, errnop, h_errnop);
}
#endif

enum nss_status _nss_kadnode_gethostbyname3_r(const char* name, int af,
                                           struct hostent* result, char* buffer,
                                           size_t buflen, int* errnop,
                                           int* h_errnop, int32_t* ttlp,
                                           char** canonp) {

    (void)ttlp;
    (void)canonp;

    buffer_t buf;
    kadnode_nss_response_t u;

    debug("_nss_kadnode_gethostbyname3_r %s", name);

    // The interfaces for gethostbyname3_r and below do not actually support
    // returning results for more than one address family
    enum nss_status status = _nss_kadnode_gethostbyname_impl(name, af, &u, errnop, h_errnop, false);
    if (status != NSS_STATUS_SUCCESS) {
        return status;
    }
    buffer_init(&buf, buffer, buflen);
    return convert_userdata_for_name_to_hostent(&u, name, af, result, &buf,
                                                errnop, h_errnop);
}

enum nss_status _nss_kadnode_gethostbyname2_r(const char* name, int af,
                                           struct hostent* result, char* buffer,
                                           size_t buflen, int* errnop,
                                           int* h_errnop) {

    return _nss_kadnode_gethostbyname3_r(name, af, result, buffer, buflen, errnop,
                                      h_errnop, NULL, NULL);
}

enum nss_status _nss_kadnode_gethostbyname_r(const char* name,
                                          struct hostent* result, char* buffer,
                                          size_t buflen, int* errnop,
                                          int* h_errnop) {

    return _nss_kadnode_gethostbyname2_r(name, AF_UNSPEC, result, buffer, buflen,
                                      errnop, h_errnop);
}
