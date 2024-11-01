
/* part of this code originate from gnunet-gns */

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#ifdef __FreeBSD__
#include <nsswitch.h>
#include <stdarg.h>
#include <sys/param.h>
#endif

#include <stdarg.h>

#include "main.h"
#include "ext-libnss.h"


#ifndef ALIGN
/** macro to align idx to 32bit boundary */
#define ALIGN(idx) do { \
    if (idx % sizeof(void*)) \
        idx += (sizeof(void*) - idx % sizeof(void*)); /* Align on 32 bit boundary */ \
} while (0)
#endif

static int _nss_kadnode_lookup(struct kadnode_nss_response *res, const struct kadnode_nss_request *req)
{
    struct sockaddr_un addr;
    const char *path = NSS_PATH;
    struct timeval tv;
    int sock;
    ssize_t rc;

    sock = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (sock < 0) {
        return 0;
    }

    // Set receive timeout to 0.1 seconds
    tv.tv_sec = 0;
    tv.tv_usec = 100000;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) < 0) {
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval)) < 0) {
        return -1;
    }

    addr.sun_family = AF_LOCAL;
    strcpy(addr.sun_path, path);

    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(sock);
        return 0;
    }

    // Send request
    send(sock, req, sizeof(*req), 0);

    // Receive request
    rc = read(sock, res, sizeof(*res));
    close(sock);

    return (rc == sizeof(struct kadnode_nss_response)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * The gethostbyname hook executed by nsswitch
 *
 * @param name the name to resolve
 * @param af the address family to resolve
 * @param result the result hostent
 * @param buffer the result buffer
 * @param buflen length of the buffer
 * @param errnop idk
 * @param h_errnop idk
 * @return a nss_status code
 */
enum nss_status
_nss_kadnode_gethostbyname2_r(const char *name,
                                int af,
                                struct hostent *result,
                                char *buffer,
                                size_t buflen,
                                int *errnop,
                                int *h_errnop)
{
    struct kadnode_nss_request req;
    struct kadnode_nss_response res;
    enum nss_status status = NSS_STATUS_UNAVAIL;
    int rc;
    size_t addrlen;
    size_t idx;
    size_t astart;

    if ((af != AF_INET) && (af != AF_INET6) && (af != AF_UNSPEC))
    {
        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;

        goto finish;
    }

    if (buflen < (sizeof(char*) + strlen(name) + 1))	{
        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        status = NSS_STATUS_TRYAGAIN;
        goto finish;
    }

    req.af = af;
    strncpy(&req.name[0], name, QUERY_MAX_SIZE);

    rc = _nss_kadnode_lookup(&res, &req);

    if (rc == EXIT_FAILURE) {
        *errnop = ESHUTDOWN;
        *h_errnop = NO_RECOVERY;
        status = NSS_STATUS_TRYAGAIN;
        goto finish;
    }

    /* Validate reply */
    if ((res.count < 0) || ((res.af != AF_INET) && (res.af != AF_INET6))) {
        *errnop = ETIMEDOUT;
        *h_errnop = HOST_NOT_FOUND;
        status = NSS_STATUS_NOTFOUND;
        goto finish;
    }

    if (res.count == 0) {
        *errnop = ETIMEDOUT;
        *h_errnop = HOST_NOT_FOUND;
        status = NSS_STATUS_NOTFOUND;
        goto finish;
    }

    /* Alias names */
    *((char**) buffer) = NULL;
    result->h_aliases = (char**) buffer;
    idx = sizeof(char*);

    /* Official name */
    strcpy (buffer + idx, name);
    result->h_name = buffer + idx;
    idx += strlen(name) + 1;

    ALIGN(idx);

    addrlen = (res.af == AF_INET) ? sizeof(struct in_addr) : sizeof(struct in6_addr);

    result->h_addrtype = af;
    result->h_length = addrlen;

    /* Check if there's enough space for the addresses */
    if (buflen < (idx + (res.count * addrlen) + sizeof(char*) * (res.count + 1)))
    {
        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        status = NSS_STATUS_TRYAGAIN;
        goto finish;
    }

    /* Addresses */
    astart = idx;

    if (res.count) {
        memcpy(buffer + astart, &res.data, res.count * addrlen);
    }

    /* addrlen is a multiple of 32bits, so idx is still aligned correctly */
    idx += res.count * addrlen;

    /* Address array addrlen is always a multiple of 32bits */
    for (size_t i = 0; i < res.count; i++) {
        ((char**) (buffer + idx))[i] = buffer + astart + addrlen * i;
    }

    ((char**) (buffer + idx))[res.count] = NULL;
    result->h_addr_list = (char**) (buffer + idx);

    status = NSS_STATUS_SUCCESS;

finish:
    return status;
}

/**
 * The gethostbyname hook executed by nsswitch
 *
 * @param name the name to resolve
 * @param result the result hostent
 * @param buffer the result buffer
 * @param buflen length of the buffer
 * @param errnop[out] the low-level error code to return to the application
 * @param h_errnop idk
 * @return a nss_status code
 */
enum nss_status
_nss_kadnode_gethostbyname_r(const char *name,
                            struct hostent *result,
                            char *buffer,
                            size_t buflen,
                            int *errnop,
                            int *h_errnop)
{
    return _nss_kadnode_gethostbyname2_r(name,
                                        AF_UNSPEC,
                                        result,
                                        buffer,
                                        buflen,
                                        errnop,
                                        h_errnop);
}

/**
 * The gethostbyaddr hook executed by nsswitch
 * We can't do this so we always return NSS_STATUS_UNAVAIL
 *
 * @param addr the address to resolve
 * @param len the length of the address
 * @param af the address family of the address
 * @param result the result hostent
 * @param buffer the result buffer
 * @param buflen length of the buffer
 * @param errnop[out] the low-level error code to return to the application
 * @param h_errnop idk
 * @return NSS_STATUS_UNAVAIL
 */
enum nss_status
_nss_kadnode_gethostbyaddr_r (const void* addr,
                                int len,
                                int af,
                                struct hostent *result,
                                char *buffer,
                                size_t buflen,
                                int *errnop,
                                int *h_errnop)
{
    *errnop = EINVAL;
    *h_errnop = NO_RECOVERY;
    //NOTE we allow to leak this into DNS so no NOTFOUND
    return NSS_STATUS_UNAVAIL;
}

#ifdef __FreeBSD__
static NSS_METHOD_PROTOTYPE(__nss_compat_gethostbyname2_r);

static ns_mtab methods[] = {
    { NSDB_HOSTS, "gethostbyname_r", __nss_compat_gethostbyname2_r, NULL },
    { NSDB_HOSTS, "gethostbyname2_r", __nss_compat_gethostbyname2_r, NULL },
};

ns_mtab *nss_module_register(const char *source, unsigned int *mtabsize, nss_module_unregister_fn *unreg) {
    *mtabsize = sizeof(methods) / sizeof(methods[0]);
    *unreg = NULL;
    return methods;
}

int __nss_compat_gethostbyname2_r(void *retval, void *mdata, va_list ap) {
    int s;
    const char *name;
    int af;
    struct hostent *hptr;
    char *buffer;
    size_t buflen;
    int *errnop;
    int *h_errnop;

    name = va_arg(ap, const char*);
    af = va_arg(ap, int);
    hptr = va_arg(ap, struct hostent*);
    buffer = va_arg(ap, char*);
    buflen = va_arg(ap, size_t);
    errnop = va_arg(ap, int*);
    h_errnop = va_arg(ap, int*);

    s = _nss_kadnode_gethostbyname2_r(name, af, hptr, buffer, buflen, errnop, h_errnop);
    *(struct hostent**) retval = (s == NS_SUCCESS) ? hptr : NULL;

    return __nss_compat_result(s, *errnop);
}
#endif
