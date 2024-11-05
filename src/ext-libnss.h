
#ifndef _EXT_LIBNSS_H_
#define _EXT_LIBNSS_H_

#include <nss.h>
#include <netdb.h> // for struct hostent
#include <netinet/in.h>

#define MAX_ENTRIES 16

struct kadnode_nss_request
{
    int af;
    char name[QUERY_MAX_SIZE];
};

struct kadnode_nss_response
{
    int af;
    int count;
    union {
        struct in_addr ipv4[MAX_ENTRIES];
        struct in6_addr ipv6[MAX_ENTRIES];
    } data;
};

enum nss_status
_nss_kadnode_gethostbyname2_r(const char *name,
    int af,
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop);

enum nss_status
_nss_kadnode_gethostbyname_r(const char *name,
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop);

enum nss_status
_nss_kadnode_gethostbyaddr_r(const void* addr,
    int len,
    int af,
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop);

#endif // _EXT_LIBNSS_H_
