
#ifndef _EXT_LIBNSS_H_
#define _EXT_LIBNSS_H_

#include <nss.h>
#include <netdb.h> // for struct hostent
#include <netinet/in.h>
#include <stdbool.h>

#include "main.h"

// Maximum number of entries to return.
#define MAX_ENTRIES 16

typedef struct {
    int af;
    bool allow_mixed_af;
    char name[QUERY_MAX_SIZE];
} kadnode_nss_request_t;

typedef struct {
    uint32_t address;
} ipv4_address_t;

typedef struct {
    uint8_t address[16];
} ipv6_address_t;

typedef struct {
    int af;
    union {
        ipv4_address_t ipv4;
        ipv6_address_t ipv6;
    } address;
    uint32_t scopeid;
} query_address_result_t;

typedef struct {
    int count;
    query_address_result_t result[MAX_ENTRIES];
} kadnode_nss_response_t;

// Define prototypes for nss function we're going to export (fixes GCC warnings)
#ifndef __FreeBSD__
enum nss_status _nss_kadnode_gethostbyname4_r(const char*, struct gaih_addrtuple**,
                                           char*, size_t, int*, int*, int32_t*);
#endif
enum nss_status _nss_kadnode_gethostbyname3_r(const char*, int, struct hostent*,
                                           char*, size_t, int*, int*, int32_t*,
                                           char**);
enum nss_status _nss_kadnode_gethostbyname2_r(const char*, int, struct hostent*,
                                           char*, size_t, int*, int*);
enum nss_status _nss_kadnode_gethostbyname_r(const char*, struct hostent*, char*,
                                          size_t, int*, int*);

#endif // _EXT_LIBNSS_H_
