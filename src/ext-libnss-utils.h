#ifndef EXT_LIBNSS_UTILS_H_
#define EXT_LIBNSS_UTILS_H_

/*
  This file is part of nss-mdns.

  nss-mdns is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2 of the
  License, or (at your option) any later version.

  nss-mdns is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with nss-mdns; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <sys/time.h>
#include <time.h>
#include <inttypes.h>
#include <netdb.h>
#include <nss.h>
#include <stdio.h>
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif
#include <resolv.h>

#include "ext-libnss.h"
//#include "avahi.h"

// Simple buffer allocator.
typedef struct {
    char* next;
    char* end;
} buffer_t;

// Sets up a buffer.
void buffer_init(buffer_t* buf, char* buffer, size_t buflen);

// Allocates a zeroed, aligned chunk of memory of a given size from the buffer
// manager.
// If there is insufficient space, returns NULL.
void* buffer_alloc(buffer_t* buf, size_t size);

// Duplicates a string into a newly allocated chunk of memory.
// If there is insufficient space, returns NULL.
char* buffer_strdup(buffer_t* buf, const char* str);

// Macro to help with checking buffer allocation results.
#define RETURN_IF_FAILED_ALLOC(ptr)                                            \
    if (ptr == NULL) {                                                         \
        *errnop = ERANGE;                                                      \
        *h_errnop = NO_RECOVERY;                                               \
        return NSS_STATUS_TRYAGAIN;                                            \
    }

// Converts from the userdata struct into the hostent format, used by
// gethostbyaddr3_r.
enum nss_status convert_userdata_for_name_to_hostent(const kadnode_nss_response_t* u,
                                                     const char* name, int af,
                                                     struct hostent* result,
                                                     buffer_t* buf, int* errnop,
                                                     int* h_errnop);

// Converts from the userdata struct into the gaih_addrtuple format, used by
// gethostbyaddr4_r.
#ifndef __FreeBSD__
enum nss_status convert_kadnode_nss_response_to_addrtuple(const kadnode_nss_response_t* u,
                                              const char* name,
                                              struct gaih_addrtuple** pat,
                                              buffer_t* buf, int* errnop,
                                              int* h_errnop);
#endif

// Appends a query_address_result to userdata.
void append_address_to_userdata(const query_address_result_t* result,
                                kadnode_nss_response_t* u);

#endif // EXT_LIBNSS_UTILS_H_
