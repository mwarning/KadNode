
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <nss.h>

#ifdef __FreeBSD__
#include <nsswitch.h>
#include <stdarg.h>
#include <sys/param.h>
#endif

#include "main.h"

#define MAX_ADDRS 32

static int g_sock = -1;
static IP g_sockaddr = { 0 };


int _nss_kadnode_init() {
	struct timeval tv;
	const int opt_on = 1;

	// Setup ::1 address
	memcpy( &((IP6*) &g_sockaddr)->sin6_addr, &in6addr_loopback, sizeof(IP6));
	((IP6*) &g_sockaddr)->sin6_family = AF_INET6;
	((IP6*) &g_sockaddr)->sin6_port = htons(NSS_PORT);

	// Setup UDP socket
	if( (g_sock = socket( g_sockaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP )) < 0 ) {
		return 0;
	}

	// Set receive timeout to 0.1 seconds
	tv.tv_sec = 0;
	tv.tv_usec = 100000;

	if( setsockopt( g_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval) ) < 0 ) {
		goto error;
	}

	if( setsockopt( g_sock, SOL_SOCKET, SO_REUSEADDR, &opt_on, sizeof(opt_on) ) < 0 ) {
		goto error;
	}

	return 1;

error:
	close(g_sock);
	g_sock = -1;

	return 0;
}

int _nss_kadnode_addr_len( const IP *addr ) {
	switch( addr->ss_family ) {
		case AF_INET:
			return sizeof(IP4);
		case AF_INET6:
			return sizeof(IP6);
		default:
			return 0;
	}
}

int _nss_kadnode_lookup( const char hostname[], int hostlen, IP addrs[] ) {
	socklen_t addrlen;
	IP clientaddr;
	int size;

	if( g_sock < 0 ) {
		if( !_nss_kadnode_init() ) {
			// Socket setup failed
			return 0;
		}
	}

	addrlen = _nss_kadnode_addr_len( &g_sockaddr );
	size = sendto( g_sock, hostname, hostlen, 0, (struct sockaddr *)&g_sockaddr, addrlen );
	if( size != hostlen ) {
		return 0;
	}

	size = recvfrom( g_sock, addrs, MAX_ADDRS * sizeof(IP), 0, (struct sockaddr *)&clientaddr, &addrlen );

	if( size > 0 ) {
		// Return number of addresses
		return (size / sizeof(IP));
	} else {
		return -1;
	}
}

enum nss_status _nss_kadnode_hostent(
		const char *hostname, int af, struct hostent *result,
		char *buf, size_t buflen, int *errnop,
		int *h_errnop, int32_t *ttlp, char **canonp ) {

	IP addrs[MAX_ADDRS];
	char *p_addr;
	char *p_name;
	char *p_aliases;
	char *p_addr_list;
	char *p_idx;
	int addrlen;
	int hostlen;
	int addrsnum;
	int i;

	hostlen = strlen( hostname );

	if( af != AF_INET6 && af != AF_INET ) {
		*errnop = EAFNOSUPPORT;
		*h_errnop = NO_DATA;
		return NSS_STATUS_UNAVAIL;
	}

	memset( addrs, '\0', sizeof(addrs) );
	addrsnum = _nss_kadnode_lookup( hostname, hostlen, addrs );
	if( addrsnum < 0 ) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_UNAVAIL;
	} else if( addrsnum == 0 ) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}

	// Check upper bound
	if( buflen < ((hostlen + 1) + sizeof(char*) + (addrsnum * sizeof(struct in6_addr)) + (addrsnum + 1) * sizeof(char*)) ) {
		*errnop = ENOMEM;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_TRYAGAIN;
	} else if( addrs[0].ss_family == AF_INET6 ) {
		af = AF_INET6;
		addrlen = sizeof(struct in6_addr);
	} else {
		af = AF_INET;
		addrlen = sizeof(struct in_addr);
	}

	memset( buf, '\0', buflen );

	// Hostname
	p_name = buf;
	memcpy( p_name, hostname, hostlen );
	p_idx = p_name + hostlen + 1;

	// Alias
	p_aliases = p_idx;
	*(char**) p_aliases = NULL;
	p_idx += sizeof(char*);

	// Address data
	p_addr = p_idx;
	for( i = 0; i < addrsnum; i++ ) {
		if( af == AF_INET6 ) {
			memcpy( p_addr, &((IP6 *)&addrs[i])->sin6_addr, addrlen );
		} else {
			memcpy( p_addr, &((IP4 *)&addrs[i])->sin_addr, addrlen );
		}
	}
	p_idx += addrsnum * addrlen;

	// Address pointer
	p_addr_list = p_idx;
	p_idx = p_addr;
	for( i = 0; i < addrsnum; i++ ) {
		((char**) p_addr_list)[i] = p_idx;
		p_idx += addrlen;
	}
	((char**) p_addr_list)[addrsnum] = NULL;

	result->h_name = p_name;
	result->h_aliases = (char**) p_aliases;
	result->h_addrtype = af;
	result->h_length = addrlen;
	result->h_addr_list = (char**) p_addr_list;

	if( ttlp != NULL ) {
		*ttlp = 0;
	}

	if( canonp != NULL ) {
		*canonp = p_name;
	}

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_kadnode_gethostbyname_r(
		const char *hostname, struct hostent *result,
		char *buf, size_t buflen, int *errnop, int *h_errnop ) {

	return _nss_kadnode_hostent( hostname, AF_INET6, result,
		buf, buflen, errnop, h_errnop, NULL, NULL );
}

enum nss_status _nss_kadnode_gethostbyname2_r(
		const char *hostname, int af, struct hostent *result,
		char *buf, size_t buflen, int *errnop, int *h_errnop ) {

	return _nss_kadnode_hostent( hostname, af, result,
		buf, buflen, errnop, h_errnop, NULL, NULL );
}

enum nss_status _nss_kadnode_gethostbyname3_r(
		const char *hostname, int af, struct hostent *result,
		char *buf, size_t buflen, int *errnop,  int *h_errnop,
		int32_t *ttlp, char **canonp ) {

	return _nss_kadnode_hostent( hostname, af, result,
		buf, buflen, errnop, h_errnop, ttlp, canonp );
}

enum nss_status _nss_kadnode_gethostbyaddr_r(
	const void* addr, int len, int af,
	struct hostent *result, char *buf, size_t buflen,
	int *errnop, int *h_errnop) {

	*errnop = EINVAL;
	*h_errnop = NO_RECOVERY;

	return NSS_STATUS_UNAVAIL;
}

#ifdef __FreeBSD__
static NSS_METHOD_PROTOTYPE(__nss_compat_gethostbyname2_r);

static ns_mtab methods[] = {
	{ NSDB_HOSTS, "gethostbyname_r", __nss_compat_gethostbyname2_r, NULL },
	{ NSDB_HOSTS, "gethostbyname2_r", __nss_compat_gethostbyname2_r, NULL },
};

ns_mtab *nss_module_register( const char *source, unsigned int *mtabsize, nss_module_unregister_fn *unreg ) {
	*mtabsize = sizeof(methods) / sizeof(methods[0]);
	*unreg = NULL;
	return methods;
}

int __nss_compat_gethostbyname2_r( void *retval, void *mdata, va_list ap ) {
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

	s = _nss_kadnode_gethostbyname2_r( name, af, hptr, buffer, buflen, errnop, h_errnop );
	*(struct hostent**) retval = (s == NS_SUCCESS) ? hptr : NULL;

	return __nss_compat_result(s, *errnop);
}
#endif
