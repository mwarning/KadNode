
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


/*
* Parse/Resolve an IP address.
* The port must be specified separately.
*/
int _nss_kadnode_addr_parse( IP *addr, const char addr_str[], const char port_str[], int af ) {
	struct addrinfo hints;
	struct addrinfo *info = NULL;
	struct addrinfo *p = NULL;

	memset( &hints, '\0', sizeof(struct addrinfo) );
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = af;

	if( getaddrinfo( addr_str, port_str, &hints, &info ) != 0 ) {
		return -2;
	}

	p = info;
	while( p != NULL ) {
		if( p->ai_family == AF_INET6 ) {
			memcpy( addr, p->ai_addr, sizeof(IP6) );
			freeaddrinfo( info );
			return 0;
		}
		if( p->ai_family == AF_INET ) {
			memcpy( addr, p->ai_addr, sizeof(IP4) );
			freeaddrinfo( info );
			return 0;
		}
	}

	freeaddrinfo( info );
	return -3;
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
	IP sockaddr;
	socklen_t addrlen;
	int sockfd, size;
	struct timeval tv;

	if( _nss_kadnode_addr_parse( &sockaddr, "localhost", NSS_PORT, AF_UNSPEC ) < 0 ) {
		return 0;
	}

	/* Setup UDP socket */
	if( (sockfd = socket( sockaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP )) < 0 ) {
		return 0;
	}

	/* Set receive timeout to 0.1 seconds */
	tv.tv_sec = 0;
	tv.tv_usec = 100000;
	if( setsockopt( sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval) ) < 0 ) {
		return 0;
	}

	addrlen = _nss_kadnode_addr_len( &sockaddr );
	size = sendto( sockfd, hostname, hostlen, 0, (struct sockaddr *)&sockaddr, addrlen );
	if( size != hostlen ) {
		return 0;
	}

	size = recvfrom( sockfd, addrs, MAX_ADDRS * sizeof(IP), 0, (struct sockaddr *)&sockaddr, &addrlen );

	if( size > 0 && (size % sizeof(IP)) == 0 ) {
		/* Return number of addresses */
		return (size / sizeof(IP));
	} else {
		return 0;
	}
}

int _nss_kadnode_valid_hostname( const char hostname[], int hostlen ) {
	size_t i;

	if( hostlen < 0 || hostlen > 300 ) {
		return 0;
	}

	for( i = 0; i < hostlen; i++ ) {
		const char c = hostname[i];
		if( (c >= '0' && c <= '9')
				|| (c >= 'A' && c <= 'Z')
				|| (c >= 'a' && c <= 'z')
				|| (c == '-')
				|| (c == '_')
				|| (c == '.') ) {
			continue;
		} else {
			return 0;
		}
	}

	return 1;
}

#ifndef __FreeBSD__
enum nss_status _nss_kadnode_gaih_addrtuple(
	const char *hostname, int hostlen, struct gaih_addrtuple **pat,
	char *buf, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp ) {

	IP addrs[MAX_ADDRS];
	char *p_name;
	char *p_idx;
	struct gaih_addrtuple *p_tuple;
	struct gaih_addrtuple *p_start;
	int addrsnum;
	int addrlen;
	int af;
	int i;

	if( !_nss_kadnode_valid_hostname( hostname, hostlen ) ) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}

	memset( addrs, '\0', sizeof(addrs) );
	if( (addrsnum = _nss_kadnode_lookup( hostname, hostlen, addrs )) <= 0 ) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	} else if( addrs[0].ss_family == AF_INET6 ) {
		af = AF_INET6;
		addrlen = sizeof(struct in6_addr);
	} else {
		af = AF_INET;
		addrlen = sizeof(struct in_addr);
	}

	/* Check upper bound */
	if( buflen < ((hostlen + 1) + sizeof(char*) + (addrsnum * sizeof(struct gaih_addrtuple))) ) {
		*errnop = ENOMEM;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_TRYAGAIN;
	}

	memset( buf, '\0', buflen );

	/* Hostname */
	p_name = buf;
	memcpy( p_name, hostname, hostlen );

	/* Object */
	p_idx = p_name + hostlen + 1;
	p_start = (struct gaih_addrtuple*) p_idx;
	for( i = 0; i < addrsnum; i++ ) {
		p_tuple = (struct gaih_addrtuple*) p_idx;
		p_tuple->name = p_name;
		p_tuple->family = af;
		if( af == AF_INET6 ) {
			memcpy( p_tuple->addr, &((IP6 *)&addrs[i])->sin6_addr, addrlen );
		} else {
			memcpy( p_tuple->addr, &((IP4 *)&addrs[i])->sin_addr, addrlen );
		}
		p_tuple->scopeid = 0;

		/* Linked list */
		if( i == addrsnum - 1 ) {
			p_tuple->next = NULL;
		} else {
			p_tuple->next = (struct gaih_addrtuple*)
			(p_idx + sizeof(struct gaih_addrtuple));
		}

		p_idx += sizeof(struct gaih_addrtuple);
	}

	*pat = p_start;

	if( ttlp != NULL ) {
		*ttlp = 0;
	}

	return NSS_STATUS_SUCCESS;
}
#endif

enum nss_status _nss_kadnode_hostent(
		const char *hostname, int af, struct hostent *host,
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

	if( !_nss_kadnode_valid_hostname( hostname, hostlen ) ) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}

	memset( addrs, '\0', sizeof(addrs) );
	if( (addrsnum = _nss_kadnode_lookup( hostname, hostlen, addrs )) <= 0 ) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}

	/* Check upper bound */
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

	/* Hostname */
	p_name = buf;
	memcpy( p_name, hostname, hostlen );
	p_idx = p_name + hostlen + 1;

	/* Alias */
	p_aliases = p_idx;
	*(char**) p_aliases = NULL;
	p_idx += sizeof(char*);

	/* Address data */
	p_addr = p_idx;
	for( i = 0; i < addrsnum; i++ ) {
		if( af == AF_INET6 ) {
			memcpy( p_addr, &((IP6 *)&addrs[i])->sin6_addr, addrlen );
		} else {
			memcpy( p_addr, &((IP4 *)&addrs[i])->sin_addr, addrlen );
		}
	}
	p_idx += addrsnum * addrlen;

	/* Address pointer */
	p_addr_list = p_idx;
	p_idx = p_addr;
	for( i = 0; i < addrsnum; i++ ) {
		((char**) p_addr_list)[i] = p_idx;
		p_idx += addrlen;
	}
	((char**) p_addr_list)[addrsnum] = NULL;

	host->h_name = p_name;
	host->h_aliases = (char**) p_aliases;
	host->h_addrtype = af;
	host->h_length = addrlen;
	host->h_addr_list = (char**) p_addr_list;

	if( ttlp != NULL ) {
		*ttlp = 0;
	}

	if( canonp != NULL ) {
		*canonp = p_name;
	}

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_kadnode_gethostbyname_r(
		const char *hostname, struct hostent *host,
		char *buf, size_t buflen, int *errnop, int *h_errnop ) {

	return _nss_kadnode_hostent( hostname, AF_INET6, host,
		buf, buflen, errnop, h_errnop, NULL, NULL );
}

enum nss_status _nss_kadnode_gethostbyname2_r(
		const char *hostname, int af, struct hostent *host,
		char *buf, size_t buflen, int *errnop, int *h_errnop ) {

	return _nss_kadnode_hostent( hostname, af, host,
		buf, buflen, errnop, h_errnop, NULL, NULL );
}

#ifndef __FreeBSD__
enum nss_status _nss_kadnode_gethostbyname3_r(
		const char *hostname, int af, struct hostent *host,
		char *buf, size_t buflen, int *errnop,  int *h_errnop,
		int32_t *ttlp, char **canonp ) {

	return _nss_kadnode_hostent( hostname, af, host,
		buf, buflen, errnop, h_errnop, ttlp, canonp );
}

enum nss_status _nss_kadnode_gethostbyname4_r(
	const char *hostname, struct gaih_addrtuple **pat,
	char *buf, size_t buflen, int *errnop,
	int *h_errnop, int32_t *ttlp ) {

	return _nss_kadnode_gaih_addrtuple(
		hostname, strlen( hostname ), pat,
		buf, buflen, errnop, h_errnop, ttlp );
}
#endif

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
