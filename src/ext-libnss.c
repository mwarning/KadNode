
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <nss.h>
#include <netdb.h> 
#include <sys/socket.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <unistd.h>

#include "main.h"
#include "ext-libnss.h"


enum nss_status _nss_kadnode_gethostbyname_r(const char *name,
        struct hostent *result, char *buf, size_t buflen,
        int *errnop, int *h_errnop ) {

	return _nss_kadnode_gethostbyname_impl( name, AF_UNSPEC, result,
		buf, buflen, errnop, h_errnop );
}

enum nss_status _nss_kadnode_gethostbyname2_r(const char *name, int af,
        struct hostent *result, char *buf, size_t buflen,
        int *errnop, int *h_errnop ) {

	return _nss_kadnode_gethostbyname_impl( name, af, result,
		buf, buflen, errnop, h_errnop );
}

enum nss_status _nss_kadnode_gethostbyname_impl(
		const char *hostname, int af, struct hostent *result,
		char *buffer, size_t buflen, int *errnop,
		int *h_errnop ) {
	IP addr;
	char *p_addr;
	char *p_name;
	char *p_aliases;
	char *p_addr_list;
	char *p_idx;
	int addrlen;
	int size;

	size = strlen( hostname );
	af = (af == AF_UNSPEC) ? AF_INET6 : af;

	if( af != AF_INET6 && af != AF_INET ) {
		*errnop = EAFNOSUPPORT;
		*h_errnop = NO_DATA;
		return NSS_STATUS_UNAVAIL;
	}

	if( !_nss_kadnode_valid_hostname( hostname, size ) ) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}

	if( !_nss_kadnode_valid_tld( hostname, size ) ) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}

	if( buflen < (size + 1 + sizeof(char*) + sizeof(struct in6_addr) + 2 * sizeof(char*)) ) {
		*errnop = ENOMEM;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_TRYAGAIN;
	}

	if( !_nss_kadnode_lookup( hostname, size, &addr ) ) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}

	memset( buffer, '\0', buflen );
	p_name = buffer;
	memcpy( p_name, hostname, size );
	p_idx = p_name + size + 1;

	p_aliases = p_idx;
	*(char**) p_aliases = NULL;
	p_idx += sizeof(char*);

	p_addr = p_idx;
	if( addr.ss_family == AF_INET6 ) {
		addrlen = sizeof(struct in6_addr);
		memcpy( p_addr, &((IP6 *)&addr)->sin6_addr, addrlen );
	} else {
		addrlen = sizeof(struct in_addr);
		memcpy( p_addr, &((IP4 *)&addr)->sin_addr, addrlen );
	}
	p_idx += addrlen;

	p_addr_list = p_idx;
	((char**) p_addr_list)[0] = p_addr;
	((char**) p_addr_list)[1] = NULL;
	p_idx += 2 * sizeof(char*);

	result->h_name = p_name;
	result->h_aliases = (char**) p_aliases;
	result->h_addrtype = addr.ss_family;
	result->h_length = addrlen;
	result->h_addr_list = (char**) p_addr_list;

	return NSS_STATUS_SUCCESS;
}

int _nss_kadnode_valid_hostname( const char *hostname, int size ) {
	int i;

	for( i = 0; i < size; i++ ) {
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

int _nss_kadnode_valid_tld( const char *hostname, int size ) {
	int i;
	char *tld;

	/* Get the last '.' */
	tld = strrchr( hostname, '.' );
	if( tld == NULL ) {
		return 0;
	} else {
		tld++;
	}

	for( i = 0; i < (sizeof(domains) / sizeof(char*)); ++i ) {
		/* Check if the TLD is listed */
		if( strcmp( tld, domains[i] ) == 0 ) {
			return 1;
		}
	}

	return 0;
}

int _nss_kadnode_lookup( const char *hostname, int size, IP *addr ) {

	IP6 sockaddr;
	socklen_t addrlen;
	char buffer[128];
	int sockfd, n;
	struct timeval tv;

	addrlen = sizeof(IP6);
	memset( &sockaddr, '\0', addrlen );
	memset( buffer, '\0', sizeof(buffer) );

	/* Setup UDP */
	sockfd = socket( AF_INET6, SOCK_DGRAM, 0 );
	if( sockfd < 0 ) {
		return 0;
	}

	/* Set receive timeout to 0.5 seconds */
	tv.tv_sec = 0;
	tv.tv_usec = 500000;
	if( setsockopt( sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval) ) < 0 ) {
		return 0;
	}

	/* Setup IPv6 */
	sockaddr.sin6_family = AF_INET6;
	sockaddr.sin6_port = htons( atoi( NSS_PORT ) );
	if( !inet_pton( AF_INET6, "::1", &sockaddr.sin6_addr ) ) {
		return 0;
	}

	n = sendto( sockfd, hostname, size, 0, (struct sockaddr *)&sockaddr, addrlen );
	if( n != size ) {
		return 0;
	}

	n = recvfrom( sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sockaddr, &addrlen );

	if( n == sizeof(IP) ) {
		/* Got result. */
		memcpy( addr, buffer, sizeof(IP) );
		return 0;
	} else {
		return -1;
	}
}
