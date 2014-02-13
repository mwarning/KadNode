
#ifndef _EXT_LIBNSS_H_
#define _EXT_LIBNSS_H_

#define _public_ __attribute__( ( visibility( "default")))
#define _hidden_ __attribute__( ( visibility( "hidden")))

#define MAIN_BUF 1024
#define SHA1_BIN_LENGTH 20

/*
* For a domain name to be handled by the KadNode NSS module
* it must have one of the top level domains (TLDs) listed below.
*
* KadNode itself will ignore any top level domain.
* A request for 'http://me.name.p2p' will result in
* KadNode to try to resolve the sha1 hash of 'me.name'.
*/

/* Accepted TLDs */
const char *domains[] = { "p2p" };


enum nss_status _nss_kadnode_gethostbyname_r(
	const char *hostname, struct hostent *host,
	char *buffer, size_t buflen, int *errnop,
	int *h_errnop ) _public_;

enum nss_status _nss_kadnode_gethostbyname2_r(
	const char *hostname, int af, struct hostent *host,
	char *buffer, size_t buflen, int *errnop,
	int *h_errnop ) _public_;

enum nss_status _nss_kadnode_gethostbyname3_r(
	const char *hostname, int af, struct hostent *host,
	char *buf, size_t buflen, int *errnop,
	int *h_errnop, int32_t *ttlp, char **canonp ) _public_;

enum nss_status _nss_kadnode_gethostbyname_impl(
	const char *hostname, int af, struct hostent *host,
	char *buffer, size_t buflen, int *errnop,
	int *h_errnop, int32_t *ttlp, char **canonp ) _public_;

int _nss_kadnode_valid_tld( const char *hostname, int hostlen );
int _nss_kadnode_valid_hostname( const char *hostname, int hostlen );

int _nss_kadnode_lookup( const char *hostname, int size, IP addr[] );

#endif /* _EXT_LIBNSS_H_ */
