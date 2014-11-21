
#ifndef _EXT_LIBNSS_H_
#define _EXT_LIBNSS_H_

#define _public_ __attribute__( ( visibility( "default")))
#define _hidden_ __attribute__( ( visibility( "hidden")))

#define MAIN_BUF 1024
#define SHA1_BIN_LENGTH 20

/*
* For a domain name to be handled by the KadNode NSS module
* it must have the .p2p top level domains.
*
* A request for 'http://my.name.p2p' will result in
* KadNode to try to resolve the identifier 'my.name'.
*/

enum nss_status _nss_kadnode_gethostbyname_r(
	const char *hostname, struct hostent *host,
	char *buffer, size_t buflen, int *errnop,
	int *h_errnop ) _public_;

enum nss_status _nss_kadnode_gethostbyname2_r(
	const char *hostname, int af, struct hostent *host,
	char *buffer, size_t buflen, int *errnop,
	int *h_errnop ) _public_;

#ifndef __FreeBSD__
enum nss_status _nss_kadnode_gethostbyname3_r(
	const char *hostname, int af, struct hostent *host,
	char *buf, size_t buflen, int *errnop,
	int *h_errnop, int32_t *ttlp, char **canonp ) _public_;

enum nss_status _nss_kadnode_gethostbyname4_r(
	const char *hostname, struct gaih_addrtuple **pat,
	char *buffer, size_t buflen, int *errnop,
	int *h_errnop, int32_t *ttlp ) _public_;
#endif

#endif /* _EXT_LIBNSS_H_ */
