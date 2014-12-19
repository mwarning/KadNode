
#ifndef _MAIN_H_
#define _MAIN_H_

#include <netinet/in.h>

#define MAIN_SRVNAME "kadnode"
#define MAIN_VERSION "1.0.0"
#define SHA1_BIN_LENGTH 20
#define SHA1_HEX_LENGTH (2 * SHA1_BIN_LENGTH)

/* Default addresses and ports */
#define DHT_ADDR4_MCAST "239.192.202.7"
#define DHT_ADDR6_MCAST "ff08:ca:07::"
#define DHT_PORT_MCAST "6771"
#define DHT_ADDR4 "0.0.0.0"
#define DHT_ADDR6 "::"
#define DHT_PORT "6881"

#define CMD_PORT "1700"
#define DNS_PORT "5353"
#define NSS_PORT "4053"
#define WEB_PORT "8053"

#define QUERY_TLD_DEFAULT ".p2p"
#define QUERY_MAX_SIZE 512

typedef unsigned char UCHAR;
typedef struct sockaddr_storage IP;
typedef struct sockaddr_in IP4;
typedef struct sockaddr_in6 IP6;

#endif /* _MAIN_H_ */
