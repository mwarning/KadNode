
#ifndef _MAIN_H_
#define _MAIN_H_

#include <signal.h>

#define MAIN_SRVNAME "kadnode"
#define MAIN_VERSION "0.4"
#define SHA_DIGEST_LENGTH 20

/* Default addresses and ports */
#define DHT_ADDR4_MCAST "239.192.202.7"
#define DHT_ADDR6_MCAST "ff08:ca:07::"
#define DHT_ADDR4 "0.0.0.0"
#define DHT_ADDR6 "::"
#define DHT_PORT "6881"

#define CMD_PORT "1700"
#define DNS_PORT "5353"
#define NSS_PORT "4053"
#define WEB_PORT "8053"

#include <netinet/in.h>

typedef unsigned short USHORT;
typedef unsigned char UCHAR;
typedef struct sockaddr_storage IP;
typedef struct sockaddr_in IP4;
typedef struct sockaddr_in6 IP6;


#endif /* _MAIN_H_ */
