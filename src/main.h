
#ifndef _MAIN_H_
#define _MAIN_H_

#include <signal.h>

#define MAIN_SRVNAME "kadnode"
#define MAIN_VERSION "0.1"
#define SHA_DIGEST_LENGTH 20

/* Default addresses and ports */
#define DHT_ADDR4_MCAST "239.0.0.1"
#define DHT_ADDR6_MCAST "ff0e::1"
#define DHT_ADDR4 "0.0.0.0"
#define DHT_ADDR6 "::"
#define DHT_PORT "8337"

#define CMD_PORT "1704"
#define DNS_PORT "3444"
#define NSS_PORT "5555"
#define WEB_PORT "8080"

#include <netinet/in.h>

typedef unsigned char UCHAR;
typedef struct sockaddr_storage IP;
typedef struct sockaddr_in IP4;
typedef struct sockaddr_in6 IP6;


#endif /* _MAIN_H_ */
