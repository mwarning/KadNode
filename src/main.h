
#ifndef _MAIN_H_
#define _MAIN_H_


#define PROGRAM_NAME "kadnode"
#define PROGRAM_VERSION "2.4.1"

#define ID_BINARY_LENGTH 20
#define ID_BASE16_LENGTH 40
#define ID_BASE32_LENGTH 32

// Default addresses and ports
#define LPD_ADDR4 "239.192.152.143"
#define LPD_ADDR6 "ff15::efc0:988f"
#define CMD_PATH "/tmp/kadnode/kadnode_cmd.sock"
#define NSS_PATH "/tmp/kadnode/kadnode_nss.sock"
#define LPD_PORT 6771
#define DHT_PORT 6881
#define DNS_PORT 3535

#define QUERY_TLD_DEFAULT "p2p"
#define QUERY_MAX_SIZE 256

void main_setup(void);
void main_free(void);


#endif // _MAIN_H_
