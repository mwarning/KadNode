
#ifndef _UTILS_H_
#define _UTILS_H_

#include <sys/time.h>


// Number of elements in an array
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// Typical min/max methods
#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

// Make a symbol into a string literal
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

// IPv6 address length including port, e.g. [::1]:12345
#define FULL_ADDSTRLEN (INET6_ADDRSTRLEN + 8)

// Direct access to time in seconds
#define time_now_sec() (gconf->time_now)


int hex_get_id( uint8_t id[], size_t len, const char query[] );

int is_suffix( const char str[], const char suffix[] );

int query_sanitize( char buf[], size_t buflen, const char query[] );

int port_random( void );
int port_parse( const char pstr[], int err );
int port_set( IP *addr, uint16_t port );

int bytes_random( uint8_t buffer[], size_t size );
void bytes_from_hex( uint8_t bin[], const char hex[], size_t length );
char *bytes_to_hex( char hex[], const uint8_t bin[], size_t length );

int id_equal( const uint8_t id1[], const uint8_t id2[] );

int str_isHex( const char str[], size_t size );
int str_isValidHostname( const char hostname[] );

const char *str_af( int af );
const char *str_id( const uint8_t id[] );
const char *str_addr( const IP *addr );

int addr_is_localhost( const IP *addr );
int addr_is_multicast( const IP *addr );
int addr_parse( IP *addr, const char addr_str[], const char port_str[], int af );
int addr_parse_full( IP *addr, const char full_addr_str[], const char default_port[], int af );
int addr_port( const IP *addr );
int addr_len( const IP *addr );
int addr_equal( const IP *addr1, const IP *addr2 );

int socket_addr( int sock, IP *addr );

time_t time_add_secs( uint32_t seconds );
time_t time_add_mins( uint32_t minutes );
time_t time_add_hours( uint32_t hours );

#endif // _UTILS_H_
