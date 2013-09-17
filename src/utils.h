
#ifndef _UTILS_H_
#define _UTILS_H_

#include <sys/time.h>

/* Size of a struct member */
#define M_SIZEOF(type, member) sizeof(((type*) 0)->member)

/* Number of elements in an array */
#define N_ELEMS(x)  (sizeof(x) / sizeof(x[0]))

/* Simple string match */
#define match(opt, arg) (strcmp( opt, arg ) == 0)

#define ADDR_PARSE_SUCCESS 0
#define ADDR_PARSE_INVALID_FORMAT 1
#define ADDR_PARSE_CANNOT_RESOLVE 2
#define ADDR_PARSE_NO_ADDR_FOUND 3


int id_random( void *buffer, size_t size );
void id_compute( UCHAR *id, const char *str );
void id_fromHex( UCHAR *id, const char *hex, size_t size );
int id_equal( const UCHAR *id1, const UCHAR *id2 );

int str_isHex( const char *string, int size );
int str_isValidHostname( const char *hostname, int size );
int str_isZero( const char* str );
void str_toLower( char* str, int size );

char *str_id( const UCHAR *in, char *idbuf );
char *str_addr( IP *addr, char *addrbuf );
char *str_addr4( IP4 *addr, char *addrbuf );
char *str_addr6( IP6 *addr, char *addrbuf );

int addr_parse( IP *addr, const char *addr_str, const char *port_str, int af );
int addr_parse_full( IP *addr, const char *full_addr_str, const char* default_port, int af );
int addr_port( const IP *addr );
int addr_len( const IP *addr );
int addr_equal( const IP *addr1, const IP *addr2 );

time_t time_now_sec( void );
time_t time_add_min( unsigned int min );


#endif /* _UTILS_H_ */
