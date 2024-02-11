
#ifndef _UTILS_H_
#define _UTILS_H_

#include <sys/time.h>
#include <stdbool.h>


// Number of elements in an array
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// Size of a struct element
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))

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

typedef struct {
	const char *name;
	uint16_t num_args;
	uint16_t code;
} option_t;

const option_t *find_option(const option_t options[], const char name[]);
int setargs(const char **argv, int argv_size, char *args);

int parse_int(const char *s, int err);

bool parse_id(uint8_t id[], size_t idsize, const char query[], size_t querysize);
bool hex_get_id(uint8_t id[], size_t idsize, const char query[]); // TODO: remove

bool parse_annoucement(uint8_t id[], int *port, const char query[], int default_port);
bool is_announcement(const char query[]); // "<hex-id>[:<port>]"

bool bytes_from_base32(uint8_t dst[], size_t dstsize, const char src[], size_t srcsize);
char *bytes_to_base32(char dst[], size_t dstsize, const uint8_t src[], size_t srcsize);
bool bytes_from_base16(uint8_t dst[], size_t dstsize, const char src[], size_t srcsize);
char *bytes_to_base16(char dst[], size_t dstsize, const uint8_t src[], size_t srcsize);

int port_random(void);
bool port_valid(int port);
int port_parse(const char pstr[], int err); // TODO: remove
bool port_set(IP *addr, uint16_t port);

bool has_tld(const char str[], const char tld[]);
bool query_sanitize(char buf[], size_t buflen, const char query[]);
bool bytes_random(uint8_t buffer[], size_t size);
bool id_equal(const uint8_t id1[], const uint8_t id2[]);

const char *str_af(int af);
const char *str_id(const uint8_t id[]);
const char *str_addr(const IP *addr);
const char *str_addr2(const void *ip, uint8_t length, uint16_t port);

bool addr_is_localhost(const IP *addr);
bool addr_is_multicast(const IP *addr);
bool addr_parse(IP *addr, const char full_addr_str[], const char default_port[], int af);
int addr_port(const IP *addr);
int addr_len(const IP *addr);
bool addr_equal(const IP *addr1, const IP *addr2);

bool socket_addr(int sock, IP *addr);

time_t time_add_secs(uint32_t seconds);
time_t time_add_mins(uint32_t minutes);
time_t time_add_hours(uint32_t hours);

#endif // _UTILS_H_
