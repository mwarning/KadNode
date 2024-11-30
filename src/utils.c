
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <limits.h>

#include "main.h"
#include "log.h"
#include "conf.h"
#include "utils.h"


// separate a string into a list of arguments (int argc, char **argv)
int setargs(const char **argv, int argv_size, char *args)
{
    int count = 0;

    // skip spaces
    while (isspace(*args)) {
        ++args;
    }

    while (*args) {
        if ((count + 1) < argv_size) {
            argv[count] = args;
        } else {
            log_error("CLI: too many arguments");
            break;
        }

        // parse word
        while (*args && !isspace(*args)) {
            ++args;
        }

        if (*args) {
            *args++ = '\0';
        }

        // skip spaces
        while (isspace(*args)) {
            ++args;
        }

        count++;
    }

    argv[MIN(count, argv_size - 1)] = NULL;

    return count;
}

const option_t *find_option(const option_t options[], const char name[])
{
    const option_t *option = options;
    while (option->name && name) {
        if (0 == strcmp(name, option->name)) {
            return option;
        }
        option++;
    }

    return NULL;
}

bool port_valid(int port)
{
    return port > 0 && port <= 65536;
}

int parse_int(const char *s, int err)
{
    char *endptr = NULL;
    const char *end = s + strlen(s);
    ssize_t n = strtoul(s, &endptr, 10);
    if (endptr != s && endptr == end && n >= INT_MIN && n < INT_MAX) {
        return n;
    } else {
        return err;
    }
}

size_t base16encsize(size_t byte_count)
{
    return byte_count * 2;
}

size_t base16decsize(size_t char_count)
{
    return (char_count + 1) / 2;
}

bool base16dec(uint8_t dst[], size_t dstsize, const char src[], size_t srcsize)
{
    size_t xv = 0;

    if (dstsize < base16decsize(srcsize)) {
        return false;
    }

    for (size_t i = 0; i < srcsize; ++i) {
        const char c = src[i];
        if (c >= '0' && c <= '9') {
            xv += c - '0';
        } else if (c >= 'a' && c <= 'f') {
            xv += (c - 'a') + 10;
        } else {
            // unknown character
            return false;
        }

        if (i % 2) {
            dst[i / 2] = xv;
            xv = 0;
        } else {
            xv *= 16;
        }
    }

    return true;
}

char *base16enc(char dst[], size_t dstsize, const uint8_t src[], size_t srcsize)
{
    static const char hexchars[16] = "0123456789abcdef";

    // + 1 for the '\0'
    if (dstsize < (base16encsize(srcsize) + 1)) {
        // destination buffer is too small
        return NULL;
    }

    for (size_t i = 0; i < srcsize; ++i) {
        dst[2 * i] = hexchars[src[i] / 16];
        dst[2 * i + 1] = hexchars[src[i] % 16];
    }

    dst[2 * srcsize] = '\0';

    return dst;
}

size_t base32encsize(size_t byte_count)
{
    size_t size = -1;
    size = byte_count << 3;
    return (size / 5) + ((size % 5) ? 1 : 0);
}

size_t base32decsize(size_t char_count)
{
    return (char_count * 5) / 8;
}

// Character map for Crockford base32, but lower case for encoding.
// 0-9a-z with 'i', 'l', 'o' and 'u' removed.
const char base32_map[33] = "0123456789abcdefghjkmnpqrstvwxyz";

bool base32dec(uint8_t *dest, int destlen, const char *src, size_t srcsize)
{
    if (destlen < base32decsize(srcsize)) {
        return false;
    }

    int destlen_bits = 8 * destlen;
    size_t out_bits = 0;
    for (size_t i = 0; i < srcsize; ++i) {
        int sym, sbits, dbits, b;
        const int c = src[i];
        for (int j = 0; j < 32; j++) {
            if (c == base32_map[j]) {
                sym = j;
                goto found;
            }
        }
        return false;  // Bad input symbol
        found:

        // Stop if we're out of space.
        if (out_bits >= destlen_bits)
            return false;
        // See how many bits we get to use from this symbol
        sbits = MIN(5, destlen_bits - out_bits);
        if (sbits < 5)
            sym >>= (5 - sbits);
        // Fill up the rest of the current byte
        dbits = 8 - (out_bits & 7);
        b = MIN(dbits, sbits);
        if (dbits == 8)
            dest[out_bits / 8] = 0;  // Starting a new byte
        dest[out_bits / 8] |= (sym << (dbits - b)) >> (sbits - b);
        out_bits += b;
        sbits -= b;
        /* Start the next byte if there's space */
        if (sbits > 0) {
            dest[out_bits / 8] = sym << (8 - sbits);
            out_bits += sbits;
        }
    }

    return true;
}

char *base32enc(char *dest, int destlen, const uint8_t *src, int srclen)
{
    int srclen_bits = srclen * 8;
    int didx = 0;
    *dest = 0;
    // Make sure the destination is big enough
    int destlen_needed = (srclen_bits + 4) / 5;  // Symbols before adding CRC
    destlen_needed++;  // For terminating null
    if (destlen < destlen_needed)
        return NULL;
    for (int i = 0; i < srclen_bits; i += 5) {
        int sym;
        int sidx = i / 8;
        int bit_offs = i % 8;
        if (bit_offs <= 3) {
            // Entire symbol fits in that byte
            sym = src[sidx] >> (3 - bit_offs);
        } else {
            // Use the bits we have left
            sym = src[sidx] << (bit_offs - 3);
            // Use the bits from the next byte, if any
            if (i + 1 < srclen_bits)
                sym |= src[sidx + 1] >> (11 - bit_offs);
        }
        sym &= 0x1f;
        // Pad incomplete symbol with 0 bits
        if (srclen_bits - i < 5)
            sym &= 0x1f << (5 + i - srclen_bits);
        dest[didx++] = base32_map[sym];
    }
    // Terminate string and return
    dest[didx] = 0;
    return dest;
}

// Check if a string has an extension.
// The ext is expected to start with a dot.
bool has_tld(const char str[], const char ext[])
{
    const char *dot = strrchr(str, '.');
    return dot && (strcmp(dot + 1, ext) == 0);
}

/*
* Sanitize a query string.
* Convert to lowercase and remove the TLD if it matches --query-tld.
*
* example.com.p2p => example.com
* example.com => example.com
* example.p2p => example
* eXample.COM.P2P => example.com
*/
bool query_sanitize(char buf[], size_t buflen, const char query[], size_t querylen)
{
    const char *tld;
    size_t i;

    if ((querylen + 1) > buflen) {
        // Output buffer too small
        return false;
    }

    memset(buf, 0, buflen);

    // Convert to a lower case
    for (i = 0; i <= querylen; ++i) {
        buf[i] = tolower(query[i]);
    }

    // Remove .p2p suffix
    tld = gconf->query_tld;
    if (has_tld(buf, tld)) {
        querylen -= 1 + strlen(tld);
        buf[querylen] = '\0';
    }

    return true;
}

// Create a random port != 0
int port_random(void)
{
    uint16_t port;

    do {
        bytes_random((uint8_t*) &port, sizeof(port));
    } while (port == 0);

    return port;
}

bool port_set(IP *addr, uint16_t port)
{
    switch (addr->ss_family) {
    case AF_INET:
        ((IP4 *)addr)->sin_port = htons(port);
        return EXIT_SUCCESS;
    case AF_INET6:
        ((IP6 *)addr)->sin6_port = htons(port);
        return EXIT_SUCCESS;
    default:
        return EXIT_FAILURE;
    }
}

bool file_exists(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (fp != NULL) {
        fclose(fp);
        return true;
    }
    return false;
}

// Fill buffer with random bytes
bool bytes_random(uint8_t buffer[], size_t size)
{
    int fd;
    int rc;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        log_error("Failed to open /dev/urandom");
        exit(1);
    }

    rc = read(fd, buffer, size);

    close(fd);

    return rc == 0;
}

bool id_equal(const uint8_t id1[], const uint8_t id2[])
{
    return (memcmp(id1, id2, ID_BINARY_LENGTH) == 0);
}

const char *str_id(const uint8_t id[])
{
    static char buf[ID_BASE32_LENGTH + 1];
    return base32enc(buf, sizeof(buf), id, ID_BINARY_LENGTH);
}

const char *str_af(int af) {
    switch (af) {
    case AF_INET:
        return "IPv4";
    case AF_INET6:
        return "IPv6";
    case AF_UNSPEC:
        return "IPv4+IPv6";
    default:
        return "<invalid>";
    }
}

const char *str_addr(const IP *addr)
{
    static char addrbuf[FULL_ADDSTRLEN];
    char buf[INET6_ADDRSTRLEN];
    const char *fmt;
    int port;

    switch (addr->ss_family) {
    case AF_INET6:
        port = ((IP6 *)addr)->sin6_port;
        inet_ntop(AF_INET6, &((IP6 *)addr)->sin6_addr, buf, sizeof(buf));
        fmt = "[%s]:%d";
        break;
    case AF_INET:
        port = ((IP4 *)addr)->sin_port;
        inet_ntop(AF_INET, &((IP4 *)addr)->sin_addr, buf, sizeof(buf));
        fmt = "%s:%d";
        break;
    default:
        return "<invalid address>";
    }

    sprintf(addrbuf, fmt, buf, ntohs(port));

    return addrbuf;
}

bool addr_is_localhost(const IP *addr)
{
    // 127.0.0.1
    const uint32_t inaddr_loopback = htonl(INADDR_LOOPBACK);

    switch (addr->ss_family) {
    case AF_INET:
        return (memcmp(&((IP4 *)addr)->sin_addr, &inaddr_loopback, 4) == 0);
    case AF_INET6:
        return (memcmp(&((IP6 *)addr)->sin6_addr, &in6addr_loopback, 16) == 0);
    default:
        return false;
    }
}

bool addr_is_multicast(const IP *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
        return IN_MULTICAST(ntohl(((IP4*) addr)->sin_addr.s_addr));
    case AF_INET6:
        return IN6_IS_ADDR_MULTICAST(&((IP6*) addr)->sin6_addr);
    default:
        return false;
    }
}

int addr_port(const IP *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
        return ntohs(((IP4 *)addr)->sin_port);
    case AF_INET6:
        return ntohs(((IP6 *)addr)->sin6_port);
    default:
        return 0;
    }
}

socklen_t addr_len(const IP *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
        return sizeof(IP4);
    case AF_INET6:
        return sizeof(IP6);
    default:
        return 0;
    }
}

static bool addr_parse_internal(IP *ret, const char addr_str[], const char port_str[], int af)
{
    struct addrinfo hints;
    struct addrinfo *info = NULL;
    struct addrinfo *p = NULL;
    bool rc = false;

    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = af;

    if (getaddrinfo(addr_str, port_str, &hints, &info) != 0) {
        return false;
    }

    p = info;
    while (p != NULL) {
        if ((af == AF_UNSPEC || af == AF_INET6) && p->ai_family == AF_INET6) {
            memcpy(ret, p->ai_addr, sizeof(IP6));
            rc = true;
            break;
        }

        if ((af == AF_UNSPEC || af == AF_INET) && p->ai_family == AF_INET) {
            memcpy(ret, p->ai_addr, sizeof(IP4));
            rc = true;
            break;
        }
        p = p->ai_next;
    }

    freeaddrinfo(info);

    return rc;
}

/*
* Parse/Resolve various string representations of
* IPv4/IPv6 addresses and optional port.
* An address can also be a domain name.
* A port can also be a service (e.g. 'www').
*
* "<address>"
* "<ipv4_address>:<port>"
* "[<address>]"
* "[<address>]:<port>"
*/
bool addr_parse(IP *addr_ret, const char full_addr_str[], const char default_port[], int af)
{
    char addr_buf[256];
    char *addr_beg;
    char *addr_tmp;
    char *last_colon;
    const char *addr_str = NULL;
    const char *port_str = NULL;
    size_t len;

    len = strlen(full_addr_str);
    if (len >= (sizeof(addr_buf) - 1)) {
        // address too long
        return false;
    } else {
        addr_beg = addr_buf;
    }

    memset(addr_buf, '\0', sizeof(addr_buf));
    memcpy(addr_buf, full_addr_str, len);

    last_colon = strrchr(addr_buf, ':');

    if (addr_beg[0] == '[') {
        // [<addr>] or [<addr>]:<port>
        addr_tmp = strrchr(addr_beg, ']');

        if (addr_tmp == NULL) {
            // broken format
            return false;
        }

        *addr_tmp = '\0';
        addr_str = addr_beg + 1;

        if (*(addr_tmp + 1) == '\0') {
            port_str = default_port;
        } else if (*(addr_tmp + 1) == ':') {
            port_str = addr_tmp + 2;
        } else {
            // port expected
            return false;
        }
    } else if (last_colon && last_colon == strchr(addr_buf, ':')) {
        // <non-ipv6-addr>:<port>
        addr_tmp = last_colon;
        *addr_tmp = '\0';
        addr_str = addr_buf;
        port_str = addr_tmp + 1;
    } else {
        // <addr>
        addr_str = addr_buf;
        port_str = default_port;
    }

    return addr_parse_internal(addr_ret, addr_str, port_str, af);
}

// Compare two ip addresses, ignore port
bool addr_equal(const IP *addr1, const IP *addr2)
{
    if (addr1->ss_family != addr2->ss_family) {
        return false;
    } else if (addr1->ss_family == AF_INET) {
        return 0 == memcmp(&((IP4 *)addr1)->sin_addr, &((IP4 *)addr2)->sin_addr, 4);
    } else if (addr1->ss_family == AF_INET6) {
        return 0 == memcmp(&((IP6 *)addr1)->sin6_addr, &((IP6 *)addr2)->sin6_addr, 16);
    } else {
        return false;
    }
}

bool socket_addr(int sock, IP *addr)
{
    socklen_t len = sizeof(IP);
    return getsockname(sock, (struct sockaddr *) addr, &len) == 0;
}

time_t time_add_secs(uint32_t seconds)
{
    return gconf->time_now + seconds;
}

time_t time_add_mins(uint32_t minutes)
{
    return gconf->time_now + (60 * minutes);
}

time_t time_add_hours(uint32_t hours)
{
    return gconf->time_now + (60 * 60 * hours);
}

const char *str_bytes(uint64_t bytes)
{
    static char strbytesbuf[4][8];
    static size_t strbytesbuf_i = 0;
    char *buf = strbytesbuf[++strbytesbuf_i % 4];

    if (bytes < 1000) {
        snprintf(buf, 8, "%u B", (unsigned) bytes);
    } else if (bytes < 1000000) {
        snprintf(buf, 8, "%.1f K", bytes / 1000.0);
    } else if (bytes < 1000000000) {
        snprintf(buf, 8, "%.1f M", bytes / 1000000.0);
    } else if (bytes < 1000000000000) {
        snprintf(buf, 8, "%.1f G", bytes / 1000000000.0);
    } else if (bytes < 1000000000000000) {
        snprintf(buf, 8, "%.1f T", bytes / 1000000000000.0);
    } else if (bytes < 1000000000000000000) {
        snprintf(buf, 8, "%.1f P", bytes / 1000000000000000.0);
    } else {
        snprintf(buf, 8, "%.1f E", bytes / 1000000000000000000.0);
    }

    return buf;
}

const char *str_time(time_t time)
{
    static char strdurationbuf[4][64];
    static size_t strdurationbuf_i = 0;
    char *buf = strdurationbuf[++strdurationbuf_i % 4];

    size_t years, days, hours, minutes, seconds;
    const char *prefix = "";

    if (time < 0) {
        time = -time;
        // prepend minus sign
        prefix = "-";
    }

    years = time / (365 * 24 * 60 * 60);
    time -= years * (365 * 24 * 60 * 60);
    days = time / (24 * 60 * 60);
    time -= days * (24 * 60 * 60);
    hours = time / (60 * 60);
    time -= hours * (60 * 60);
    minutes = time / 60;
    time -= minutes * 60;
    seconds = time;

    if (years > 0) {
        snprintf(buf, 64, "%s%zuy%zud", prefix, years, days);
    } else if (days > 0) {
        snprintf(buf, 64, "%s%zud%zuh", prefix, days, hours);
    } else if (hours > 0) {
        snprintf(buf, 64, "%s%zuh%zum", prefix, hours, minutes);
    } else if (minutes > 0) {
        snprintf(buf, 64, "%s%zum%zus", prefix, minutes, seconds);
    } else {
        snprintf(buf, 64, "%s%zus", prefix, seconds);
    }

    return buf;
}
