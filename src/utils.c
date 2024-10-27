
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

bool hex_parse_id(uint8_t id[], size_t idsize, const char query[], size_t querylen)
{
    if (bytes_from_base32(id, idsize, query, querylen)) {
        return true;
    }

    if (bytes_from_base16(id, idsize, query, querylen)) {
        return true;
    }

    return false;
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

static size_t base16_len(size_t len)
{
    return 2 * len;
}

bool bytes_from_base16(uint8_t dst[], size_t dstsize, const char src[], size_t srcsize)
{
    size_t i;
    size_t xv = 0;

    if (base16_len(dstsize) != srcsize) {
        return false;
    }

    for (i = 0; i < srcsize; ++i) {
        const char c = src[i];
        if (c >= '0' && c <= '9') {
            xv += c - '0';
        } else if (c >= 'a' && c <= 'f') {
            xv += (c - 'a') + 10;
        } else {
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

char *bytes_to_base16(char dst[], size_t dstsize, const uint8_t src[], size_t srcsize)
{
    static const char hexchars[16] = "0123456789abcdef";
    size_t i;

    // + 1 for the '\0'
    if (dstsize != (base16_len(srcsize) + 1)) {
        return NULL;
    }

    for (i = 0; i < srcsize; ++i) {
        dst[2 * i] = hexchars[src[i] / 16];
        dst[2 * i + 1] = hexchars[src[i] % 16];
    }

    dst[2 * srcsize] = '\0';

    return dst;
}

// get length of len hex string as bytes string
// e.g.: 32 bytes need 52 characters to encode in base32
static size_t base32_len(size_t len)
{
    const size_t mod = (len % 5);
    return 8 * (len / 5) + 2 * mod - (mod > 2);
}

bool bytes_from_base32(uint8_t dst[], size_t dstsize, const char src[], size_t srcsize)
{
    size_t processed = 0;
    unsigned char *d = dst;
    int i;
    int v;

    if (srcsize != base32_len(dstsize)) {
        return false;
    }

    for (i = 0; i < srcsize; i++) {
        if (*src >= 'a' && *src <= 'v') {
            v = *src - 'a' + 10;
        } else if (*src >= '0' && *src <= '9') {
            v = *src - '0';
        } else if (*src == '=') {
            src++;
            continue;
        } else {
            return false;
        }

        src++;

        switch (processed % 8) {
        case 0:
            if (dstsize <= 0) {
                return false;
            }
            d[0] &= 0x07;
            d[0] |= (v << 3) & 0xF8;
            break;
        case 1:
            if (dstsize < 1) {
                return false;
            }
            d[0] &= 0xF8;
            d[0] |= (v >> 2) & 0x07;
            if (dstsize >= 2) {
                d[1] &= 0x3F;
                d[1] |= (v << 6) & 0xC0;
            }
            break;
        case 2:
            if (dstsize < 2) {
                return false;
            }
            d[1] &= 0xC1;
            d[1] |= (v << 1) & 0x3E;
            break;
        case 3:
            if (dstsize < 2) {
                return false;
            }
            d[1] &= 0xFE;
            d[1] |= (v >> 4) & 0x01;
            if (dstsize >= 3) {
                d[2] &= 0x0F;
                d[2] |= (v << 4) & 0xF0;
            }
            break;
        case 4:
            if (dstsize < 3) {
                return false;
            }
            d[2] &= 0xF0;
            d[2] |= (v >> 1) & 0x0F;
            if (dstsize >= 4) {
                d[3] &= 0x7F;
                d[3] |= (v << 7) & 0x80;
            }
            break;
        case 5:
            if (dstsize < 4) {
                return false;
            }
            d[3] &= 0x83;
            d[3] |= (v << 2) & 0x7C;
            break;
        case 6:
            if (dstsize < 4) {
                return false;
            }
            d[3] &= 0xFC;
            d[3] |= (v >> 3) & 0x03;
            if (dstsize >= 5) {
                d[4] &= 0x1F;
                d[4] |= (v << 5) & 0xE0;
            }
            break;
        default:
            if (dstsize < 5) {
                return false;
            }
            d[4] &= 0xE0;
            d[4] |= v & 0x1F;
            d += 5;
            dstsize -= 5;
            break;
        }
        processed++;
    }

    return true;
}

char *bytes_to_base32(char dst[], size_t dstsize, const uint8_t *src, size_t srcsize) {
    const uint8_t *s = src;
    int byte = 0;
    uint8_t *d = (uint8_t*) dst;
    int i;

    // + 1 for the '\0'
    if (dstsize != (base32_len(srcsize) + 1)) {
        return NULL;
    }

    while (srcsize) {
        switch (byte) {
        case 0:
            d[0] = *s >> 3;
            d[1] = (*s & 0x07) << 2;
            break;
        case 1:
            d[1] |= (*s >> 6) & 0x03;
            d[2] = (*s >> 1) & 0x1f;
            d[3] = (*s & 0x01) << 4;
            break;
        case 2:
            d[3] |= (*s >> 4) & 0x0f;
            d[4] = (*s & 0x0f) << 1;
            break;
        case 3:
            d[4] |= (*s >> 7) & 0x01;
            d[5] = (*s >> 2) & 0x1f;
            d[6] = (*s & 0x03) << 3;
            break;
        case 4:
            d[6] |= (*s >> 5) & 0x07;
            d[7] = *s & 0x1f;
            break;
        }

        srcsize--;
        s++;
        byte++;

        if (byte == 5) {
            d += 8;
            byte = 0;
        }
    }

    d = (uint8_t*) dst;

    dstsize--;
    for (i = 0; i < dstsize; i++) {
        if (*d < 10) {
            *d = *d +'0';
        } else if (*d < 32) {
            *d = *d - 10 + 'a';
        } else {
            *d = '?';
        }
        d++;
    }

    dst[dstsize] = '\0';

    return dst;
}

// Check if a string has and extension.
// ext is epected to start with a dot.
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

    // Convert to lower case
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
    return (memcmp(id1, id2, SHA1_BIN_LENGTH) == 0);
}

const char *str_id(const uint8_t id[])
{
    static char hexbuf[SHA1_HEX_LENGTH + 1];
    return bytes_to_base16(hexbuf, sizeof(hexbuf), id, SHA1_BIN_LENGTH);
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

const char *str_addr2(const void *ip, uint8_t length, uint16_t port)
{
    static char addrbuf[FULL_ADDSTRLEN];
    char buf[INET6_ADDRSTRLEN];
    const char *fmt;

    switch (length) {
    case 16:
        inet_ntop(AF_INET6, ip, buf, sizeof(buf));
        fmt = "[%s]:%d";
        break;
    case 4:
        inet_ntop(AF_INET, ip, buf, sizeof(buf));
        fmt = "%s:%d";
        break;
    default:
        return "<invalid address>";
    }

    sprintf(addrbuf, fmt, buf, port);

    return addrbuf;
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

int addr_len(const IP *addr)
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
        if (addr_tmp) {
            *addr_tmp = '\0';
            addr_str = addr_buf;
            port_str = addr_tmp + 1;
        } else {
            addr_str = addr_buf;
            port_str = default_port;
        }
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
        return 0;
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
