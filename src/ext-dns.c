
/*
* DNS-Server interface for KadNode.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "ext-dns.h"

#define MAX_ADDR_RECORDS 32


static int g_sock4 = -1;
static int g_sock6 = -1;

// A simple ring buffer for DNS proxy.
static uint16_t proxy_entries_id[16] = { 0 };
static IP proxy_entries_addr[16] = { { 0 } };
static uint32_t proxy_entries_count = 0;
static IP g_proxy_addr;


// DNS Header Masks
enum {
    QR_MASK = 0x8000,
    OPCODE_MASK = 0x7800,
    AA_MASK = 0x0400,
    TC_MASK = 0x0200,
    RD_MASK = 0x0100,
    RA_MASK = 0x8000,
    RCODE_MASK = 0x000F
};

// Response Type
enum {
    Ok_ResponseType = 0,
    FormatError_ResponseType = 1,
    ServerFailure_ResponseType = 2,
    NameError_ResponseType = 3,
    NotImplemented_ResponseType = 4,
    Refused_ResponseType = 5
};

// Resource Record Types
enum {
    A_Resource_RecordType = 1,
    NS_Resource_RecordType = 2,
    CNAME_Resource_RecordType = 5,
    SOA_Resource_RecordType = 6,
    PTR_Resource_RecordType = 12,
    MX_Resource_RecordType = 15,
    TXT_Resource_RecordType = 16,
    AAAA_Resource_RecordType = 28,
    SRV_Resource_RecordType = 33
};

// Operation Code
enum {
    QUERY_OperationCode = 0, // standard query
    IQUERY_OperationCode = 1, // inverse query
    STATUS_OperationCode = 2, // server status request
    NOTIFY_OperationCode = 4, // request zone transfer
    UPDATE_OperationCode = 5 // change resource records
};

// Response Code
enum {
    NoError_ResponseCode = 0,
    FormatError_ResponseCode = 1,
    ServerFailure_ResponseCode = 2,
    NameError_ResponseCode = 3
};

// Query Type
enum {
    IXFR_QueryType = 251,
    AXFR_QueryType = 252,
    MAILB_QueryType = 253,
    MAILA_QueryType = 254,
    STAR_QueryType = 255
};

// Question Section
struct Question {
    const char *qName;
    uint16_t qType;
    uint16_t qClass;
};

// Data part of a Resource Record
union ResourceData {
    struct {
        const char *txt_data;
    } txt_record;
    struct {
        uint8_t addr[4];
    } a_record;
    struct {
        const char *name;
    } name_server_record;
    struct {
        const char name;
    } cname_record;
    struct {
        const char *name;
    } ptr_record;
    struct {
        uint16_t preference;
        const char *exchange;
    } mx_record;
    struct {
        uint8_t addr[16];
    } aaaa_record;
    struct {
        uint16_t priority;
        uint16_t weight;
        uint16_t port;
        const char *target;
    } srv_record;
};

// Resource Record Section
struct ResourceRecord {
    const char *name;
    uint16_t type;
    uint16_t class;
    uint16_t ttl;
    uint16_t rd_length;
    union ResourceData rd_data;
};

struct Message {
    uint16_t id; // Identifier

    // Flags
    uint16_t qr; // Query/Response Flag
    uint16_t opcode; // Operation Code
    uint16_t aa; // Authoritative Answer Flag
    uint16_t tc; // Truncation Flag
    uint16_t rd; // Recursion Desired
    uint16_t ra; // Recursion Available
    uint16_t rcode; // Response Code

    uint16_t qdCount; // Question Count
    uint16_t anCount; // Answer Record Count
    uint16_t nsCount; // Authority Record Count
    uint16_t arCount; // Additional Record Count

    // We only handle one question and multiple answers
    struct Question question;
    struct ResourceRecord answers[MAX_ADDR_RECORDS*2];

    // Buffer for the qName part
    char qName_buffer[300];
};

// Placeholder names to link together SRV and A/AAAA records
static const char g_names[MAX_ADDR_RECORDS][3] = {
    "01", "02", "03", "04", "05", "06", "07", "08",
    "09", "10", "11", "12", "13", "14", "15", "16",
    "17", "18", "19", "20", "21", "22", "23", "24",
    "25", "26", "27", "28", "29", "30", "31", "32"
};

/*
* Basic memory operations.
*/

static uint16_t get16bits(const uint8_t** buffer)
{
    uint16_t value;

    memcpy(&value, *buffer, 2);
    *buffer += 2;

    return ntohs(value);
}

static void put16bits(uint8_t** buffer, uint16_t value)
{
    value = htons(value);
    memcpy(*buffer, &value, 2);
    *buffer += 2;
}

static void put32bits(uint8_t** buffer, uint32_t value)
{
    value = htonl(value);
    memcpy(*buffer, &value, 4);
    *buffer += 4;
}

/*
* Decoding/Encoding functions
*/

// 3foo3bar3com0 => foo.bar.com
static int dns_decode_domain(char *domain, const uint8_t** buffer, size_t size)
{
    const uint8_t *p = *buffer;
    size_t i = 0;
    size_t len = 0;

    while (*p != '\0') {
        if (i != 0) {
            domain[i] = '.';
            i += 1;
        }

        len = *p;
        p += 1;

        if ((i + len) >= size) {
            return -1;
        }

        memcpy(domain + i, p, len);
        p += len;
        i += len;
    }

    domain[i] = '\0';

    // also jump over the last 0
    *buffer = p + 1;

    return 1;
}

// foo.bar.com => 3foo3bar3com0
static int dns_encode_domain(uint8_t** buffer, const char *domain)
{
    char *buf = (char*) *buffer;
    const char *beg = domain;
    const char *pos = NULL;
    size_t len = strlen(domain);
    size_t plen = 0;
    size_t i = 0;

    while ((pos = strchr(beg, '.')) != NULL) {
        plen = pos - beg;
        buf[i] = plen;
        i += 1;
        memcpy(buf + i, beg, plen);
        i += plen;

        beg = pos + 1;
    }

    plen = len - (beg - domain);

    buf[i] = plen;
    i += 1;

    memcpy(buf + i, beg, plen);
    i += plen;

    buf[i] = '\0';
    i += 1;

    *buffer += i;

    return 1;
}

static int dns_encode_header(uint8_t** buffer, const struct Message *msg)
{
    size_t fields;

    put16bits(buffer, msg->id);

    // Set Flags - Most fields are omitted
    fields = 0;
    fields |= (msg->qr << 15) & QR_MASK;
    fields |= (msg->rcode << 0) & RCODE_MASK;
    put16bits(buffer, fields);

    put16bits(buffer, msg->qdCount);
    put16bits(buffer, msg->anCount);
    put16bits(buffer, msg->nsCount);
    put16bits(buffer, msg->arCount);

    return 1;
}

static int dns_decode_header(struct Message *msg, const uint8_t** buffer)
{
    size_t fields;

    msg->id = get16bits(buffer);
    fields = get16bits(buffer);
    msg->qr = (fields & QR_MASK) >> 15;
    msg->opcode = (fields & OPCODE_MASK) >> 11;
    msg->aa = (fields & AA_MASK) >> 10;
    msg->tc = (fields & TC_MASK) >> 9;
    msg->rd = (fields & RD_MASK) >> 8;
    msg->ra = (fields & RA_MASK) >> 7;
    msg->rcode = (fields & RCODE_MASK) >> 0;

    msg->qdCount = get16bits(buffer);
    msg->anCount = get16bits(buffer);
    msg->nsCount = get16bits(buffer);
    msg->arCount = get16bits(buffer);

    return 1;
}

// Decode the message from a byte array into a message structure
static int dns_decode_msg(struct Message *msg, const uint8_t *buffer)
{
    size_t i;

    if (dns_decode_header(msg, &buffer) < 0) {
        return -1;
    }

    // Parse questions - but stop after the first question we can handle
    for (i = 0; i < msg->qdCount; ++i) {
        if (dns_decode_domain(msg->qName_buffer, &buffer, 300) < 0) {
            return -1;
        }

        msg->question.qName = msg->qName_buffer;
        msg->question.qType = get16bits(&buffer);
        msg->question.qClass = get16bits(&buffer);
        return 1;
    }

    log_warning("DNS: No msg.");

    return -1;
}

// Encode the message structure into a byte array
static int dns_encode_msg(uint8_t *buffer, size_t size, const struct Message *msg)
{
    const size_t qName_offset = 12;
    const struct ResourceRecord *rr;
    uint8_t *beg;
    size_t i;

    beg = buffer;
    if (dns_encode_header(&buffer, msg) < 0) {
        return -1;
    }

    // Attach a single question section.
    if (dns_encode_domain(&buffer, msg->question.qName) < 0) {
        return -1;
    }

    put16bits(&buffer, msg->question.qType);
    put16bits(&buffer, msg->question.qClass);

    // Attach multiple resource records.
    const size_t count = msg->anCount + msg->nsCount + msg->arCount;
    for (i = 0; i < count; i++) {
        rr = &msg->answers[i];

        if (msg->question.qName == rr->name) {
            // Reference qName in question section (message compression)
            put16bits(&buffer, (3 << 14) + qName_offset);
        } else {
            if (dns_encode_domain(&buffer, rr->name) < 0) {
                return -1;
            }
        }

        put16bits(&buffer, rr->type);
        put16bits(&buffer, rr->class);
        put32bits(&buffer, rr->ttl);
        put16bits(&buffer, rr->rd_length); // already accounts for encoded data

        if (rr->type == SRV_Resource_RecordType) {
            put16bits(&buffer, rr->rd_data.srv_record.priority);
            put16bits(&buffer, rr->rd_data.srv_record.weight);
            put16bits(&buffer, rr->rd_data.srv_record.port);
            if (dns_encode_domain(&buffer, rr->rd_data.srv_record.target) < 0) {
                return -1;
            }
        } else if (rr->type == PTR_Resource_RecordType) {
            if (dns_encode_domain(&buffer, rr->rd_data.ptr_record.name) < 0) {
                return -1;
            }
        } else {
            // Assume A/AAAA address record data
            memcpy(buffer, &rr->rd_data, rr->rd_length);
            buffer += rr->rd_length;
        }
    }

    return (buffer - beg);
}

static const char* dns_lookup_ptr(const char ptr_name[])
{
    typedef struct {
        const char* ptr_name;
        const char* hostname;
    } entry_t;

    static const entry_t entries[] = {
        { "1.0.0.127.in-addr.arpa", "localhost" },
        { "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", "localhost" }
    };

    size_t i;
    for (i = 0; i < ARRAY_SIZE(entries); i++) {
        if (strcmp(ptr_name, entries[i].ptr_name)  == 0) {
            return entries[i].hostname;
        }
    }

    return NULL;
}

static void setAddressRecord(struct ResourceRecord *rr, const char name[], const IP *addr)
{
    if (addr->ss_family == AF_INET) {
        rr->name = name;
        rr->type = A_Resource_RecordType;
        rr->class = 1;
        rr->ttl = 0; // no caching
        rr->rd_length = 4;

        memcpy(rr->rd_data.a_record.addr, &((IP4 *)addr)->sin_addr, 4);
    } else {
        rr->name = name;
        rr->type = AAAA_Resource_RecordType;
        rr->class = 1;
        rr->ttl = 0; // no caching
        rr->rd_length = 16;

        memcpy(rr->rd_data.aaaa_record.addr, &((IP6 *)addr)->sin6_addr, 16);
    }
}

static void setServiceRecord(struct ResourceRecord *rr, const char name[], const char target[], int port)
{
    rr->name = name;
    rr->type = SRV_Resource_RecordType;
    rr->class = 1;
    rr->ttl = 0; // no caching
    rr->rd_length = 6 + strlen(target) + 2; // encoded target will be +2 longer

    rr->rd_data.srv_record.priority = 0;
    rr->rd_data.srv_record.weight = 0;
    rr->rd_data.srv_record.port = port;
    rr->rd_data.srv_record.target = target;
}

static void setPointerRecord(struct ResourceRecord *rr, const char name[], const char domain[])
{
    rr->name = name;
    rr->type = PTR_Resource_RecordType;
    rr->class = 1;
    rr->ttl = 0; // no caching
    rr->rd_length = strlen(domain) + 2; // encoded target will be +2 longer

    rr->rd_data.ptr_record.name = domain;
}

static int dns_setup_msg(struct Message *msg, const struct result_t *results, const char *hostname)
{
    const struct result_t *result;
    const char *qName;
    int port, i, c;

    // Header: leave most values intact for response
    msg->qr = 1; // This is a response
    msg->aa = 1; // This server is authoritative
    msg->ra = 0; // No recursion available - we don't ask other DNS servers
    msg->rcode = Ok_ResponseType;

    msg->qdCount = 1;
    msg->anCount = 0;
    msg->nsCount = 0;
    msg->arCount = 0;

    if (!results) {
        return 1;
    }
    c = 0;
    qName = msg->question.qName;
    if (msg->question.qType == SRV_Resource_RecordType) {
        for (result = results, i = 0; result && c <= MAX_ADDR_RECORDS; result = result->next) {
            if (is_valid_result(result)) {
                port = addr_port(&result->addr);
                setServiceRecord(&msg->answers[c++], qName, g_names[i++], port);
                msg->anCount++;
            }
        }

        for (result = results, i = 0; result && c < MAX_ADDR_RECORDS; result = result->next) {
            if (is_valid_result(result)) {
                setAddressRecord(&msg->answers[c++], g_names[i++], &result->addr);
                msg->anCount++;
                i++;
            }
        }
    } else if (msg->question.qType == PTR_Resource_RecordType && hostname != NULL) {
        setPointerRecord(&msg->answers[c++], qName, hostname);
        msg->anCount++;
        i = 1;
    } else {
        // Assume AAAA or A Record Type
        for (result = results, i = 0; result && c <= MAX_ADDR_RECORDS; result = result->next) {
            if (is_valid_result(result)) {
                setAddressRecord(&msg->answers[c++], qName, &result->addr);
                msg->anCount++;
                i++;
            }
        }
    }

    return i;
}

#ifdef DEBUG
// Get a small string representation of the query type
static const char* qtype_str(int qType)
{
    switch(qType) {
    case A_Resource_RecordType:
        return "A";
    case AAAA_Resource_RecordType:
        return "AAAA";
    case SRV_Resource_RecordType:
        return "SRV";
    case PTR_Resource_RecordType:
        return "PTR";
    case NS_Resource_RecordType:
        return "NS";
    case CNAME_Resource_RecordType:
        return "CNAME";
    case SOA_Resource_RecordType:
        return "SOA";
    case MX_Resource_RecordType:
        return "MX";
    case TXT_Resource_RecordType:
        return "TXT";
    default:
        return "???";
    }
}
#endif

// Read DNS proxy server from /etc/resolv.conf
static void proxy_read_resolv(IP *dst, const char path[])
{
    static time_t last_checked = 0;
    static time_t last_modified = 0;

    // Check at most every second
    if (last_checked == gconf->time_now) {
        return;
    }
    last_checked = gconf->time_now;

    IP addr;
    struct stat attr;
    FILE *file;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    char dns_serv[256];

    // Check if the path was modified
    stat(path, &attr);
    if (last_modified != attr.st_mtime) {
        last_modified = attr.st_mtime;

        file = fopen(path, "rb");
        if (file) {
            while ((nread = getline(&line, &len, file)) != -1) {
                if (nread == 0) {
                    continue;
                }

                int rc = sscanf(line, "nameserver %255[^ \t\r\n#]", dns_serv);
                if (rc != 1) {
                    continue;
                }

                if (!addr_parse(&addr, dns_serv, "53", AF_UNSPEC)) {
                    log_warning("DNS: Failed to read DNS server %s from %s", dns_serv, path);
                    continue;
                }

                if (!addr_is_localhost(&addr)) {
                    *dst = addr;
                    log_debug("DNS: Pick the DNS server %s from %s", dns_serv, path);
                    // we pick the first IP address
                    break;
                }
            }
            free(line);
            fclose(file);
        } else {
            log_warning("DNS: Failed to open %s", path);
        }
    }
}

// Forward request to external DNS server
static void proxy_forward_request(uint8_t *buffer, ssize_t buflen, IP *clientaddr, uint16_t id)
{
    int sock;

    sock = (g_proxy_addr.ss_family == AF_INET) ? g_sock4 : g_sock6;
    if (sendto(sock, buffer, buflen, 0, (struct sockaddr*) &g_proxy_addr, sizeof(IP)) < 0) {
        log_warning("DNS: Failed to send request to dns server %s", str_addr(&g_proxy_addr));
        return;
    }

    // Remember DNS request id and client address
    proxy_entries_id[proxy_entries_count] = id;
    proxy_entries_addr[proxy_entries_count] = *clientaddr;
    proxy_entries_count = (proxy_entries_count + 1) % ARRAY_SIZE(proxy_entries_id);
}

// Forward DNS response back to client address
static void proxy_forward_response(uint8_t *buffer, ssize_t buflen, uint16_t id)
{
    for (size_t i = 0; i < ARRAY_SIZE(proxy_entries_id); ++i) {
        if (proxy_entries_id[i] == id) {
            int sock = (proxy_entries_addr[i].ss_family == AF_INET) ? g_sock4 : g_sock6;
            sendto(sock, buffer, buflen, 0, (struct sockaddr*) &proxy_entries_addr[i], sizeof(IP));
            return;
        }
    }

    log_warning("DNS: Failed to find client for request.");
}

static void dns_handler(int rc, int sock)
{
    struct Message msg;
    IP clientaddr;
    const struct search_t *search;
    socklen_t addrlen_ret;
    ssize_t buflen;
    uint8_t buffer[1472];
    const char *hostname;
    const char *domain;

    if (rc == 0) {
        return;
    }

    memset(buffer, 0, sizeof(buffer));
    addrlen_ret = sizeof(IP);
    buflen = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &clientaddr, &addrlen_ret);

    if (buflen < 0) {
        return;
    }

    // Decode message
    if (dns_decode_msg(&msg, buffer) < 0) {
        return;
    }

    hostname = msg.question.qName;

    // Check if hostname ends with .p2p
    if (!has_tld(hostname, gconf->query_tld)) {
        // Act as an DNS proxy
        if (gconf->dns_proxy_enable) {
            // Update proxy server address if no fixed DNS server is given
            if (gconf->dns_proxy_server == NULL) {
                proxy_read_resolv(&g_proxy_addr, "/etc/resolv.conf");
            }

            if (msg.qr == 1) {
                proxy_forward_response(buffer, buflen, msg.id);
            } else {
                proxy_forward_request(buffer, buflen, &clientaddr, msg.id);
            }
        }
        return;
    }

    log_debug("DNS: Received %s query from %s for: %s",
        qtype_str(msg.question.qType),
        str_addr(&clientaddr),
        hostname
    );

    if (msg.question.qType == PTR_Resource_RecordType) {
        if ((domain = dns_lookup_ptr(hostname)) == NULL) {
            log_debug("DNS: No domain found for PTR question.");
            dns_setup_msg(&msg, NULL, NULL);
        } else {
            if (dns_setup_msg(&msg, NULL, domain) < 1) {
                log_debug("DNS: Failed to setup msg");
                dns_setup_msg(&msg, NULL, NULL);
            }
        }

        log_debug("DNS: Send back hostname '%s' to: %s",
            domain, str_addr(&clientaddr)
        );
    } else if (msg.question.qType == A_Resource_RecordType
        || msg.question.qType == AAAA_Resource_RecordType
    ) {

        // Start lookup for one address
        search = kad_lookup(hostname);

        if (search == NULL) {
            log_debug("DNS: Failed to start query");
            dns_setup_msg(&msg, NULL, NULL);
        } else {
            if (dns_setup_msg(&msg, search->results, NULL) < 1) {
                log_debug("DNS: Failed to setup msg");
                dns_setup_msg(&msg, NULL, NULL);
            }
        }

        log_debug("DNS: Send back addresses to: %s", str_addr(&clientaddr));
    } else {
        log_warning("DNS: No question for A, AAAA, SRV or PTR resource found in query.");
        dns_setup_msg(&msg, NULL, NULL);
    }

    // Encode message
    buflen = dns_encode_msg(buffer, sizeof(buffer), &msg);

    if (buflen > 0) {
        if (sendto(sock, buffer, buflen, 0, (struct sockaddr*) &clientaddr, addr_len(&clientaddr)) < 0) {
            log_warning("DNS: Cannot send message to '%s': %s", str_addr(&clientaddr), strerror(errno));
        }
    } else {
        log_error("DNS: Failed to create response packet.");
    }
}

bool dns_setup(void)
{
    if (gconf->dns_port < 1) {
        return true;
    }

    // Initialize g_proxy_addr
    if (gconf->dns_proxy_enable && gconf->dns_proxy_server) {
        if (!addr_parse(&g_proxy_addr, gconf->dns_proxy_server, "53", AF_UNSPEC)) {
            log_error("DNS: Failed to parse IP address: %s", gconf->dns_proxy_server);
            return false;
        }
    }

    g_sock4 = net_bind("DNS", "127.0.0.1", gconf->dns_port, NULL, IPPROTO_UDP);
    g_sock6 = net_bind("DNS", "::1", gconf->dns_port, NULL, IPPROTO_UDP);

    if (g_sock4 >= 0) {
        net_add_handler(g_sock4, &dns_handler);
    }

    if (g_sock6 >= 0) {
        net_add_handler(g_sock6, &dns_handler);
    }

    return true;
}

void dns_free(void)
{
    // Nothing to do
}
