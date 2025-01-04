
#define _GNU_SOURCE

#include <sys/time.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "log.h"
#include "main.h"
#include "utils.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "searches.h"
#include "announces.h"
#ifdef BOB
#include "ext-bob.h"
#endif

// include dht.c instead of dht.h to access private vars
#include "dht.c"


/*
* The interface that is used to interact with the DHT.
*/

// Next time to do DHT maintenance
static time_t g_dht_maintenance = 0;
static int g_dht_socket4 = -1;
static int g_dht_socket6 = -1;


/*
* Put an address and port into a sockaddr_storages struct.
* Both addr and port are in network byte order.
*/
void to_addr(IP *out_addr, const void *in_addr, size_t len, uint16_t port)
{
    memset(out_addr, '\0', sizeof(IP));

    if (len == 4) {
        IP4 *a = (IP4 *) out_addr;
        a->sin_family = AF_INET;
        a->sin_port = port;
        memcpy(&a->sin_addr.s_addr, in_addr, 4);
    }

    if (len == 16) {
        IP6 *a = (IP6 *) out_addr;
        a->sin6_family = AF_INET6;
        a->sin6_port = port;
        memcpy(&a->sin6_addr.s6_addr, in_addr, 16);
    }
}

typedef struct {
    uint8_t addr[16];
    uint16_t port;
} dht_addr6_t;

typedef struct {
    uint8_t addr[4];
    uint16_t port;
} dht_addr4_t;


// This callback is called when a search result arrives or a search completes
void dht_callback_func(void *closure, int event, const uint8_t *info_hash, const void *data, size_t data_len)
{
    struct search_t *search;
    dht_addr4_t *data4;
    dht_addr6_t *data6;
    IP addr;

    search = searches_find_by_id(info_hash);

    if (search == NULL) {
        return;
    }

    switch (event) {
        case DHT_EVENT_VALUES:
            data4 = (dht_addr4_t *) data;
            for (size_t i = 0; i < (data_len / sizeof(dht_addr4_t)); ++i) {
                to_addr(&addr, &data4[i].addr, 4, data4[i].port);
                searches_add_addr(search, &addr);
            }
            break;
        case DHT_EVENT_VALUES6:
            data6 = (dht_addr6_t *) data;
            for (size_t i = 0; i < (data_len / sizeof(dht_addr6_t)); ++i) {
                to_addr(&addr, &data6[i].addr, 16, data6[i].port);
                searches_add_addr(search, &addr);
            }
            break;
        case DHT_EVENT_SEARCH_DONE:
        case DHT_EVENT_SEARCH_DONE6:
            // ignore..
            break;
        case DHT_EVENT_SEARCH_EXPIRED:
            searches_remove_by_id(info_hash);
            break;
    }
}

#if 0
/*
* Lookup in values we announce ourselves.
* Useful for networks of only one node, also faster.
*/
void kad_lookup_own_announcements(struct search_t *search)
{
    struct announcement_t* value;
    int af;
    IP addr;

    // 127.0.0.1
    const uint32_t inaddr_loopback = htonl(INADDR_LOOPBACK);

    af = gconf->af;
    value = announces_find(search->id);
    if (value) {
        if (af == AF_UNSPEC || af == AF_INET6) {
            to_addr(&addr, &in6addr_loopback, 16, htons(value->port)); // ::1
            log_debug("KAD: Address found in own announcements: %s", str_addr(&addr));
            searches_add_addr(search, &addr);
        }

        if (af == AF_UNSPEC || af == AF_INET) {
            to_addr(&addr, &inaddr_loopback, 4, htons(value->port)); // 127.0.0.1
            log_debug("KAD: Address found in own announcements: %s", str_addr(&addr));
            searches_add_addr(search, &addr);
        }
    }
}
#endif

static void clear_old_traffic_counters(void)
{
    size_t idx = gconf->time_now % TRAFFIC_DURATION_SECONDS;
    uint32_t since = (gconf->time_now - gconf->traffic_time);
    size_t n = MIN(since, TRAFFIC_DURATION_SECONDS);

    // clear old traffic measurement buckets
    for (size_t i = 0; i < n; ++i) {
        size_t j = (TRAFFIC_DURATION_SECONDS + idx + i + 1) % TRAFFIC_DURATION_SECONDS;
        gconf->traffic_in[j] = 0;
        gconf->traffic_out[j] = 0;
    }
}

static void record_traffic(uint32_t in_bytes, uint32_t out_bytes)
{
    clear_old_traffic_counters();

    gconf->traffic_in_sum += in_bytes;
    gconf->traffic_out_sum += out_bytes;

    size_t idx = gconf->time_now % TRAFFIC_DURATION_SECONDS;
    gconf->traffic_time = gconf->time_now;
    gconf->traffic_in[idx] += out_bytes;
    gconf->traffic_out[idx] += in_bytes;
}

// Handle incoming packets and pass them to the DHT code
void dht_handler(int rc, int sock)
{
    uint8_t buffer[1500];
    uint8_t *buf = &buffer[0];
    ssize_t buflen = 0;
    IP from;

    if (rc > 0) {
        // Check which socket received the data
        socklen_t fromlen = sizeof(from);
        buflen = recvfrom(sock, buf, sizeof(buffer) - 1, 0, (struct sockaddr*) &from, &fromlen);

        if (buflen <= 0 || buflen >= sizeof(buffer)) {
            return;
        }

        record_traffic(buflen, 0);

        // The DHT code expects the message to be null-terminated.
        buf[buflen] = '\0';
    }


#ifdef BOB
    // Hook up BOB extension on the DHT socket
    if (bob_handler(sock, buf, buflen, &from)) {
        return;
    }
#endif

    if (buflen > 0) {
        size_t plen = gconf->dht_isolation_prefix_length;
        if (plen > 0) {
            // DHT isolation enabled - check and remove prefix
            if ((buflen <= plen)
                || (0 != memcmp(buf, &gconf->dht_isolation_prefix[0], plen))) {
                    // prefix does not match
                    return;
            }

            // strip prefix
            buf += plen;
            buflen -= plen;
        }

        // Handle incoming data
        time_t time_wait = 0;
        socklen_t fromlen = sizeof(from);
        rc = dht_periodic(buf, buflen, (struct sockaddr*) &from, fromlen, &time_wait, dht_callback_func, NULL);

        if (rc < 0 && errno != EINTR) {
            if (rc == EINVAL || rc == EFAULT) {
                log_error("KAD: Error calling dht_periodic");
                exit(1);
            }
            g_dht_maintenance = time_now_sec() + 1;
        } else {
            g_dht_maintenance = time_now_sec() + time_wait;
        }
    } else if (g_dht_maintenance <= time_now_sec()) {
        // Do a maintenance call
        time_t time_wait = 0;
        rc = dht_periodic(NULL, 0, NULL, 0, &time_wait, dht_callback_func, NULL);

        // Wait for the next maintenance call
        g_dht_maintenance = time_now_sec() + time_wait;
        //log_debug("KAD: Next maintenance call in %u seconds.", (unsigned) time_wait);
    } else {
        rc = 0;
    }

    if (rc < 0) {
        if (errno == EINTR) {
            return;
        } else if (rc == EINVAL || rc == EFAULT) {
            log_error("KAD: Error using select: %s", strerror(errno));
            return;
        } else {
            g_dht_maintenance = time_now_sec() + 1;
        }
    }
}

/*
* Kademlia needs dht_blacklisted/dht_hash/dht_random_bytes functions to be present.
*/

int dht_sendto(int sockfd, const void *buf, int buflen, int flags, const struct sockaddr *to, int tolen)
{
    size_t plen = gconf->dht_isolation_prefix_length;
    if (plen > 0) {
        // DHT isolation enabled - add prefix
        uint8_t buf2[1500];
        int buflen2 = buflen + plen;
        if (buflen2 > sizeof(buf2)) {
            log_warning("dht_sendto() packet too big for prefix");
            return -1;
        }
        memcpy(&buf2[0], &gconf->dht_isolation_prefix[0], plen);
        memcpy(&buf2[plen], buf, buflen);

        record_traffic(0, buflen2);

        return sendto(sockfd, buf2, buflen2, flags, to, tolen);
    } else {
        record_traffic(0, buflen);
        return sendto(sockfd, buf, buflen, flags, to, tolen);
    }
}

int dht_blacklisted(const struct sockaddr *sa, int salen)
{
    return 0;
}

// Hashing for the DHT - implementation does not matter for interoperability
void dht_hash(void *hash_return, int hash_size,
        const void *v1, int len1,
        const void *v2, int len2,
        const void *v3, int len3)
{
    union {
        uint8_t data[8];
        uint16_t num4[4];
        uint32_t num2[2];
        uint64_t num1[1];
    } hash;

    assert(len1 == 8);
    memcpy(&hash.data, v1, 8);

    assert(len2 == 4 || len2 == 16);
    if (len2 == 4) {
        const uint32_t d2 = *((uint32_t*) v2);
        hash.num2[0] ^= d2;
        hash.num2[1] ^= d2;
    } else {
        hash.num1[0] ^= *((uint64_t*) v2);
        hash.num1[0] ^= *((uint64_t*) v2 + 8);
    }

    assert(len3 == 2);
    const uint16_t d3 = *((uint16_t*) v3);
    hash.num4[0] ^= d3;
    hash.num4[1] ^= d3;
    hash.num4[2] ^= d3;
    hash.num4[3] ^= d3;

    assert(hash_size == 8);
    memcpy(hash_return, &hash.data, 8);
}

int dht_random_bytes(void *buf, size_t size)
{
    return bytes_random(buf, size);
}

bool kad_setup(void)
{
    uint8_t node_id[ID_BINARY_LENGTH];

#ifdef DEBUG
    if (gconf->verbosity == VERBOSITY_DEBUG) {
        // Let the DHT output debug text
        dht_debug = stdout;
    }
#endif

    bytes_random(node_id, ID_BINARY_LENGTH);

    g_dht_socket4 = net_bind("KAD", "0.0.0.0", gconf->dht_port, gconf->dht_ifname, IPPROTO_UDP);
    g_dht_socket6 = net_bind("KAD", "::", gconf->dht_port, gconf->dht_ifname, IPPROTO_UDP);

    if (g_dht_socket4 >= 0) {
        net_add_handler(g_dht_socket4, &dht_handler);
    }

    if (g_dht_socket6 >= 0) {
        net_add_handler(g_dht_socket6, &dht_handler);
    }

    if (g_dht_socket4 < 0 && g_dht_socket6 < 0) {
        return false;
    }

    // Init the DHT.  Also set the sockets into non-blocking mode.
    if (dht_init(g_dht_socket4, g_dht_socket6, node_id, (uint8_t*) "KN\0\0") < 0) {
        log_error("KAD: Failed to initialize the DHT.");
        return false;
    }

    return true;
}

void kad_free(void)
{
    dht_uninit();
}

int kad_count_bucket(const struct bucket *bucket, int good)
{
    struct node *node;
    int count;

    count = 0;
    while (bucket) {
        if (good) {
            node = bucket->nodes;
            while (node) {
                count += node_good(node) ? 1 : 0;
                node = node->next;
            }
        } else {
            count += bucket->count;
        }
        bucket = bucket->next;
    }
    return count;
}

int kad_count_nodes(bool good)
{
    // Count nodes in IPv4 and IPv6 buckets
    return kad_count_bucket(buckets, good) + kad_count_bucket(buckets6, good);
}

void kad_status(FILE *fp)
{
    struct storage *strg = storage;
    struct search *srch = searches;
    struct announcement_t *announcement = announces_get();
    int numsearches4_active = 0;
    int numsearches4_done = 0;
    int numsearches6_active = 0;
    int numsearches6_done = 0;
    int numstorage = 0;
    int numstorage_peers = 0;
    int numannounces = 0;

    // Count searches
    while (srch) {
        if (srch->af == AF_INET6) {
            if (srch->done) {
                numsearches6_done += 1;
            } else {
                numsearches6_active += 1;
            }
        } else {
            if (srch->done) {
                numsearches4_done += 1;
            } else {
                numsearches4_active += 1;
            }
        }
        srch = srch->next;
    }

    // Count storage and peers
    while (strg) {
        numstorage_peers += strg->numpeers;
        numstorage += 1;
        strg = strg->next;
    }

    while (announcement) {
        numannounces += 1;
        announcement = announcement->next;
    }

    // Use dht data structure!
    int nodes4 = kad_count_bucket(buckets, false);
    int nodes6 = kad_count_bucket(buckets6, false);
    int nodes4_good = kad_count_bucket(buckets, true);
    int nodes6_good = kad_count_bucket(buckets6, true);

    clear_old_traffic_counters();
    uint32_t traffic_sum_in = 0;
    uint32_t traffic_sum_out = 0;
    for (size_t i = 0; i < TRAFFIC_DURATION_SECONDS; ++i) {
        traffic_sum_in += gconf->traffic_in[i];
        traffic_sum_out += gconf->traffic_out[i];
    }

    fprintf(
        fp,
        "%s\n"
        "DHT id: %s\n"
        "DHT uptime: %s\n"
        "DHT listen on: %s / device: %s / port: %d\n"
        "DHT nodes: %d IPv4 (%d good), %d IPv6 (%d good)\n"
        "DHT storage: %d entries with %d addresses\n"
        "DHT searches: %d IPv4 (%d done), %d IPv6 active (%d done)\n"
        "DHT announcements: %d\n"
        "DHT blocklist: %d\n"
        "DHT traffic: %s, %s/s (in) / %s, %s/s (out)\n",
        kadnode_version_str,
        str_id(myid),
        str_time(gconf->time_now - gconf->startup_time),
        str_af(gconf->af), gconf->dht_ifname ? gconf->dht_ifname : "<any>", gconf->dht_port,
        nodes4, nodes4_good, nodes6, nodes6_good,
        numstorage, numstorage_peers,
        numsearches4_active, numsearches4_done, numsearches6_active, numsearches6_done,
        numannounces,
        (next_blacklisted % DHT_MAX_BLACKLISTED),
        str_bytes(gconf->traffic_in_sum),
        str_bytes(traffic_sum_in / TRAFFIC_DURATION_SECONDS),
        str_bytes(gconf->traffic_out_sum),
        str_bytes(traffic_sum_out / TRAFFIC_DURATION_SECONDS)
    );
}

bool kad_ping(const IP* addr)
{
    return dht_ping_node((struct sockaddr *)addr, addr_len(addr)) >= 0;
}

/*
* Find nodes that are near the given id and announce to them
* that this node can satisfy the given id on the given port.
*/
bool kad_announce_once(const uint8_t id[], int port)
{
    if (port < 1 || port > 65535) {
        log_debug("KAD: Invalid port for announcement: %d", port);
        return false;
    }

    dht_search(id, port, AF_INET, dht_callback_func, NULL);
    dht_search(id, port, AF_INET6, dht_callback_func, NULL);

    return true;
}

/*
* Add a new value to the announcement list or refresh an announcement.
*/
bool kad_announce(FILE *fp, const char query[], time_t lifetime)
{
    return announces_add(fp, query, lifetime) ? true : false;
}

// Lookup known nodes that are nearest to the given id
const struct search_t *kad_lookup(const char query[])
{
    struct search_t *search;

    log_debug("KAD: lookup identifier: %s", query);

    // Find an existing or create new search
    search = searches_start(query);

    if (search == NULL) {
        // Failed to create a new search
        log_debug("KAD: searches_start error");
        return NULL;
    }

    // Start DHT search if search was just started/restarted
    if (search->start_time == time_now_sec()) {
#if 0
        // Search own announces
        kad_lookup_own_announcements(search);
#endif
        log_debug("KAD: Start DHT search");

        // Start a new DHT search
        dht_search(search->id, 0, AF_INET, dht_callback_func, NULL);
        dht_search(search->id, 0, AF_INET6, dht_callback_func, NULL);
    }

    return search;
}

#if 0
/*
* Lookup the address of the node whose node id matches id.
* The lookup will be performed on the results of kad_lookup().
* The port in the returned address refers to the kad instance.
*/
bool kad_lookup_node(const char query[], IP *addr_return)
{
    uint8_t id[ID_BINARY_LENGTH];
    struct search *sr;
    int i;
    bool rc;

    if (base16dec(id, sizeof(id), query, ID_BASE16_LENGTH) != sizeof(id)) {
        return false;
    }

    rc = true;
    sr = searches;
    while (sr) {
        if (sr->af == gconf->af && id_equal(sr->id, id)) {
            for (i = 0; i < sr->numnodes; ++i) {
                if (id_equal(sr->nodes[i].id, id)) {
                    memcpy(addr_return, &sr->nodes[i].ss, sizeof(IP));
                    rc = false;
                    goto done;
                }
            }
            break;
        }
        sr = sr->next;
    }

    done:;

    return rc;
}
#endif

bool kad_block(const IP* addr)
{
    blacklist_node(NULL, (struct sockaddr *) addr, sizeof(IP));

    return true;
}

// Export known peers; the maximum is 400 nodes
int kad_export_peers(FILE *fp)
{
    IP4 addr4[200];
    IP6 addr6[200];

    int num6 = ARRAY_SIZE(addr4);
    int num4 = ARRAY_SIZE(addr6);

    dht_get_nodes(addr4, &num4, addr6, &num6);

    for (size_t i = 0; i < num4; i++) {
#ifdef __CYGWIN__
        fprintf(fp, "%s\r\n", str_addr((IP*) &addr4[i]));
#else
        fprintf(fp, "%s\n", str_addr((IP*) &addr4[i]));
#endif
    }

    for (size_t i = 0; i < num6; i++) {
#ifdef __CYGWIN__
        fprintf(fp, "%s\r\n", str_addr((IP*) &addr6[i]));
#else
        fprintf(fp, "%s\n", str_addr((IP*) &addr6[i]));
#endif
    }

    return num4 + num6;
}

// Print buckets (leaf/finger table)
void kad_print_buckets(FILE* fp)
{
    size_t i, j;

    struct bucket *b = (gconf->af == AF_INET) ? buckets : buckets6;
    for (j = 0; b; ++j) {
        fprintf(fp, " bucket: %s\n", str_id(b->first));

        struct node * n = b->nodes;
        for (i = 0; n; ++i) {
            fprintf(fp, "   id: %s\n", str_id(n->id));
            fprintf(fp, "    address: %s\n", str_addr(&n->ss));
            fprintf(fp, "    pinged: %d\n", n->pinged);
            n = n->next;
        }
        fprintf(fp, "  Found %u nodes.\n", (unsigned) i);
        b = b->next;
    }
    fprintf(fp, "Found %u buckets.\n", (unsigned) j);
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

// Print announced ids we have received
void kad_print_storage(FILE *fp)
{
    size_t i, j;

    struct storage *s = storage;
    for (i = 0; s; ++i) {
        fprintf(fp, " id: %s\n", str_id(s->id));
        for (j = 0; j < s->numpeers; ++j) {
            struct peer *p = &s->peers[j];
            fprintf(fp, "   peer: %s\n", str_addr2(&p->ip[0], p->len, p->port));
        }
        fprintf(fp, "  Found %u peers.\n", (unsigned) j);
        s = s->next;
    }
    fprintf(fp, " Found %u stored hashes from received announcements.\n", (unsigned) i);
}

// Print searches
void kad_print_searches(FILE *fp)
{
    struct search *s;
    int i;
    int j;

    s = searches;
    for (j = 0; s; ++j) {
        fprintf(fp, " DHT-Search: %s\n", str_id(s->id));
        fprintf(fp, "  af: %s\n", (s->af == AF_INET) ? "AF_INET" : "AF_INET6");
        fprintf(fp, "  port: %hu\n", s->port);
        //fprintf(fp, "  done: %d\n", s->done);
        for (i = 0; i < s->numnodes; ++i) {
            struct search_node *sn = &s->nodes[i];
            fprintf(fp, "   Node: %s\n", str_id(sn->id));
            fprintf(fp, "     addr: %s\n", str_addr(&sn->ss));
            fprintf(fp, "     pinged: %d\n", sn->pinged);
            fprintf(fp, "     replied: %d\n", sn->replied);
            fprintf(fp, "     acked: %d\n", sn->acked);
        }
        fprintf(fp, "  Found %d nodes.\n", i);
        s = s->next;
    }

    fprintf(fp, " Found %d searches.\n", j);
}

void kad_print_blocklist(FILE *fp)
{
    size_t i;

    for (i = 0; i < (next_blacklisted % DHT_MAX_BLACKLISTED); i++) {
        fprintf(fp, " %s\n", str_addr(&blacklist[i]));
    }

    fprintf(fp, " Found %u blocked addresses.\n", (unsigned) i);
}

void kad_print_constants(FILE *fp)
{
    fprintf(fp, "DHT_SEARCH_EXPIRE_TIME: %d\n", DHT_SEARCH_EXPIRE_TIME);
    fprintf(fp, "DHT_MAX_SEARCHES: %d\n", DHT_MAX_SEARCHES);

    // Maximum number of announced hashes we track
    fprintf(fp, "DHT_MAX_HASHES: %d\n", DHT_MAX_HASHES);

    // Maximum number of peers for each announced hash we track
    fprintf(fp, "DHT_MAX_PEERS: %d\n", DHT_MAX_PEERS);

    // Maximum number of blocked nodes
    fprintf(fp, "DHT_MAX_BLACKLISTED: %d\n", DHT_MAX_BLACKLISTED);
}
