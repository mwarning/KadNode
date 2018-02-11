
#define _GNU_SOURCE

#include <sys/time.h>
#include <assert.h>

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
void to_addr( IP *out_addr, const void *in_addr, size_t len, uint16_t port ) {
	memset( out_addr, '\0', sizeof(IP) );

	if( len == 4 ) {
		IP4 *a = (IP4 *) out_addr;
		a->sin_family = AF_INET;
		a->sin_port = port;
		memcpy( &a->sin_addr.s_addr, in_addr, 4 );
	}

	if( len == 16 ) {
		IP6 *a = (IP6 *) out_addr;
		a->sin6_family = AF_INET6;
		a->sin6_port = port;
		memcpy( &a->sin6_addr.s6_addr, in_addr, 16 );
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
void dht_callback_func( void *closure, int event, const uint8_t *info_hash, const void *data, size_t data_len ) {
	struct search_t *search;
	dht_addr4_t *data4;
	dht_addr6_t *data6;
	IP addr;
	size_t i;

	search = searches_find_by_id( info_hash );

	if( search == NULL ) {
		return;
	}

	switch( event ) {
		case DHT_EVENT_VALUES:
			data4 = (dht_addr4_t *) data;
			for( i = 0; i < (data_len / sizeof(dht_addr4_t)); ++i ) {
				to_addr( &addr, &data4[i].addr, 4, data4[i].port );
				searches_add_addr( search, &addr );
			}
			break;
		case DHT_EVENT_VALUES6:
			data6 = (dht_addr6_t *) data;
			for( i = 0; i < (data_len / sizeof(dht_addr6_t)); ++i ) {
				to_addr( &addr, &data6[i].addr, 16, data6[i].port );
				searches_add_addr( search, &addr );
			}
			break;
		case DHT_EVENT_SEARCH_DONE:
		case DHT_EVENT_SEARCH_DONE6:
			// Ignore..
			break;
	}
}

/*
* Lookup in values we announce ourselves.
* Useful for networks of only one node, also faster.
*/
void kad_lookup_own_announcements(struct search_t *search)
{
	struct value_t* value;
	int af;
	IP addr;

	// 127.0.0.1
	const uint32_t inaddr_loopback = htonl(INADDR_LOOPBACK);

	af = gconf->af;
	value = announces_find(search->id);
	if (value) {
		if (af == AF_UNSPEC || af == AF_INET6) {
			to_addr(&addr, &in6addr_loopback, 16, htons(value->port)); // ::1
			searches_add_addr(search, &addr);
			log_debug("KAD: Address found in own announcements: %s", str_addr(&addr));
		}

		if (af == AF_UNSPEC || af == AF_INET) {
			to_addr(&addr, &inaddr_loopback, 4, htons(value->port)); // 127.0.0.1
			searches_add_addr(search, &addr);
			log_debug("KAD: Address found in own announcements: %s", str_addr(&addr));
		}
	}
}

// Handle incoming packets and pass them to the DHT code
void dht_handler(int rc, int sock)
{
	uint8_t buf[1500];
	uint32_t buflen;
	IP from;
	socklen_t fromlen;
	time_t time_wait = 0;

	if (rc > 0) {
		// Check which socket received the data
		fromlen = sizeof(from);
		buflen = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr*) &from, &fromlen);

		if (buflen <= 0 || buflen >= sizeof(buf)) {
			return;
		}

		// The DHT code expects the message to be null-terminated.
		buf[buflen] = '\0';
	} else {
		buflen = 0;
	}

#ifdef BOB
	// Hook up BOB extension on the DHT socket
	if (bob_handler(sock, buf, buflen, &from) == 0) {
		return;
	}
#endif

	if (buflen > 0) {
		// Handle incoming data
		rc = dht_periodic(buf, buflen, (struct sockaddr*) &from, fromlen, &time_wait, dht_callback_func, NULL);

		if (rc < 0 && errno != EINTR) {
			if (rc == EINVAL || rc == EFAULT) {
				log_error("KAD: Error calling dht_periodic.");
				exit(1);
			}
			g_dht_maintenance = time_now_sec() + 1;
		} else {
			g_dht_maintenance = time_now_sec() + time_wait;
		}
	} else if (g_dht_maintenance <= time_now_sec()) {
		// Do a maintenance call
		rc = dht_periodic(NULL, 0, NULL, 0, &time_wait, dht_callback_func, NULL);

		// Wait for the next maintenance call
		g_dht_maintenance = time_now_sec() + time_wait;
		log_debug("KAD: Next maintenance call in %u seconds.", (unsigned int) time_wait);
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

int dht_sendto(int sockfd, const void *buf, int len, int flags, const struct sockaddr *to, int tolen)
{
    return sendto(sockfd, buf, len, flags, to, tolen);
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

void kad_setup(void)
{
	uint8_t node_id[SHA1_BIN_LENGTH];

#ifdef DEBUG
	// Let the DHT output debug text
	dht_debug = stdout;
#endif

	bytes_random(node_id, SHA1_BIN_LENGTH);

	g_dht_socket4 = net_bind("KAD", "0.0.0.0", gconf->dht_port, gconf->dht_ifname, IPPROTO_UDP);
	g_dht_socket6 = net_bind("KAD", "::", gconf->dht_port, gconf->dht_ifname, IPPROTO_UDP);

	if (g_dht_socket4 >= 0) {
		net_add_handler(g_dht_socket4, &dht_handler);
	}

	if (g_dht_socket6 >= 0) {
		net_add_handler(g_dht_socket6, &dht_handler);
	}

	// Init the DHT.  Also set the sockets into non-blocking mode.
	if (dht_init(g_dht_socket4, g_dht_socket6, node_id, (uint8_t*) "KN\0\0") < 0) {
		log_error("KAD: Failed to initialize the DHT.");
		exit(1);
	}
}

void kad_free(void)
{
	// Nothing to do
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

int kad_count_nodes(int good)
{
	// Count nodes in IPv4 and IPv6 buckets
	return kad_count_bucket(buckets, good) + kad_count_bucket(buckets6, good);
}

void kad_status(FILE *fp)
{
	struct storage *strg = storage;
	struct search *srch = searches;
	struct value_t *announces = announces_get();
	int numsearches_active = 0;
	int numsearches_done = 0;
	int numstorage = 0;
	int numstorage_peers = 0;
	int numannounces = 0;

	// Count searches
	while (srch) {
		if (srch->done) {
			numsearches_done += 1;
		} else {
			numsearches_active += 1;
		}
		srch = srch->next;
	}

	// Count storage and peers
	while (strg) {
		numstorage_peers += strg->numpeers;
		numstorage += 1;
		strg = strg->next;
	}

	while (announces) {
		numannounces += 1;
		announces = announces->next;
	}

	// Use dht data structure!
	int nodes4 = kad_count_bucket(buckets, 0);
	int nodes6 = kad_count_bucket(buckets6, 0);
	int nodes4_good = kad_count_bucket(buckets, 1);
	int nodes6_good = kad_count_bucket(buckets6, 1);

	fprintf(
		fp,
		"%s\n"
		"DHT id: %s\n"
		"DHT listen on: %s / %s\n"
		"DHT Nodes: %d IPv4 (%d good), %d IPv6 (%d good)\n"
		"DHT Storage: %d (max %d) entries with %d addresses (max %d)\n"
		"DHT Searches: %d active, %d completed (max %d)\n"
		"DHT Announcements: %d\n"
		"DHT Blacklist: %d (max %d)\n",
		kadnode_version_str,
		str_id(myid),
		str_af(gconf->af), gconf->dht_ifname ? gconf->dht_ifname : "<any>",
		nodes4, nodes4_good, nodes6, nodes6_good,
		numstorage, DHT_MAX_HASHES, numstorage_peers, DHT_MAX_PEERS,
		numsearches_active, numsearches_done, DHT_MAX_SEARCHES,
		numannounces,
		(next_blacklisted % DHT_MAX_BLACKLISTED), DHT_MAX_BLACKLISTED
	);
}

int kad_ping(const IP* addr)
{
	int rc;

	rc = dht_ping_node((struct sockaddr *)addr, addr_len(addr));

	return (rc < 0) ? -1 : 0;
}

/*
* Find nodes that are near the given id and announce to them
* that this node can satisfy the given id on the given port.
*/
int kad_announce_once(const uint8_t id[], int port)
{

	if (port < 1 || port > 65535) {
		log_debug("KAD: Invalid port for announcement: %d", port);
		return EXIT_FAILURE;
	}

	dht_search(id, port, AF_INET, dht_callback_func, NULL);
	dht_search(id, port, AF_INET6, dht_callback_func, NULL);

	return EXIT_SUCCESS;
}

/*
* Add a new value to the announcement list or refresh an announcement.
*/
int kad_announce(const char query[], int port, time_t lifetime)
{
	char hostname[QUERY_MAX_SIZE];

	// Remove .p2p suffix and convert to lowercase
	if (EXIT_FAILURE == query_sanitize(hostname, sizeof(hostname), query)) {
		return EXIT_FAILURE;
	}

	// Store query to call kad_announce_once() later/multiple times
	return announces_add(hostname, port, lifetime) ? EXIT_SUCCESS : EXIT_FAILURE;
}

// Lookup known nodes that are nearest to the given id
int kad_lookup(const char query[], IP addr_array[], size_t *addr_num)
{
	char hostname[QUERY_MAX_SIZE];
	struct search_t *search;

	// Remove .p2p suffix and convert to lowercase
	if (EXIT_FAILURE == query_sanitize(hostname, sizeof(hostname), query)) {
		log_debug("KAD: query_sanitize error");
		return EXIT_FAILURE;
	}

	log_debug("KAD: Lookup identifier: %s", hostname);

	// Find existing or create new search
	search = searches_start(hostname);

	if (search == NULL) {
		// Failed to create a new search
		log_debug("KAD: searches_start error");
		return EXIT_FAILURE;
	}

	// Search was just started
	if (search->start_time == time_now_sec()) {
		// Search own announces
		kad_lookup_own_announcements(search);

		// Start a new DHT search
		dht_search(search->id, 0, AF_INET, dht_callback_func, NULL);
		dht_search(search->id, 0, AF_INET6, dht_callback_func, NULL);
	}

	// Collect addresses to be returned
	*addr_num = searches_collect_addrs(search, addr_array, *addr_num);
	return EXIT_SUCCESS;
}

#if 0
/*
* Lookup the address of the node whose node id matches id.
* The lookup will be performed on the results of kad_lookup().
* The port in the returned address refers to the kad instance.
*/
int kad_lookup_node(const char query[], IP *addr_return)
{
	uint8_t id[SHA1_BIN_LENGTH];
	struct search *sr;
	int i, rc;

	if (EXIT_FAILURE == bytes_from_base16hex(id, query, SHA1_HEX_LENGTH) {
		return EXIT_FAILURE;
	}

	rc = 1;
	sr = searches;
	while (sr) {
		if (sr->af == gconf->af && id_equal(sr->id, id)) {
			for (i = 0; i < sr->numnodes; ++i) {
				if (id_equal( sr->nodes[i].id, id)) {
					memcpy(addr_return, &sr->nodes[i].ss, sizeof(IP));
					rc = 0;
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

int kad_blacklist(const IP* addr)
{

	blacklist_node(NULL, (struct sockaddr *) addr, sizeof(IP));

	return EXIT_SUCCESS;
}

// Export known nodes; the maximum is 200 nodes
int kad_export_nodes(FILE *fp)
{
	IP4 addr4[150];
	IP6 addr6[150];
	int num4;
	int num6;
	int i;

	num6 = ARRAY_SIZE(addr4);
	num4 = ARRAY_SIZE(addr6);

	dht_get_nodes(addr4, &num4, addr6, &num6);

	for (i = 0; i < num4; i++) {
#ifdef __CYGWIN__
		fprintf(fp, "%s\r\n", str_addr((IP*) &addr4[i]));
#else
		fprintf(fp, "%s\n", str_addr((IP*) &addr4[i]));
#endif
	}

	for (i = 0; i < num6; i++) {
#ifdef __CYGWIN__
		fprintf(fp, "%s\r\n", str_addr((IP*) &addr6[i]));
#else
		fprintf(fp, "%s\n", str_addr((IP*) &addr6[i]));
#endif
	}

	return num4 + num6;
}

// Print buckets (leaf/finger table)
void kad_debug_buckets(FILE* fp)
{
	struct bucket *b;
	struct node *n;
	int i, j;

	b = (gconf->af == AF_INET) ? buckets : buckets6;
	for (j = 0; b; ++j) {
		fprintf(fp, " Bucket: %s\n", str_id(b->first));

		n = b->nodes;
		for (i = 0; n; ++i) {
			fprintf(fp, "   Node: %s\n", str_id(n->id));
			fprintf(fp, "    addr: %s\n", str_addr(&n->ss));
			fprintf(fp, "    pinged: %d\n", n->pinged);
			n = n->next;
		}
		fprintf(fp, "  Found %d nodes.\n", i);
		b = b->next;
	}
	fprintf(fp, " Found %d buckets.\n", j);
}

// Print searches
void kad_debug_searches(FILE *fp)
{
	struct search *s;
	int i;
	int j;

	s = searches;
	for (j = 0; s; ++j) {
		fprintf(fp, " DHT-Search: %s\n", str_id(s->id));
		fprintf(fp, "  af: %s\n", (s->af == AF_INET) ? "AF_INET" : "AF_INET6");
		fprintf(fp, "  port: %hu\n", s->port);
		//fprintf(fp, "  done: %d\n", s->done );
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

// Print announced ids we have received
void kad_debug_storage(FILE *fp)
{
	struct storage *s;
	struct peer* p;
	IP addr;
	int i, j;

	s = storage;
	for (j = 0; s; ++j) {
		fprintf(fp, " id: %s\n", str_id( s->id));
		for (i = 0; i < s->numpeers; ++i) {
			p = &s->peers[i];
			to_addr(&addr, &p->ip, p->len, htons(p->port));
			fprintf(fp, "   peer: %s\n", str_addr(&addr));
		}
		fprintf(fp, "  Found %d peers.\n", i);
		s = s->next;
	}
	fprintf(fp, " Found %d stored hashes from received announcements.\n", j);
}

void kad_debug_blacklist(FILE *fp)
{
	int i;

	for (i = 0; i < (next_blacklisted % DHT_MAX_BLACKLISTED); i++) {
		fprintf(fp, " %s\n", str_addr(&blacklist[i]));
	}

	fprintf(fp, " Found %d blacklisted addresses.\n", i);
}

void kad_debug_constants(FILE *fp)
{
	fprintf(fp, "DHT_SEARCH_EXPIRE_TIME: %d\n", DHT_SEARCH_EXPIRE_TIME);
	fprintf(fp, "DHT_MAX_SEARCHES: %d\n", DHT_MAX_SEARCHES);

	// Maximum number of announced hashes we track
	fprintf(fp, "DHT_MAX_HASHES: %d\n", DHT_MAX_HASHES);

	// Maximum number of peers for each announced hash we track
	fprintf(fp, "DHT_MAX_PEERS: %d\n", DHT_MAX_PEERS);

	// Maximum number of blacklisted nodes
	fprintf(fp, "DHT_MAX_BLACKLISTED: %d\n", DHT_MAX_BLACKLISTED);
}
