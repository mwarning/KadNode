
#define _GNU_SOURCE

#include <pthread.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/time.h>

#include "log.h"
#include "sha1.h"
#include "main.h"
#include "utils.h"
#include "conf.h"
#include "dht.c"
#include "dht_wrapper.h"


/*
* This is a wrapper for the Kademlia DHT
* that contains the event loop and stores
* the search results.
*/

#define MAX_VALUE_SEARCH_RESULTS 16

#define EXPIRE_SEARCH_RESULT 60


/* Searches along with received addresses */
struct value_search {
	/* The value id to search for */
	UCHAR id[SHA_DIGEST_LENGTH];
	int af;
	time_t start_time;
	/* These nodes have announced that the can satisfy id */
	IP addrs[MAX_VALUE_SEARCH_RESULTS];
	size_t numaddrs;
	int done;

	struct value_search* next;
};

struct value_search* value_searches = NULL;
int num_value_searches = 0;

/* Count all nodes in the given bucket */
int count_nodes( struct bucket *bucket ) {
	int count = 0;
	while( bucket ) {
		count += bucket->count;
		bucket = bucket->next;
	}
	return count;
}

/* Check if any nodes are in the bucket */
int buckets_empty( void ) {
	struct bucket *bucket;

	bucket = (gstate->af == AF_INET ) ? buckets : buckets6;

	while( bucket ) {
		if( bucket->count > 0 ) {
			return 0;
		}
		bucket = bucket->next;
	}
	return 1;
}

int cmp_id( const UCHAR *id1, const UCHAR *id2 ) {
	return (memcmp( id1, id2, SHA_DIGEST_LENGTH ) == 0);
}

time_t time_now_sec( void ) {
	return gstate->time_now.tv_sec;
}

time_t time_add_5_min( void ) {
	return time_now_sec() + 300;
}

time_t time_add_2_min( void ) {
	return time_now_sec() + 120;
}

void dht_lock_init( void ) {
	pthread_mutex_init( &gstate->dht_mutex, NULL );
}

void dht_lock( void ) {
	pthread_mutex_lock( &gstate->dht_mutex );
}

void dht_unlock( void ) {
	pthread_mutex_unlock( &gstate->dht_mutex );
}

/* Send a ping over IPv4 multicast to find other nodes */
void multicast_ping4( IP *addr ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	struct ip_mreq mreq;

	/* Try to register multicast address */
	if( gstate->mcast_registered == 0 ) {

		memset( &mreq, '\0', sizeof(mreq) );
		memcpy( &mreq.imr_multiaddr, &((IP4 *)addr)->sin_addr, sizeof(mreq.imr_multiaddr) );

		/* Using an interface index of x is indicated by 0.0.0.x */
		if( gstate->dht_ifce && ((mreq.imr_interface.s_addr = htonl( if_nametoindex( gstate->dht_ifce )) ) == 0) ) {
			log_err( "DHT: Cannot find interface '%s' for multicast: %s", gstate->dht_ifce, strerror( errno ) );
		} else {
			mreq.imr_interface.s_addr = 0;
		}

		if( setsockopt( gstate->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq) ) < 0) {
			log_warn( "DHT: Failed to register multicast address: %s", strerror( errno ) );
			return;
		} else {
			log_info( "DHT: Registered IPv4 multicast address." );
			gstate->mcast_registered = 1;
		}
	}

	log_info( "DHT: Send ping to %s", str_addr( addr, addrbuf ) );

	/* Send ping */
	dht_lock();
	dht_ping_node( (struct sockaddr *)addr, sizeof(IP4) );
	dht_unlock();
}

/* Send a ping over IPv6 multicast to find other nodes */
void multicast_ping6( IP *addr ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	struct ipv6_mreq mreq;

	/* Try to register multicast address */
	if( gstate->mcast_registered == 0 ) {

		memset( &mreq, '\0', sizeof(mreq) );
		memcpy( &mreq.ipv6mr_multiaddr, &((IP6 *)addr)->sin6_addr, sizeof(mreq.ipv6mr_multiaddr) );

		if( gstate->dht_ifce && ((mreq.ipv6mr_interface = if_nametoindex( gstate->dht_ifce )) == 0) ) {
			log_err( "DHT: Cannot find interface '%s' for multicast: %s", gstate->dht_ifce, strerror( errno ) );
		}

		if( setsockopt( gstate->sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) != 0 ) {
			log_warn( "DHT: Failed to register multicast address. Try again later..." );
			return;
		} else {
			log_info( "DHT: Registered IPv6 multicast address." );
			gstate->mcast_registered = 1;
		}
	}

	log_info( "DHT: Send ping to %s", str_addr( addr, addrbuf ) );

	/* Send ping */
	dht_lock();
	dht_ping_node( (struct sockaddr *)addr, sizeof(IP6) );
	dht_unlock();
}

/* Find a value search result */
struct value_search* vs_find( const UCHAR *id, int af ) {
	struct value_search* vs;

	vs = value_searches;
	while( vs != NULL ) {
		if(  cmp_id( vs->id, id ) && vs->af == af ) {
			return vs;
		}
		vs = vs->next;
	}

	return NULL;
}

void vs_expire() {
	struct value_search* pre = NULL;
	struct value_search* vs = value_searches;
	struct value_search *next = NULL;

    while( vs ) {
        next = vs->next;
        if( vs->start_time < (now.tv_sec - EXPIRE_SEARCH_RESULT) ) {
            if( pre ) {
                pre->next = next;
            } else {
                value_searches = next;
			}
            free( vs );
            num_value_searches--;
        } else {
            pre = vs;
        }
        vs = next;
    }
}

int vs_insert( const UCHAR *id, int af ) {
	struct value_search* vs;
	struct value_search* vss;

	if( num_value_searches > 64 ) {
		return 1;
	}

	vs = vs_find( id, af );

	/* Search exists */
	if( vs != NULL ) {
		return 0;
	}

	vs = calloc( 1, sizeof(struct value_search ) );
	if( vs == NULL ) {
		return 0;
	}

	memcpy( vs->id, id, SHA_DIGEST_LENGTH );
	vs->af = af;
	vs->start_time = now.tv_sec;

	num_value_searches++;

	if( value_searches == NULL ) {
		value_searches = vs;
		return 1;
	}

	vss = value_searches;
	while( 1 ) {
		if( vss->next == NULL ) {
			vss->next = vs;
			return 1;
		}
		vss = vss->next;
	}

	return 1;
}

typedef struct {
	UCHAR addr[16];
	unsigned short port;
} ADDR6;

typedef struct {
	UCHAR addr[4];
	unsigned short port;
} ADDR4;

/* Add an address to an array if it is not already contained in there */
void vs_add_unique( struct value_search *vs, IP* addr ) {
	int i;

	if( vs->numaddrs >= MAX_VALUE_SEARCH_RESULTS ) {
		return;
	}

	for( i = 0; i < vs->numaddrs; i++ ) {
		if( memcmp( &vs->addrs[i], addr, sizeof(IP) ) == 0 ) {
			return;
		}
	}

	memcpy( &vs->addrs[vs->numaddrs], addr, sizeof(IP) );
	vs->numaddrs++;
}

/* This callback is called when a search result arrives or a search completes */
void dht_callback_func( void *closure, int event, UCHAR *info_hash, void *data, size_t data_len ) {
	struct value_search* vs;
	IP addr;
	int af;
	int i;

	if( event == DHT_EVENT_SEARCH_DONE6 || event == DHT_EVENT_VALUES6 ) {
		af = AF_INET6;
	} else {
		af = AF_INET;
	}

	/* Find search to put results into */
	if( (vs = vs_find( info_hash, af )) == NULL ) {
		return;
	}

	if( event == DHT_EVENT_VALUES ) {

		ADDR4 *data4 = (ADDR4 *) data;
		size_t data4_len = MIN(data_len / sizeof(ADDR4), MAX_VALUE_SEARCH_RESULTS);
		IP4 *a = (IP4 *)&addr;

		for( i = 0; i < data4_len; i++ ) {
			memset( &addr, '\0', sizeof(IP) );
			a->sin_family = AF_INET;
			a->sin_port = data4[i].port;
			memcpy( &a->sin_addr, &data4[i].addr, 4 );
			vs_add_unique( vs, &addr );
		}

	} else if( event == DHT_EVENT_VALUES6 ) {

		ADDR6 *data6 = (ADDR6 *) data;
		size_t data6_len = MIN(data_len / sizeof(ADDR6), MAX_VALUE_SEARCH_RESULTS);
		IP6 *a = (IP6 *)&addr;

		for( i = 0; i < data6_len; i++ ) {
			memset( &addr, '\0', sizeof(IP) );
			a->sin6_family = AF_INET6;
			a->sin6_port = data6[i].port;
			memcpy( &a->sin6_addr, &data6[i].addr, 16 );
			vs_add_unique( vs, &addr );
		}

	} else if( event == DHT_EVENT_SEARCH_DONE || event == DHT_EVENT_SEARCH_DONE6 ) {
		vs->done = 1;
	}
}


/* Create a IPv4/IPv6 dual server and let the */
void *dht_loop( void *arg ) {
	UCHAR buf[1500];
	char addrbuf[FULL_ADDSTRLEN+1];
	UCHAR octet;
	int rc;
    IP from;
    socklen_t fromlen;
	time_t time_wait = 0;
	time_t time_maintenance = 0;
	time_t time_value_search = 0;
	struct timeval tv;
	fd_set workfds;
	IP mcast_addr;

	if( addr_parse( &mcast_addr, gstate->mcast_addr, gstate->dht_port, gstate->af ) != 0 ) {
		log_err( "DHT: Failed to parse ip address for '%s'.", gstate->mcast_addr );
	}

	if( gstate->af == AF_INET ) {
		/* Verifiy IPv4 multicast address */
		octet = ((UCHAR *) &((IP4 *)&mcast_addr)->sin_addr)[0];
		if( octet != 224 && octet != 239 ) {
			log_err( "DHT: Multicast address expected: %s", str_addr( &mcast_addr, addrbuf ) );
		}
	} else {
		/* Verifiy IPv6 multicast address */
		octet = ((UCHAR *)&((IP6 *)&mcast_addr)->sin6_addr)[0];
		if( octet != 0xFF ) {
			log_err( "DHT: Multicast address expected: %s", str_addr( &mcast_addr, addrbuf ) );
		}
	}

	time_wait = 0;
	while( gstate->is_running ) {

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		/* Update clock */
		gettimeofday( &gstate->time_now, NULL );

		/* Send multicast ping */
		if( buckets_empty() && gstate->time_mcast <= time_now_sec() ) {
			if( gstate->af == AF_INET ) {
				multicast_ping4( &mcast_addr );
			} else {
				multicast_ping6( &mcast_addr );
			}
			/* Try again in ~5 minutes */
			gstate->time_mcast = time_add_5_min();
		}

		/* Expire value searches */
		if( time_value_search <= time_now_sec() ) {
			dht_lock();
			vs_expire();
			dht_unlock();

			/* Try again in ~2 minutes */
			time_value_search = time_add_2_min();
		}

		/* Prepare a basic fd set */
		FD_ZERO( &workfds );
		FD_SET( gstate->sock, &workfds );

        rc = select( gstate->sock + 1, &workfds, NULL, NULL, &tv );

		if( rc > 0 ) {
			/* Check which socket received the data */
			fromlen = sizeof(from);
			if( FD_ISSET( gstate->sock, &workfds ) ) {
				rc = recvfrom( gstate->sock, buf, sizeof(buf) - 1, 0, (struct sockaddr*) &from, &fromlen );
			} else {
				log_crit( "DHT: Cannot identify socket we received the data from." );
				return NULL;
			}

			/* Kademlia expects the message to be null-terminated. */
			buf[rc] = '\0';

			/* Handle incoming data */
			dht_lock();
			rc = dht_periodic( buf, rc, (struct sockaddr*) &from, fromlen, &time_wait, dht_callback_func, NULL );
			dht_unlock();

			if( rc < 0 && errno != EINTR ) {
				if( rc == EINVAL || rc == EFAULT ) {
					log_err("DHT: Error calling dht_periodic.");
				}
				time_maintenance = time_now_sec() + 1;
			}
		} else if( time_maintenance <= time_now_sec() ) {
			/* Do a maintenance call */
			dht_lock();
			rc = dht_periodic( NULL, 0, NULL, 0, &time_wait, dht_callback_func, NULL );
			dht_unlock();

			/* Wait for the next maintenance call */
			time_maintenance = time_now_sec() + time_wait;
			log_debug("DHT: Next maintenance call in %u seconds.", (unsigned int) time_wait);
		} else {
			rc = 0;
		}

		if( rc < 0 ) {
			if( errno == EINTR ) {
				continue;
			} else if(rc == EINVAL || rc == EFAULT) {
				log_err( "DHT: Error using select: %s", strerror( errno ) );
				return NULL;
			} else {
				time_maintenance = time_now_sec() + 1;
			}
		}
    }

	close( gstate->sock );

	return NULL;
}

/*
* Kademlia needs these functions to be present.
*/

int dht_blacklisted( const struct sockaddr *sa, int salen ) {
    return 0;
}

void dht_hash( void *hash_return, int hash_size,
	const void *v1, int len1,
	const void *v2, int len2,
	const void *v3, int len3
) {
    SHA1_CTX ctx;

    SHA1_Init( &ctx );
    if(v1) SHA1_Update( &ctx, v1, len1 );
	if(v2) SHA1_Update( &ctx, v2, len2 );
	if(v3) SHA1_Update( &ctx, v3, len3 );
    SHA1_Final( &ctx, hash_return );
}

int dht_random_bytes( void *buf, size_t size ) {
	return id_random( buf, size );
}
