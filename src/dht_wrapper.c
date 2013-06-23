
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
* This is a wrapper for the Kademlia DHT.
*/

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
int buckets_empty( struct bucket *bucket ) {
	while( bucket ) {
		if( bucket->count > 0 ) {
			return 0;
		}
		bucket = bucket->next;
	}
	return 1;
}

time_t time_now_sec( void ) {
	return gstate->time_now.tv_sec;
}

time_t time_add_5_min( void ) {
	return time_now_sec() + 300;
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

/* Bootstrap using IPv4 multicast */
void multicast_boostrap4( IP4 *addr ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	struct ip_mreq mreq;

	/* Try to register multicast address */
	if( gstate->mcast_registered4 == 0 ) {

		memset( &mreq, '\0', sizeof(mreq) );
		memcpy( &mreq.imr_multiaddr, &addr->sin_addr, sizeof(mreq.imr_multiaddr) );

		/* Using an interface index of x is indicated by 0.0.0.x */
		if( gstate->dht_ifce && ((mreq.imr_interface.s_addr = htonl( if_nametoindex( gstate->dht_ifce )) ) == 0) ) {
			log_err( "DHT: Cannot find interface '%s' for multicast: %s", gstate->dht_ifce, strerror( errno ) );
		} else {
			mreq.imr_interface.s_addr = 0;
		}

		if( setsockopt( gstate->sock4, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq) ) < 0) {
			log_warn( "DHT: Failed to register multicast address: %s", strerror( errno ) );
			return;
		} else {
			log_info( "DHT: Registered IPv4 multicast address." );
			gstate->mcast_registered4 = 1;
		}
	}

	log_info( "DHT: Send ping to %s", str_addr4( addr, addrbuf ) );

	/* Send ping */
	dht_lock();
	dht_ping_node( (struct sockaddr *)addr, sizeof(IP4) );
	dht_unlock();
}

/* Bootstrap using IPv6 multicast */
void multicast_boostrap6( IP6 *addr ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	struct ipv6_mreq mreq;

	/* Try to register multicast address */
	if( gstate->mcast_registered6 == 0 ) {

		memset( &mreq, '\0', sizeof(mreq) );
		memcpy( &mreq.ipv6mr_multiaddr, &addr->sin6_addr, sizeof(mreq.ipv6mr_multiaddr) );

		if( gstate->dht_ifce && ((mreq.ipv6mr_interface = if_nametoindex( gstate->dht_ifce )) == 0) ) {
			log_err( "DHT: Cannot find interface '%s' for multicast: %s", gstate->dht_ifce, strerror( errno ) );
		}

		if( setsockopt( gstate->sock6, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) != 0 ) {
			log_warn( "DHT: Failed to register multicast address. Try again later..." );
			return;
		} else {
			log_info( "DHT: Registered IPv6 multicast address." );
			gstate->mcast_registered6 = 1;
		}
	}

	log_info( "DHT: Send ping to %s", str_addr6( addr, addrbuf ) );

	/* Send ping */
	dht_lock();
	dht_ping_node( (struct sockaddr *)addr, sizeof(IP6) );
	dht_unlock();
}

int udp_bind( const char* addr, const char* port, const char* ifce, int af ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	int sock;
	int val;
	IP sockaddr;

	if( af != AF_INET && af != AF_INET6 ) {
		log_err( "DHT: Unknown address family value." );
		return -1;
	}

	if( addr_parse( &sockaddr, addr, port, af ) != 0 ) {
		log_err( "DHT: Failed to parse ip address '%s' and port '%s'.", addr, port );
	}

	sock = socket( sockaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP );

	if( sock < 0 ) {
		log_err( "DHT: Failed to create socket: %s", strerror( errno ) );
		return -1;
	}

	val = 1;
	if ( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val) ) < 0 ) {
		log_err( "DHT: Failed to set socket option SO_REUSEADDR: %s", strerror( errno ));
		return -1;
	}

	if( ifce && setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, ifce, strlen( ifce ) ) ) {
		log_warn( "DHT: Unable to bind to device '%s': %s", ifce, strerror( errno ) );
		return -1;
	}

	if( af == AF_INET6 ) {
		val = 1;
		if( setsockopt( sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val) ) < 0 ) {
			log_err( "DHT: Failed to set socket option IPV6_V6ONLY: %s", strerror( errno ));
			return -1;
		}
	}

	if( bind( sock, (struct sockaddr*) &sockaddr, sizeof(IP) ) < 0 ) {
		log_warn( "DHT: Failed to bind socket to address: '%s'", strerror( errno ) );
		close( sock );
		return -1;
	}

	log_info( ifce ? "DHT: Bind to %s, interface %s" : "DHT: Bind to %s" ,
		str_addr( &sockaddr, addrbuf ), ifce
	);

	return sock;
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
	struct timeval tv;
	fd_set basefds;
	fd_set workfds;
	IP4 mcast_addr4;
	IP6 mcast_addr6;

	/* shortcut */
	const int s4 = gstate->sock4;
	const int s6 = gstate->sock6;

	if( addr_parse( (IP *) &mcast_addr4, gstate->mcast_addr4, gstate->dht_port, AF_INET ) != 0 ) {
		log_err( "DHT: Failed to parse ip address for '%s'.", gstate->mcast_addr4 );
	}

	if( addr_parse( (IP *) &mcast_addr6, gstate->mcast_addr6, gstate->dht_port, AF_INET6 ) != 0 ) {
		log_err( "DHT: Failed to parse ip address for '%s'.", gstate->mcast_addr6 );
	}

	/* Verifiy IPv4 multicast address */
	octet = ((UCHAR *)&mcast_addr4.sin_addr)[0];
	if( octet != 224 && octet != 239 ) {
		log_err( "DHT: Multicast address expected: %s", str_addr4( &mcast_addr4, addrbuf ) );
	}

	/* Verifiy IPv6 multicast address */
	octet = ((UCHAR *)&mcast_addr6.sin6_addr)[0];
	if( octet != 0xFF ) {
		log_err( "DHT: Multicast address expected: %s", str_addr6( &mcast_addr6, addrbuf ) );
	}

	/* Prepare a basic fd set */
	FD_ZERO( &basefds );

	if( s6 >= 0 ) {
		FD_SET( s6, &basefds );
	}

	if( s4 >= 0 ) {
		FD_SET( s4, &basefds );
	}

	time_wait = 0;
	while( gstate->is_running ) {

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		/* Update clock */
		gettimeofday( &gstate->time_now, NULL );

		if( s6 >= 0 && buckets_empty( buckets6 ) && gstate->time_mcast6 <= time_now_sec() ) {
			multicast_boostrap6( &mcast_addr6 );

			/* Try again in ~5 minutes */
			gstate->time_mcast6 = time_add_5_min();
		}

		if( s4 >= 0 && buckets_empty( buckets ) && gstate->time_mcast4 <= time_now_sec() ) {
			multicast_boostrap4( &mcast_addr4 );

			/* Try again in ~5 minutes */
			gstate->time_mcast4 = time_add_5_min();
		}

		/* Initialize fd set from base */
		memcpy( &workfds, &basefds, sizeof(basefds) );

        rc = select( MAX(s4, s6) + 1, &workfds, NULL, NULL, &tv );

		if( rc > 0 ) {
			/* Check which socket received the data */
			fromlen = sizeof(from);
			if( s4 >= 0 && FD_ISSET( s4, &workfds ) ) {
				rc = recvfrom( s4, buf, sizeof(buf) - 1, 0, (struct sockaddr*) &from, &fromlen );
			} else if( s6 >= 0 && FD_ISSET( s6, &workfds ) ) {
				rc = recvfrom( s6, buf, sizeof(buf) - 1, 0, (struct sockaddr*) &from, &fromlen );
			} else {
				log_crit( "DHT: Cannot identify socket we received the data from." );
				return NULL;
			}

			/* Kademlia expects the message to be null-terminated. */
			buf[rc] = '\0';

			/* Handle incoming data */
			dht_lock();
			rc = dht_periodic( buf, rc, (struct sockaddr*) &from, fromlen, &time_wait, NULL, NULL );
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
			rc = dht_periodic( NULL, 0, NULL, 0, &time_wait, NULL, NULL );
			dht_unlock();

			/* Wait for the next maintenance call */
			time_maintenance = time_now_sec() + time_wait;
			log_debug("DHT: Next maintenance call in %ul seconds.", time_wait);
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

	if( s6 >= 0 ) {
		close( s6 );
	}

	if( s4 >= 0 ) {
		close( s4 );
	}

	return NULL;
}

void kad_init( void ) {

	/* Let the DHT output debug text */
	if( gstate->verbosity == VERBOSITY_DEBUG ) {
		dht_debug = stdout;
	}

	dht_lock_init();

	if( !gstate->ipv6_only ) {
		gstate->sock4 = udp_bind( DHT_ADDR4, gstate->dht_port, gstate->dht_ifce, AF_INET );
	}

	if( !gstate->ipv4_only ) {
		gstate->sock6 = udp_bind( DHT_ADDR6, gstate->dht_port, gstate->dht_ifce, AF_INET6 );
	}

	if( gstate->sock6 < 0 && gstate->sock4 < 0 ) {
		log_err( "DHT: No socket has been initialized." );
	}

	/* Init the DHT.  Also set the sockets into non-blocking mode. */
	if( dht_init( gstate->sock4, gstate->sock6, gstate->node_id, (UCHAR*) "KN\0\0") < 0 ) {
		log_err( "DHT: Failed to initialize the DHT." );
	}
}

void kad_start( void ) {
	pthread_attr_t attr;
	pthread_attr_init( &attr );
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_JOINABLE );

	if( pthread_create( &gstate->dht_thread, &attr, &dht_loop, NULL ) != 0 ) {
		log_crit( "DHT: Failed to create thread." );
	}
}

void kad_stop( void ) {
	if( pthread_join( gstate->dht_thread, NULL ) != 0 ) {
		log_err( "DHT: Failed to join thread." );
	}
}

#ifdef DEBUG
/* Print buckets (leaf/finger table) */
void kad_debug_buckets( int fd, struct bucket *b ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	char hexbuf[HEX_LEN+1];
	struct node *n;
	int i, j;

	for( j = 0; b != NULL; ++j ) {
		dprintf( fd, " Bucket: %s\n", str_id( b->first, hexbuf ) );

		n = b->nodes;
		for( i = 0; n != NULL; ++i ) {
			dprintf( fd, "   Node: %s\n", str_id( n->id, hexbuf ) );
			dprintf( fd, "    addr %s\n", str_addr( &n->ss, addrbuf ) );
			dprintf( fd, "    pinged %d\n", n->pinged );
			n = n->next;
		}
		dprintf( fd, "  Found %d nodes.\n", i );
		b = b->next;
	}
	dprintf( fd, " Found %d buckets.\n", j );
}

/* Print searches */
void kad_debug_searches( int fd ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	char hexbuf[HEX_LEN+1];
	struct search *s = searches;
	int i, j;

	for( j = 0; s != NULL; ++j ) {
		dprintf( fd, " Search: %s\n", str_id( s->id, hexbuf ) );
		dprintf( fd, "  port %d\n", s->port );
		dprintf( fd, "  done %d\n", s->done );
		for(i = 0; i < s->numnodes; ++i) {
			struct search_node *sn = &s->nodes[i];
			dprintf( fd, "  Node: %s\n", str_id(sn->id, hexbuf ) );
			dprintf( fd, "   addr: %s\n", str_addr( &sn->ss, addrbuf ) );
			dprintf( fd, "   pinged: %d\n", sn->pinged );
			dprintf( fd, "   replied: %d\n", sn->replied );
			dprintf( fd, "   acked: %d\n", sn->acked );
		}
		dprintf( fd, "  Found %d nodes.\n", i );
		s = s->next;
	}
	dprintf( fd, " Found %d searches.\n", j );
}

/* Print announced ids we have received */
void kad_debug_storage( int fd ) {
	char hexbuf[HEX_LEN+1];
	struct storage *s = storage;
	int i, j;

	for( j = 0; s != NULL; ++j ) {
		dprintf( fd, "Id: %s\n", str_id(s->id, hexbuf ));
		for( i = 0; i < s->numpeers; ++i ) {
			struct peer* p = &s->peers[i];
			dprintf( fd, "  Peer: %s %d %d\n", p->ip, p->len, p->port );
		}
		dprintf( fd, " Found %d peers.\n", i );
		s = s->next;
	}
	dprintf( fd, " Found %d stored hashes from received announcements.\n", j );
}

void kad_debug_blacklist( int fd ) {
	char addrbuf[FULL_ADDSTRLEN+1];
	int i;

	for( i = 0; i < (next_blacklisted % DHT_MAX_BLACKLISTED); i++ ) {
		dprintf( fd, " %s\n", str_addr( &blacklist[i], addrbuf) );
	}

	dprintf( fd, " Found %d blacklisted addresses.\n", i );
}

void kad_debug( int fd ) {

	dprintf( fd, "DHT_SEARCH_EXPIRE_TIME: %d\n", DHT_SEARCH_EXPIRE_TIME );
	dprintf( fd, "DHT_MAX_SEARCHES: %d\n", DHT_MAX_SEARCHES );

	/* maximum number of announced hashes we track */
	dprintf( fd, "DHT_MAX_HASHES: %d\n", DHT_MAX_HASHES );

	/* maximum number of peers for each announced hash we track */
	dprintf( fd, "DHT_MAX_PEERS: %d\n", DHT_MAX_PEERS );

	/* maximum number of blacklisted nodes */
	dprintf( fd, "DHT_MAX_BLACKLISTED: %d\n", DHT_MAX_BLACKLISTED );

	dht_lock();

	dprintf( fd, "\nIPv4 buckets:\n" );
	kad_debug_buckets( fd, buckets );

	dprintf( fd, "\nIPv6 buckets:\n" );
	kad_debug_buckets( fd, buckets6 );

	dprintf( fd, "\nSearches:\n" );
	kad_debug_searches( fd );

	dprintf( fd, "\nStorage:\n" );
	kad_debug_storage( fd );

	dprintf( fd, "\nBlacklist:\n" );
	kad_debug_blacklist( fd );

	dht_unlock();
}
#endif

#define bprintf(...) (written += snprintf( buf+written, size-written, __VA_ARGS__))

int kad_status( char *buf, int size ) {
	char hexbuf[HEX_LEN+1];
	struct storage *strg = storage;
	struct search *srch = searches;
	int numsearches_active = 0;
	int numsearches_done = 0;
	int numstorage = 0;
	int numstorage_peers = 0;
	int written = 0;

	/* count searches */
	while( srch != NULL ) {
		if( srch->done ) {
			numsearches_done++;
		} else {
			numsearches_active++;
		}
		srch = srch->next;
	}

	/* count storage and peers */
	while( strg != NULL ) {
		numstorage_peers += strg->numpeers;
		numstorage++;
		strg = strg->next;
	}

	bprintf( "Own id: %s\n", str_id( myid, hexbuf ) );
	bprintf( "Nodes: %d (IPv6), %d (IPv4)\n",
		count_nodes( buckets6 ), count_nodes( buckets ) );
	bprintf( "Storage: %d (max %d), %d peers (max %d per storage)\n",
		numstorage, DHT_MAX_HASHES, numstorage_peers, DHT_MAX_PEERS );
	bprintf( "Searches: %d active, %d completed (max %d)\n",
		numsearches_active, numsearches_done, DHT_MAX_SEARCHES );
	bprintf( "Blacklist: %d (max %d)\n",
		(next_blacklisted % DHT_MAX_BLACKLISTED), DHT_MAX_BLACKLISTED );

	return written;
}


void kad_ping( const IP* addr ) {
	dht_lock();
	dht_ping_node( (struct sockaddr *)addr, addr_len(addr) );
	dht_unlock();
}

/*
* Find nodes that are near the given id and annouce
* that this node can satisfy the given id on the given port
*/
int kad_announce( int af, const UCHAR *id, unsigned short port ) {

	if( port < 1 || port > 65535 ) {
		return 1;
	}

	dht_lock();

	if( af == AF_UNSPEC ) {
		dht_search( id, port, AF_INET6, NULL, NULL );
		dht_search( id, port, AF_INET, NULL, NULL );
	} else {
		dht_search( id, port, af, NULL, NULL );
	}

	dht_unlock();

	return 0;
}

/*
* Start a search for nodes that are near the given id.
*/
int kad_search( int af, const UCHAR *id ) {

	dht_lock();

	if( af == AF_UNSPEC ) {
		dht_search( id, 0, AF_INET6, NULL, NULL );
		dht_search( id, 0, AF_INET, NULL, NULL );
	} else {
		dht_search( id, 0, af, NULL, NULL );
	}

	dht_unlock();

	return 0;
}

/*
* Lookup known nodes that are nearest to the given id.
* The port refers to the id.
*/
int kad_lookup_values( int af, const UCHAR* id, IP addr_array[], int *addr_num ) {
	struct search *sr;
	int i, rc;

	dht_lock();

	rc = 1;
	sr = searches;
    while( sr ) {
		if( (af == AF_UNSPEC || sr->af == af) && sr->done && memcmp( sr->id, id, 20 ) == 0 ) {
			*addr_num = MIN(sr->numnodes, *addr_num);
			for( i = 0; i < *addr_num; ++i) {
				memcpy( &addr_array[i], &sr->nodes[i].ss, sizeof(IP) );
			}
			rc = 0;
			break;
		}
        sr = sr->next;
    }

	dht_unlock();

	return rc;
}

/*
* Lookup the address of the node that has the given id.
* The port refers to the kad instance.
*/
int kad_lookup_node( int af, const UCHAR* id, IP *addr_return ) {
	struct search *sr;
	int i, rc;

	dht_lock();

	rc = 1;
	sr = searches;
    while( sr ) {
		if( (af == AF_UNSPEC || sr->af == af) && memcmp( sr->id, id, 20 ) == 0 ) {
			for( i = 0; i < sr->numnodes; ++i ) {
				if( memcmp( &sr->nodes[i].id, id, 20 ) == 0 ) {
					memcpy( addr_return, &sr->nodes[i].ss, sizeof(IP) );
					rc = 0;
					goto done;
				}
			}
			if( sr->done == 0 ) {
				/* Search still in progress */
				rc = 2;
			} else {
				/* Search already done */
				rc = 3;
			}
			break;
		}
        sr = sr->next;
    }

	done:;

	dht_unlock();

	return rc;
}

int kad_blacklist( const IP* addr ) {

	dht_lock();
	blacklist_node( NULL, (struct sockaddr *) addr, sizeof(IP) );
	dht_unlock();
	
	return 0;
}

int kad_export_nodes( int af, IP addr_array[], int *num ) {
	IP4 addr4[32];
	IP6 addr6[32];
	int num4 = 0;
	int num6 = 0;
	int i, count;

	switch( af ) {
		case AF_UNSPEC:
			num4 = N_ELEMS( addr4 );
			num6 = N_ELEMS( addr6 );
			break;
		case AF_INET6:
			num6 = N_ELEMS( addr6 );
			break;
		case AF_INET:
			num4 = N_ELEMS( addr4 );
			break;
		default:
			return 1;
	}

	dht_lock();
	dht_get_nodes( addr4, &num4, addr6, &num6 );
	dht_unlock();

	count = 0;

	for( i = 0; i < num6 && count < *num; ++i, ++count ) {
		memcpy( addr_array, addr6, sizeof(IP6) );
	}

	for( i = 0; i < num4 && count < *num; ++i, ++count ) {
		memcpy( addr_array, addr4, sizeof(IP4) );
	}

	/* store number of nodes we have actually found */
	*num = count;

	return 0;
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
