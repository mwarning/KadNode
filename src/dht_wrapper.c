
#include <netdb.h>
#include <net/if.h>
#include <sys/time.h>

#include "log.h"
#include "sha1.h"
#include "main.h"
#include "utils.h"
#include "conf.h"
#include "results.h"

#include "dht.c"
#include "dht_wrapper.h"

/*
* This is a wrapper for the Kademlia DHT
* that contains the event loop and stores
* the search results.
*/

void dht_lock_init( void ) {
#ifdef PTHREAD
	pthread_mutex_init( &gstate->dht_mutex, NULL );
#endif
}

void dht_lock( void ) {
#ifdef PTHREAD
	pthread_mutex_lock( &gstate->dht_mutex );
#endif
}

void dht_unlock( void ) {
#ifdef PTHREAD
	pthread_mutex_unlock( &gstate->dht_mutex );
#endif
}

/* This callback is called when a search result arrives or a search completes */
void dht_callback_func( void *closure, int event, UCHAR *info_hash, void *data, size_t data_len ) {

	switch( event ) {
		case DHT_EVENT_VALUES:
			results_import( info_hash, data, data_len, AF_INET );
			break;
		case DHT_EVENT_VALUES6:
			results_import( info_hash, data, data_len, AF_INET6 );
			break;
		case DHT_EVENT_SEARCH_DONE:
			results_done( info_hash, AF_INET );
			break;
		case DHT_EVENT_SEARCH_DONE6:
			results_done( info_hash, AF_INET6 );
			break;
	}
}

/* Handle incoming packets and pass them to the DHT code */
void dht_handler( int rc, int sock ) {
	UCHAR buf[1500];
    IP from;
    socklen_t fromlen;
	time_t time_wait = 0;

	if( rc > 0 ) {
		/* Check which socket received the data */
		fromlen = sizeof(from);
		rc = recvfrom( sock, buf, sizeof(buf) - 1, 0, (struct sockaddr*) &from, &fromlen );

		if( rc <= 0 || rc >= sizeof(buf) ) {
			return;
		}

		/* Kademlia expects the message to be null-terminated. */
		buf[rc] = '\0';

		/* Handle incoming data */
		dht_lock();
		rc = dht_periodic( buf, rc, (struct sockaddr*) &from, fromlen, &time_wait, dht_callback_func, NULL );
		dht_unlock();

		if( rc < 0 && errno != EINTR ) {
			if( rc == EINVAL || rc == EFAULT ) {
				log_err( "DHT: Error calling dht_periodic." );
			}
			gstate->time_dht_maintenance = time_now_sec() + 1;
		} else {
			gstate->time_dht_maintenance = time_now_sec() + time_wait;
		}
	} else if( gstate->time_dht_maintenance <= time_now_sec() ) {
		/* Do a maintenance call */
		dht_lock();
		rc = dht_periodic( NULL, 0, NULL, 0, &time_wait, dht_callback_func, NULL );
		dht_unlock();

		/* Wait for the next maintenance call */
		gstate->time_dht_maintenance = time_now_sec() + time_wait;
		log_debug( "DHT: Next maintenance call in %u seconds.", (unsigned int) time_wait );
	} else {
		rc = 0;
	}

	if( rc < 0 ) {
		if( errno == EINTR ) {
			return;
		} else if( rc == EINVAL || rc == EFAULT ) {
			log_err( "DHT: Error using select: %s", strerror( errno ) );
			return;
		} else {
			gstate->time_dht_maintenance = time_now_sec() + 1;
		}
	}
}

/*
* Kademlia needs these functions to be present.
*/

int dht_blacklisted( const struct sockaddr *sa, int salen ) {
    return 0;
}

/* Hashing for the DHT - implementation does not matter for interoperability */
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
