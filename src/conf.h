
#ifndef _CONF_H_
#define _CONF_H_

void conf_init( void );
void conf_load( int argc, char **argv );
void conf_check( void );
void conf_free( void );

/* value to announce */
struct value {
	UCHAR value_id[SHA_DIGEST_LENGTH];
	int port;
	struct value *next;
};

struct obj_gstate {

	/* Current time */
	struct timeval time_now;

	/* Identifier of this instance */
	UCHAR node_id[SHA_DIGEST_LENGTH];

	/* Values that will be announced regulary */
	struct value *values;

	/* Drop privileges to user */
	char *user;

	/* Write a pid file if set */
	char *pid_file;

	/* Foreground / Background */
	int is_daemon;

	/* Thread terminator */
	int is_running;

	/* Quiet / Verbose / Debug */
	int verbosity;

	/* IPv4 or IPv6 mode */
	int af;

	/* DHT socket */
	int sock;

	/* DHT port number */
	char* dht_port;

	/* DHT interface */
	char *dht_ifce;

	/* DHT multicast address for bootstrapping */
	char *mcast_addr;

	/* Indicates if the multicast addresses has been registered */
	int mcast_registered;

	/* Last performed multicast ping */
	time_t time_mcast;

#ifdef CMD
	char *cmd_port;
	pthread_t cmd_thread;
#endif

#ifdef DNS
	char *dns_port;
	pthread_t dns_thread;
#endif

#ifdef NSS
	char *nss_port;
	pthread_t nss_thread;
#endif

#ifdef WEB
	char *web_port;
	pthread_t web_thread;
#endif

	/* Catch signals */
	struct sigaction sig_stop;
	struct sigaction sig_term;

	/* DHT thread stuff */
	pthread_t dht_thread;
	pthread_mutex_t dht_mutex;
};

extern struct obj_gstate *gstate;

#endif /* _CONF_H_ */
