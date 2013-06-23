
#ifndef _CONF_H_
#define _CONF_H_

void conf_init( void );
void conf_load( int argc, char **argv );
void conf_check( void );
void conf_free( void );

struct obj_gstate {

	/* Current time */
	struct timeval time_now;

	/* Identifier of this instance */
	UCHAR node_id[SHA_DIGEST_LENGTH];

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

	int ipv4_only;
	int ipv6_only;

	/* DHT sockets */
	int sock4;
	int sock6;

	/* Port number for the DHT and multicast */
	char* dht_port;

	/* DHT multicast addresses for bootstrapping */
	char *mcast_addr4;
	char *mcast_addr6;

	/* Limit the DHT to this interface */
	char *dht_ifce;

	/* Have the multicast addresses been registered yet? */
	int mcast_registered4;
	int mcast_registered6;

	/* Last performed multicast */
	time_t time_mcast4;
	time_t time_mcast6;

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
