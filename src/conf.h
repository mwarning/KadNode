
#ifndef _CONF_H_
#define _CONF_H_

void conf_init( void );
void conf_load( int argc, char **argv );
void conf_check( void );
void conf_free( void );

void conf_handle( char *var, char *val );

/* value to announce */
struct value {
	UCHAR value_id[SHA1_BIN_LENGTH];
	int port;
	struct value *next;
};

struct gconf_t {

	/* Current time */
	struct timeval time_now;

	/* Identifier of this instance */
	UCHAR node_id[SHA1_BIN_LENGTH];

	/* Drop privileges to user */
	char *user;

	/* Write a pid file if set */
	char *pidfile;

	/* Import/Export peers from this file */
	char *peerfile;

	/* Foreground / Background */
	int is_daemon;

	/* Thread terminator */
	int is_running;

	/* Quiet / Verbose / Debug */
	int verbosity;

	/* Write log to /var/log/message */
	int use_syslog;

	/* IPv4 or IPv6 mode */
	int af;

	/* DHT port number */
	char* dht_port;

	/* DHT interface */
	char *dht_ifce;

	/* DHT multicast address for bootstrapping */
	char *mcast_addr;

	/* KadNode startup time */
	time_t startup_time;

	/* Disable ping on multicast address */
	int disable_multicast;

	/* Disable port forwarding */
	int disable_forwarding;

#ifdef CMD
	char *cmd_port;
#endif

#ifdef DNS
	char *dns_port;
#endif

#ifdef NSS
	char *nss_port;
#endif

#ifdef WEB
	char *web_port;
#endif

	/* Catch signals */
	struct sigaction sig_stop;
	struct sigaction sig_term;

#ifdef PTHREAD
	/* DHT thread stuff */
	pthread_t dht_thread;
	pthread_mutex_t dht_mutex;
#endif
};

extern struct gconf_t *gconf;

#endif /* _CONF_H_ */
