
#ifndef _CONF_H_
#define _CONF_H_

#include <time.h>
#include <stdbool.h>
#include <stdint.h>

// Measurement duration for traffic
#define TRAFFIC_DURATION_SECONDS 8

extern const char *kadnode_version_str;

bool conf_setup(int argc, char **argv);
bool conf_load(void);
void conf_info(void);
void conf_free(void);

struct gconf_t {
    // Current time
    time_t time_now;

    // KadNode startup time
    time_t startup_time;

    // Drop privileges to user
    char *user;

    // Top level domain used by KadNode (e.g. ".p2p")
    char *query_tld;

    // Write a pid file if set
    char *pidfile;

    // Import/Export peers from this file
    char *peerfile;

    // Path to configuration file
    char *configfile;

    // Start in Foreground / Background
    bool is_daemon;

    // Thread terminator
    bool is_running;

    // Quiet / Verbose / Debug
    int verbosity;

    // Write log to /var/log/message
    int use_syslog;

    // Net mode (AF_INET / AF_INET6 / AF_UNSPEC)
    int af;

    // DHT port number
    int dht_port;

    // DHT interface
    char *dht_ifname;

#ifdef __CYGWIN__
    // Start as windows service
    int service_start;
#endif

#ifdef FWD
    // Disable port forwarding
    bool fwd_disable;
#endif

#ifdef LPD
    // Disable ping on multicast address
    bool lpd_disable;
#endif

#ifdef CMD
    char *cmd_path;
    bool cmd_disable_stdin;
#endif

#ifdef DNS
    int dns_port;
    bool dns_proxy_enable;
    char *dns_proxy_server;
#endif

#ifdef NSS
    char *nss_path;
#endif

    // Traffic measurement
    time_t traffic_time;
    uint64_t traffic_in_sum;
    uint64_t traffic_out_sum;
    uint32_t traffic_in[TRAFFIC_DURATION_SECONDS];
    uint32_t traffic_out[TRAFFIC_DURATION_SECONDS];
};

extern struct gconf_t *gconf;

#endif // _CONF_H_
