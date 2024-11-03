
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>

#include "main.h"
#include "log.h"
#include "utils.h"
#include "conf.h"
#include "peerfile.h"
#include "kad.h"
#include "announces.h"
#ifdef TLS
#include "ext-tls-client.h"
#include "ext-tls-server.h"
#endif
#ifdef BOB
#include "ext-bob.h"
#endif
#ifdef FWD
#include "ext-fwd.h"
#endif
#ifdef __CYGWIN__
#include "windows.h"
#endif

// Global object variables
struct gconf_t *gconf = NULL;

static const char *g_announce_args[64] = { 0 };
#ifdef TLS
static const char *g_tls_client_args[16] = { 0 };
static const char *g_tls_server_args[16] = { 0 };
#endif

const char *kadnode_version_str = PROGRAM_NAME " " PROGRAM_VERSION" ("
#ifdef BOB
" bob"
#endif
#ifdef CMD
" cmd"
#endif
#ifdef DEBUG
" debug"
#endif
#ifdef DNS
" dns"
#endif
#ifdef LPD
" lpd"
#endif
#ifdef FWD_NATPMP
" natpmp"
#endif
#ifdef NSS
" nss"
#endif
#ifdef TLS
" tls"
#endif
#ifdef FWD_UPNP
" upnp"
#endif
" )";

static const char *kadnode_usage_str =
"KadNode is a small decentralized DNS resolver.\n"
"\n"
"Usage: kadnode [OPTIONS]\n"
"\n"
" --announce <query>[:<port>]		Announce a domain name or key.\n\n"
" --peerfile <file>			Import/Export peers from and to a file.\n\n"
" --peer <address>[:<port>]		Add a static peer by IP address or domain name.\n"
"					This option may occur multiple times.\n\n"
" --user <user>				Change the UUID after start.\n\n"
" --port	<port>				Bind DHT to this port.\n"
"					Default: "STR(DHT_PORT)"\n\n"
" --config <file>			Provide a configuration file with one command line\n"
"					option on each line. Comments start after '#'.\n\n"
" --ifname <interface>			Bind to this interface.\n"
"					Default: <any>\n\n"
" --daemon				Run the node in background.\n\n"
" --verbosity <level>			Verbosity level: quiet, verbose or debug.\n"
"					Default: verbose\n\n"
" --pidfile <file>			Write process pid to a file.\n\n"
" --ipv4, -4, --ipv6, -6			Enable IPv4 or IPv6 only mode.\n"
"					Default: IPv4+IPv6\n\n"
" --query-tld <domain>			Top level domain to be handled by KadNode.\n"
"					Default: "QUERY_TLD_DEFAULT"\n\n"
#ifdef LPD
" --lpd-disable				Disable multicast to discover local peers.\n\n"
#endif
#ifdef BOB
" --bob-create-key <file>		Write a new secp256r1 secret key in PEM format to the file.\n"
"					The public key will be printed to the terminal before exit.\n\n"
" --bob-load-key <file>			Read a secret key in PEM format and announce the public key.\n"
"					This option may occur multiple times.\n\n"
#endif
#ifdef CMD
" --cmd-disable-stdin			Disable the local control interface.\n\n"
" --cmd-path <path>			Bind the remote control interface to this unix socket path.\n"
"					Default: "CMD_PATH"\n\n"
#endif
#ifdef DNS
" --dns-port <port>			Bind the DNS server interface to this local port.\n"
"					Default: "STR(DNS_PORT)"\n\n"
" --dns-proxy-enable			Enable DNS proxy mode. The proxy reads /etc/resolv.conf by default.\n\n"
" --dns-proxy-server <ip-addr>		Use IP address of an external DNS server instead of resolv.conf.\n\n"
#endif
#ifdef NSS
" --nss-path <path>			Bind the Network Service Switch to this unix socket path.\n"
"					Default: "NSS_PATH"\n\n"
#endif
#ifdef FWD
" --fwd-disable				Disable UPnP/NAT-PMP to forward router ports.\n\n"
#endif
#ifdef TLS
" --tls-client-cert <path>		Path to file or folder of CA root certificates.\n"
"					This option may occur multiple times.\n\n"
" --tls-server-cert <path>,<path>	Add a comma separated tuple of server certificate file and key.\n"
"					This option may occur multiple times.\n"
"					Example: kadnode.crt,kadnode.key\n\n"
#endif
#ifdef __CYGWIN__
" --service-start			Start, install and remove KadNode as Windows service.\n"
" --service-install			KadNode will be started/shut down along with Windows\n"
" --service-remove			or on request by using the Service Control Manager.\n\n"
#endif
" --dht-isolation-prefix <prefix>	Only peer with nodes that use the same prefix (base16).\n"  
"					This allows an isolated swarm of selected nodes.\n\n"
" -h, --help				Print this help.\n\n"
" -v, --version				Print program version.\n";


const char *verbosity_str(int verbosity)
{
    switch (verbosity) {
    case VERBOSITY_QUIET: return "quiet";
    case VERBOSITY_VERBOSE: return "verbose";
    case VERBOSITY_DEBUG: return "debug";
    default:
        log_error("Invalid verbosity: %d", verbosity);
        exit(1);
    }
}

void conf_info(void)
{
    log_info("Starting %s", kadnode_version_str);
    log_info("Net Mode: %s", str_af(gconf->af));
    log_info("Run Mode: %s", gconf->is_daemon ? "daemon" : "foreground");

    if (gconf->configfile) {
        log_info("Configuration File: %s", gconf->configfile);
    }

    log_info("Verbosity: %s", verbosity_str(gconf->verbosity));
    log_info("Query TLD: %s", gconf->query_tld);
    log_info("Peer File: %s", gconf->peerfile ? gconf->peerfile : "none");
#ifdef LPD
    log_info("Local Peer Discovery: %s", gconf->lpd_disable ? "disabled" : "enabled");
#endif
#ifdef DNS
    if (gconf->dns_proxy_enable) {
        if (gconf->dns_proxy_server) {
            log_info("DNS proxy enabled: %s", gconf->dns_proxy_server);
        } else {
            log_info("DNS proxy enabled: /etc/resolv.conf");
        }
    }
#endif
    if (gconf->dht_isolation_prefix_length > 0) {
        // DHT isolation is enabled
        char buf[DHT_ISOLATION_PREFIX_MAX_LENGTH*2];
        log_info("DHT isolation prefix: %s",
            base16enc(buf, sizeof(buf), &gconf->dht_isolation_prefix[0], gconf->dht_isolation_prefix_length));
    }
}

void conf_free(void)
{
    free(gconf->query_tld);
    free(gconf->user);
    free(gconf->pidfile);
    free(gconf->peerfile);
    free(gconf->dht_ifname);
    free(gconf->configfile);

#ifdef CMD
    free(gconf->cmd_path);
#endif
#ifdef DNS
    free(gconf->dns_proxy_server);
#endif
#ifdef NSS
    free(gconf->nss_path);
#endif

    free(gconf);
}

// Enumerate all options to keep binary size smaller
enum OPCODE {
    oAnnounce,
    oQueryTld,
    oPidFile,
    oPeerFile,
    oPeer,
    oVerbosity,
    oCmdDisableStdin,
    oCmdPath,
    oDhtIsolationPrefix,
    oDnsPort,
    oDnsProxyEnable,
    oDnsProxyServer,
    oNssPath,
    oTlsClientCert,
    oTlsServerCert,
    oConfig,
    oIpv4,
    oIpv6,
    oPort,
    oLpdDisable,
    oFwdDisable,
    oServiceInstall,
    oServiceRemove,
    oServiceStart,
    oBobCreateKey,
    oBobLoadKey,
    oIfname,
    oUser,
    oDaemon,
    oHelp,
    oVersion
};

static option_t g_options[] = {
    {"--announce", 1, oAnnounce},
    {"--query-tld", 1, oQueryTld},
    {"--pidfile", 1, oPidFile},
    {"--peerfile", 1, oPeerFile},
    {"--peer", 1, oPeer},
    {"--verbosity", 1, oVerbosity},
#ifdef CMD
    {"--cmd-disable-stdin", 0, oCmdDisableStdin},
    {"--cmd-path", 1, oCmdPath},
#endif
#ifdef DNS
    {"--dns-port", 1, oDnsPort},
    {"--dns-proxy-enable", 0, oDnsProxyEnable},
    {"--dns-proxy-server", 1, oDnsProxyServer},
#endif
#ifdef NSS
    {"--nss-path", 1, oNssPath},
#endif
#ifdef TLS
    {"--tls-client-cert", 1, oTlsClientCert},
    {"--tls-server-cert", 1, oTlsServerCert},
#endif
    {"--config", 1, oConfig},
    {"--port", 1, oPort},
    {"-4", 0, oIpv4},
    {"--ipv4", 0, oIpv4},
    {"-6", 0, oIpv6},
    {"--ipv6", 0, oIpv6},
#ifdef LPD
    {"--lpd-disable", 0, oLpdDisable},
#endif
#ifdef FWD
    {"--fwd-disable", 0, oFwdDisable},
#endif
#ifdef __CYGWIN__
    {"--service-install", 0, oServiceInstall},
    {"--service-remove", 0, oServiceRemove},
    {"--service-start", 0, oServiceStart},
#endif
#ifdef BOB
    {"--bob-create-key", 1, oBobCreateKey},
    {"--bob-load-key", 1, oBobLoadKey},
#endif
    {"--dht-isolation-prefix", 1, oDhtIsolationPrefix},
    {"--ifname", 1, oIfname},
    {"--user", 1, oUser},
    {"--daemon", 0, oDaemon},
    {"-h", 0, oHelp},
    {"--help", 0, oHelp},
    {"-v", 0, oVersion},
    {"--version", 0, oVersion},
    {NULL, 0, 0}
};

// Set a string once - error when already set
static bool conf_str(const char opt[], char *dst[], const char src[])
{
    if (*dst != NULL) {
        log_error("Value was already set for %s: %s", opt, src);
        return false;
    }

    *dst = strdup(src);
    return true;
}

static bool conf_port(const char opt[], int *dst, const char src[])
{
    int n = parse_int(src, -1);

    if (!port_valid(n)) {
        log_error("Invalid port for %s: %s", opt, src);
        return false;
    }

    if (*dst >= 0) {
        log_error("Value was already set for %s: %s", opt, src);
        return false;
    }

    *dst = n;
    return true;
}

// forward declaration
static bool conf_set(const char opt[], const char val[]);

static bool conf_load_file(const char path[])
{
    char option[32];
    char value[256];
    char line[32 + 256];
    char dummy[4];
    char *last;
    struct stat s;
    int ret;
    FILE *file;
    size_t nline;

    if (stat(path, &s) == 0 && !(s.st_mode & S_IFREG)) {
        log_error("File expected: %s", path);
        return false;
    }

    nline = 0;
    file = fopen(path, "r");
    if (file == NULL) {
        log_error("Cannot open file: %s (%s)", path, strerror(errno));
        return false;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        nline += 1;

        // Cut off comments
        last = strchr(line, '#');
        if (last) {
            *last = '\0';
        }

        if (line[0] == '\n' || line[0] == '\0') {
            continue;
        }

        ret = sscanf(line, " %31s%*[ ]%255s %3s", option, value, dummy);

        if (ret == 1 || ret == 2) {
            // Prevent recursive inclusion
            if (strcmp(option, "--config ") == 0) {
                fclose(file);
                log_error("Option '--config' not allowed inside a configuration file, line %ld.", nline);
                return false;
            }

            // parse --option value / --option
            if (!conf_set(option, (ret == 2) ? value : NULL)) {
                fclose(file);
                return false;
            }
        } else {
            fclose(file);
            log_error("Invalid line in config file: %s (%d)", path, nline);
            return false;
        }
    }

    fclose(file);
    return true;
}

// Append to an array
static bool array_append(const char **array, size_t array_length, const char element[])
{
    size_t i = 0;

    while ((i < array_length) && (array[i] != NULL)) {
        i += 1;
    }

    if (i < array_length) {
        array[i] = strdup(element);
        return true;
    } else {
        return false;
    }
}

// Free array elements
static void array_free(const char **array)
{
    while (*array) {
        free((void*) *array);
        array += 1;
    }
}

static bool conf_set(const char opt[], const char val[])
{
    const option_t *option = find_option(g_options, opt);

    if (option == NULL) {
        log_error("Unknown parameter: %s", opt);
        return false;
    }

    if (option->num_args == 1 && val == NULL) {
        log_error("Argument expected for option: %s", opt);
        return false;
    }

    if (option->num_args == 0 && val != NULL) {
        log_error("No argument expected for option: %s", opt);
        return false;
    }

    switch (option->code)
    {
    case oAnnounce:
        if (!array_append(&g_announce_args[0], ARRAY_SIZE(g_announce_args), val)) {
            log_error("Too many announcements.");
            return false;
        }
        break;
    case oQueryTld:
        // ignore old dot prefix
        if (val[0] == '.') {
            val++;
        }
        return conf_str(opt, &gconf->query_tld, val);
    case oPidFile:
        return conf_str(opt, &gconf->pidfile, val);
    case oPeerFile:
        return conf_str(opt, &gconf->peerfile, val);
    case oPeer:
        return peerfile_add_peer(val);
    case oVerbosity:
        if (strcmp(val, "quiet") == 0) {
            gconf->verbosity = VERBOSITY_QUIET;
        } else if (strcmp(val, "verbose") == 0) {
            gconf->verbosity = VERBOSITY_VERBOSE;
        } else if (strcmp(val, "debug") == 0) {
            gconf->verbosity = VERBOSITY_DEBUG;
        } else {
            log_error("Invalid argument for %s", opt);
            return false;
        }
        break;
#ifdef CMD
    case oCmdDisableStdin:
        gconf->cmd_disable_stdin = true;
        break;
    case oCmdPath:
        if (strlen(val) > FIELD_SIZEOF(struct sockaddr_un, sun_path) - 1) {
            log_error("Path too long for %s", opt);
            return false;
        }
        return conf_str(opt, &gconf->cmd_path, val);
#endif
#ifdef DNS
    case oDnsPort:
        return conf_port(opt, &gconf->dns_port, val);
    case oDnsProxyEnable:
        gconf->dns_proxy_enable = true;
        break;
    case oDnsProxyServer:
        return conf_str(opt, &gconf->dns_proxy_server, val);
#endif
#ifdef NSS
    case oNssPath:
        return conf_str(opt, &gconf->nss_path, val);
#endif
#ifdef TLS
    case oTlsClientCert:
        if (!array_append(&g_tls_client_args[0], ARRAY_SIZE(g_tls_client_args), val)) {
            log_error("Too many TLS client certificate entries");
            return false;
        }
        break;
    case oTlsServerCert:
        if (!array_append(&g_tls_server_args[0], ARRAY_SIZE(g_tls_server_args), val)) {
            log_error("Too many TLS server certificate entries");
            return false;
        }
        break;
#endif
    case oConfig:
        return conf_str(opt, &gconf->configfile, val);
    case oIpv4:
    case oIpv6:
        if (gconf->af != -1) {
            log_error("Network mode already set: %s", opt);
            return false;
        }

        gconf->af = (option->code == oIpv6) ? AF_INET6 : AF_INET;
        break;
    case oPort:
        return conf_port(opt, &gconf->dht_port, val);
#ifdef LPD
    case oLpdDisable:
        gconf->lpd_disable = true;
        break;
#endif
#ifdef FWD
    case oFwdDisable:
        gconf->fwd_disable = true;
        break;
#endif
#ifdef __CYGWIN__
    case oServiceInstall:
        windows_service_install();
        exit(0);
    case oServiceRemove:
        windows_service_remove();
        exit(0);
    case oServiceStart:
        gconf->service_start = true;
        break;
#endif
    case oDhtIsolationPrefix: {
        int vlen = strlen(val);
        uint8_t prefix[DHT_ISOLATION_PREFIX_MAX_LENGTH];
        uint8_t plen = base16decsize(vlen);
        if (vlen == 0 || !base16dec(prefix, sizeof(prefix), val, vlen)) {
            log_error("DHT isolation prefix is not a base16 string of max %d bytes: %s", sizeof(prefix), val);
            return false;
        }

        gconf->dht_isolation_prefix_length = plen;
        memcpy(&gconf->dht_isolation_prefix[0], prefix, plen);
        return true;
    }
    case oIfname:
        return conf_str(opt, &gconf->dht_ifname, val);
    case oUser:
        return conf_str(opt, &gconf->user, val);
    case oDaemon:
        gconf->is_daemon = true;
        break;
    case oHelp:
        printf("%s\n", kadnode_usage_str);
        exit(0);
    case oVersion:
        printf("%s\n", kadnode_version_str);
        exit(0);
#ifdef BOB
    case oBobCreateKey: {
        bool success = bob_create_key(val);
        exit(success ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    case oBobLoadKey:
        return bob_load_key(val);
#endif
    default:
        return false;
    }

    return true;
}

// Load some values that depend on proper settings
bool conf_load(void)
{
    const char **args;
    bool rc = true;

    args = g_announce_args;

    while (rc && *args) {
        rc = announces_add(NULL, *args, LONG_MAX) ? true : false;
        args += 1;
    }

#ifdef TLS
    args = g_tls_client_args;
    while (rc && *args) {
        // Add Certificate Authority (CA) entries for the TLS client
        rc = tls_client_add_ca(*args);
        args += 1;
    }

    args = g_tls_server_args;
    while (rc && *args) {
        // Add SNI entries for the TLS server (e.g. my.cert,my.key)
        char crt_file[128];
        char key_file[128];

        if (sscanf(*args, "%127[^,],%127[^,]", crt_file, key_file) == 2) {
            rc = tls_server_add_sni(crt_file, key_file);
        } else {
            log_error("Invalid cert/key tuple: %s", *args);
            rc = false;
        }
        args += 1;
    }
#endif

    array_free(&g_announce_args[0]);
#ifdef TLS
    array_free(&g_tls_client_args[0]);
    array_free(&g_tls_server_args[0]);
#endif

    return rc;
}

static struct gconf_t *conf_alloc()
{
    struct gconf_t *conf;
    time_t now = time(NULL);

    conf = (struct gconf_t*) calloc(1, sizeof(struct gconf_t));
    *conf = ((struct gconf_t) {
        .dht_port = -1,
        .af = -1,
#ifdef DNS
        .dns_port = -1,
#endif
#ifdef DEBUG
        .verbosity = VERBOSITY_DEBUG,
#else
        .verbosity = VERBOSITY_VERBOSE,
#endif
        .query_tld = strdup(QUERY_TLD_DEFAULT),
#ifdef CMD
        .cmd_path = strdup(CMD_PATH),
#endif
#ifdef NSS
        .nss_path = strdup(NSS_PATH),
#endif
        .time_now = now,
        .startup_time = now,
        .is_running = true
    });

    return conf;
}

static void conf_set_defaults()
{
    if (gconf->af == -1) {
        gconf->af = AF_UNSPEC;
    }

    if (gconf->dht_port == -1) {
        gconf->dht_port = DHT_PORT;
    }

#ifdef DNS
    if (gconf->dns_port == -1) {
        gconf->dns_port = DNS_PORT;
    }
#endif
}

bool conf_setup(int argc, char **argv)
{
    const char *opt;
    const char *val;

    gconf = conf_alloc();

    for (size_t i = 1; i < argc; ++i) {
        opt = argv[i];
        val = argv[i + 1];

        if (val && val[0] != '-') {
            // -x abc
            if (!conf_set(opt, val)) {
                return false;
            }
            i += 1;
        } else {
            // -x
            if (!conf_set(opt, NULL)) {
                return false;
            }
        }
    }

    conf_set_defaults();

    if (gconf->configfile) {
        if (!conf_load_file(gconf->configfile)) {
            return false;
        }
    }

    return true;
}
