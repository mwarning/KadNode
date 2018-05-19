
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

const char *kadnode_version_str = "KadNode v"MAIN_VERSION" ("
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
"Usage: kadnode [OPTIONS]*\n"
"\n"
" --announce <name>:<port>		Announce a name and port.\n\n"
" --peerfile <file>			Import/Export peers from and to a file.\n\n"
" --peer <addr>				Add a static peer address.\n"
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
" -h, --help				Print this help.\n\n"
" -v, --version				Print program version.\n";


// Set default if setting was not set and validate settings
void conf_defaults(void)
{
	if (gconf->af == 0) {
		gconf->af = AF_UNSPEC;
	}

	if (gconf->query_tld == NULL) {
		gconf->query_tld = strdup(QUERY_TLD_DEFAULT);
	}

	if (gconf->dht_port < 0) {
		gconf->dht_port = DHT_PORT;
	}

#ifdef CMD
	if (gconf->cmd_path == NULL) {
		gconf->cmd_path = strdup(CMD_PATH);
	}
#endif

#ifdef DNS
	if (gconf->dns_port < 0) {
		gconf->dns_port = DNS_PORT;
	}
#endif

#ifdef NSS
	if (gconf->nss_path == NULL) {
		gconf->nss_path = strdup(NSS_PATH);
	}
#endif

	time_t now = time(NULL);
	gconf->time_now = now;
	gconf->startup_time = now;
	gconf->is_running = 1;
}

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
	oLpdAddr,
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

static struct option options[] = {
	{"announce", required_argument, 0, oAnnounce},
	{"query-tld", required_argument, 0, oQueryTld},
	{"pidfile", required_argument, 0, oPidFile},
	{"peerfile", required_argument, 0, oPeerFile},
	{"peer", required_argument, 0, oPeer},
	{"verbosity", required_argument, 0, oVerbosity},
#ifdef CMD
	{"cmd-disable-stdin", no_argument, 0, oCmdDisableStdin},
	{"cmd-port", required_argument, 0, oCmdPath},
#endif
#ifdef DNS
	{"dns-port", required_argument, 0, oDnsPort},
	{"dns-proxy-enable", no_argument, 0, oDnsProxyEnable},
	{"dns-proxy-server", required_argument, 0, oDnsProxyServer},
#endif
#ifdef NSS
	{"nss-path", required_argument, 0, oNssPath},
#endif
#ifdef TLS
	{"tls-client-cert", required_argument, 0, oTlsClientCert},
	{"tls-server-cert", required_argument, 0, oTlsServerCert},
#endif
	{"config", required_argument, 0, oConfig},
	{"port", required_argument, 0, oPort},
	{"ipv4", no_argument, 0, oIpv4},
	{"ipv6", no_argument, 0, oIpv6},
#ifdef LPD
	{"lpd-addr", required_argument, 0, oLpdAddr},
	{"lpd-disable", no_argument, 0, oLpdDisable},
#endif
#ifdef FWD
	{"fwd-disable", no_argument, 0, oFwdDisable},
#endif
#ifdef __CYGWIN__
	{"service-install", no_argument, 0, oServiceInstall},
	{"service-remove", no_argument, 0, oServiceRemove},
	{"service-start", no_argument, 0, oServiceStart},
#endif
#ifdef BOB
	{"bob-create-key", required_argument, 0, oBobCreateKey},
	{"bob-load-key", required_argument, 0, oBobLoadKey},
#endif
	{"ifname", required_argument, 0, oIfname},
	{"user", required_argument, 0, oUser},
	{"daemon", no_argument, 0, oDaemon},
	{"help", no_argument, 0, oHelp},
	{"version", no_argument, 0, oVersion},
	{0, 0, 0, 0}
};

// Set a string once - error when already set
static int conf_str(const char opt[], char *dst[], const char src[])
{
	if (*dst != NULL) {
		log_error("Value was already set for %s: %s", opt, src);
		return 1;
	}

	*dst = strdup(src);
	return 0;
}

static int conf_port(const char opt[], int *dst, const char src[])
{
	int n = port_parse(src, -1);

	if (n < 0) {
		log_error("Invalid port for %s: %s", opt, src);
		return 1;
	}

	if (*dst >= 0) {
		log_error("Value was already set for %s: %s", opt, src);
		return 1;
	}

	*dst = n;
	return 0;
}

// forward declaration
int conf_parse(int argc, char **argv);

static int conf_load_file(const char path[])
{
	char line[256];
	char option[32];
	char value[128];
	char dummy[4];
	char *argv[3];
	char *last;
	struct stat s;
	int ret;
	FILE *file;
	size_t nline;

	if (stat(path, &s) == 0 && !(s.st_mode & S_IFREG)) {
		log_error("File expected: %s", path);
		return 1;
	}

	nline = 0;
	file = fopen(path, "r");
	if (file == NULL) {
		log_error("Cannot open file: %s (%s)", path, strerror(errno));
		return 1;
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

		ret = sscanf(line, " %31s %127s %3s", option, value, dummy);

		if (ret == 1 || ret == 2) {
			// Prevent recursive inclusion
			if (strcmp(option, "--config ") == 0) {
				fclose(file);
				log_error("Option '--config' not allowed inside a configuration file, line %ld.", nline);
				return 1;
			}

			// parse --option value / --option
			argv[0] = (char*) path;
			argv[1] = option;
			argv[2] = value;
			ret = conf_parse(ret + 1, &argv[0]);
			if (ret != 0) {
				fclose(file);
				return 1;
			}
		} else {
			fclose(file);
			log_error("Invalid line in config file: %s (%d)", path, nline);
			return 1;
		}
	}

	fclose(file);
	return 0;
}

// Append to an array (assumes there is alway enough space ...)
static void array_append(const char **array, const char element[])
{
	while (*array) {
		array++;
	}

	*array = strdup(element);
}

// Free array elements
static void array_free(const char **array)
{
	while (*array) {
		free((void*) *array);
		array += 1;
	}
}

int conf_parse(int argc, char **argv)
{
	int index;
	const char *optname;
	int i;
	int c;

	while (1)
	{
		index = 0;
		c = getopt_long(argc, argv, "46vh", options, &index);
		optname = options[index].name;

		switch (c)
		{
		case -1:
			// End of options reached
			for (i = optind; i < argc; i++) {
				log_error("Unknown option: %s\n", argv[i]);
				return 1;
			}
			return 0;
		case '?':
			//log_error("Invalid option: %s", argv[curind]);
			return 1;
		case oAnnounce:
			array_append(&g_announce_args[0], optarg);
			return 0;
		case oQueryTld:
			return conf_str(optname, &gconf->query_tld, optarg);
		case oPidFile:
			return conf_str(optname, &gconf->pidfile, optarg);
		case oPeerFile:
			return conf_str(optname, &gconf->peerfile, optarg);
		case oPeer:
			return peerfile_add_peer(optarg);
		case oVerbosity:
			if (strcmp(optarg, "quiet") == 0) {
				gconf->verbosity = VERBOSITY_QUIET;
			} else if (strcmp(optarg, "verbose") == 0) {
				gconf->verbosity = VERBOSITY_VERBOSE;
			} else if (strcmp(optarg, "debug") == 0) {
				gconf->verbosity = VERBOSITY_DEBUG;
			} else {
				log_error("Invalid argument for %s", optname);
				return 1;
			}
			return 0;
#ifdef CMD
		case oCmdDisableStdin:
			gconf->cmd_disable_stdin = 1;
			return 0;
		case oCmdPath:
			return conf_str(optname, &gconf->cmd_path, optarg);
#endif
#ifdef DNS
		case oDnsPort:
			return conf_port(optname, &gconf->dns_port, optarg);
		case oDnsProxyEnable:
			gconf->dns_proxy_enable = 1;
			return 0;
		case oDnsProxyServer:
			return conf_str(optname, &gconf->dns_proxy_server, optarg);
#endif
#ifdef NSS
		case oNssPath:
			return conf_str(optname, &gconf->nss_path, optarg);
#endif
#ifdef TLS
		case oTlsClientCert:
			array_append(&g_tls_client_args[0], optarg);
			return 0;
		case oTlsServerCert:
			array_append(&g_tls_server_args[0], optarg);
			return 0;
#endif
		case oConfig:
			return conf_str(optname, &gconf->configfile, optarg);
		case '4':
		case '6':
		case oIpv4:
		case oIpv6:
			if (gconf->af != AF_UNSPEC) {
				log_error("IPv4 or IPv6 mode already set: %s", optname);
				return 1;
			}

			gconf->af = (c == oIpv6 || c == '6') ? AF_INET6 : AF_INET;
			return 0;
		case oPort:
			return conf_port(optname, &gconf->dht_port, optarg);
#ifdef LPD
		case oLpdDisable:
			gconf->lpd_disable = 1;
			return 0;
#endif
#ifdef FWD
		case oFwdDisable:
			gconf->fwd_disable = 1;
			return 0;
#endif
#ifdef __CYGWIN__
		case oServiceInstall:
			windows_service_install();
			exit(0);
		case oServiceRemove:
			windows_service_remove();
			exit(0);
		case oServiceStart:
			gconf->service_start = 1;
			return 0;
#endif
		case oIfname:
			return conf_str(optname, &gconf->dht_ifname, optarg);
		case oUser:
			return conf_str(optname, &gconf->user, optarg);
		case oDaemon:
			gconf->is_daemon = 1;
			return 0;
		case 'h':
		case oHelp:
			printf("%s\n", kadnode_usage_str);
			exit(0);
		case 'v':
		case oVersion:
			printf("%s\n", kadnode_version_str);
			exit(0);
#ifdef BOB
		case oBobCreateKey:
			exit(bob_create_key(optarg) < 0);
		case oBobLoadKey:
			return bob_load_key(optarg);
#endif
		default:
			log_error("Unhandled parameter %d", c);
			return 1;
		}
	}
}

// Load some values that depend on proper settings
int conf_load(void)
{
	const char **args;
	int rc = 0;

	args = g_announce_args;
	while (rc == 0 && *args) {
		uint16_t port = gconf->dht_port;
		char name[QUERY_MAX_SIZE] = { 0 };

		int n = sscanf(*args, "%254[^:]:%hu", name, &port);
		if (n == 1 || n == 2) {
			rc = (EXIT_FAILURE == kad_announce(name, port, LONG_MAX));
		} else {
			log_error("Invalid announcement: %s", *args);
			rc = 1;
		}
		args += 1;
	}

#ifdef TLS
	args = g_tls_client_args;
	while (rc == 0 && *args) {
		// Add Certificate Authority (CA) entries for the TLS client
		rc = (EXIT_FAILURE == tls_client_add_ca(*args));
		args += 1;
	}

	args = g_tls_server_args;
	while (rc == 0 && *args) {
		// Add SNI entries for the TLS server (e.g. my.cert,my.key)
		char crt_file[128];
		char key_file[128];

		if (sscanf(*args, "%127[^,],%127[^,]", crt_file, key_file) == 2) {
			rc = (EXIT_FAILURE == tls_server_add_sni(crt_file, key_file));
		} else {
			log_error("Invalid cert/key tuple: %s", *args);
			rc = 1;
		}
		args += 1;
	}
#endif

	array_free(&g_announce_args[0]);
#ifdef TLS
	array_free(&g_tls_client_args[0]);
	array_free(&g_tls_server_args[0]);
#endif

	return (rc != 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}

int conf_setup(int argc, char **argv)
{
	int rc;

	gconf = (struct gconf_t*) calloc(1, sizeof(struct gconf_t));
	*gconf = ((struct gconf_t) {
		.dht_port = -1,
		.af = AF_UNSPEC,
#ifdef DNS
		.dns_port = -1,
#endif
#ifdef DEBUG
		.verbosity = VERBOSITY_DEBUG
#else
		.verbosity = VERBOSITY_VERBOSE
#endif
	});

	rc = conf_parse(argc, argv);

	if (rc == 0 && gconf->configfile) {
		rc = conf_load_file(gconf->configfile);
	}

	// Set defaults for unset settings
	conf_defaults();

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
