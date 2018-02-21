
#define _WITH_DPRINTF
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "main.h"
#include "conf.h"
#include "utils.h"
#include "log.h"
#include "kad.h"
#include "net.h"
#include "unix.h"
#include "announces.h"
#include "searches.h"
#ifdef BOB
#include "ext-bob.h"
#endif
#ifdef FWD
#include "ext-fwd.h"
#endif
#include "ext-cmd.h"


static const char *g_client_usage =
MAIN_SRVNAME" Control Program - Send commands to a KadNode instance.\n\n"
"Usage: kadnode-ctl [OPTIONS]* [COMMANDS]*\n"
"\n"
" -p <port>	Connect to this unix socket (Default: "CMD_PATH")\n"
" -h		Print this help.\n"
"\n";

static const char* g_server_usage =
	"Usage:\n"
	"	status\n"
	"	lookup <query>\n"
	"	announce [<query>[:<port>] [<minutes>]]\n"
	"	ping <addr>\n";

const char* g_server_usage_debug =
	"	blacklist <addr>\n"
	"	list blacklist|searches|announcements|nodes"
#ifdef FWD
	"|forwardings"
#endif
#ifdef BOB
	"|keys"
#endif
	"|constants\n"
	"	list dht_buckets|dht_searches|dht_storage\n";

static int g_cmd_sock = -1;


static void cmd_ping(FILE *fp, const char addr_str[])
{
	IP addr;
	int rc;

	// If the address contains no port - use the default port
	if ((rc = addr_parse_full(&addr, addr_str, STR(DHT_PORT), gconf->af)) == 0) {
		if (kad_ping(&addr) == 0) {
			fprintf(fp, "Send ping to: %s\n", str_addr(&addr));
			return;
		}
		fprintf(fp, "Failed to send ping.\n");
	} else if (rc == -1) {
		fprintf(fp, "Failed to parse address.\n");
	} else {
		fprintf(fp, "Failed to resolve address.\n");
	}
}

static void cmd_blacklist(FILE *fp, const char *addr_str)
{
	IP addr;

	if (addr_parse(&addr, addr_str, NULL, gconf->af) == 0) {
		kad_blacklist(&addr);
		fprintf(fp, "Added to blacklist: %s\n", str_addr(&addr));
	} else {
		fprintf(fp, "Invalid address.\n");
	}
}

static void cmd_announce(FILE *fp, const char hostname[], int port, int minutes)
{
	time_t lifetime;

	if (minutes < 0) {
		lifetime = LONG_MAX;
	} else {
		// Round up to multiple of 30 minutes
		minutes = (30 * (minutes / 30 + 1));
		lifetime = (time_now_sec() + (minutes * 60));
	}

	if (EXIT_SUCCESS == kad_announce(hostname, port, lifetime)) {
#ifdef FWD
		// Add port forwarding
		fwd_add(port, lifetime);
#endif
		if (minutes < 0) {
			fprintf(fp ,"Start regular announcements for the entire run time (port %d).\n", port);
		} else {
			fprintf(fp ,"Start regular announcements for %d minutes (port %d).\n", minutes, port);
		}
	} else {
		fprintf(fp ,"Invalid port or query too long.\n");
	}
}

// Match a format string with only %n at the end
static int match(const char request[], const char fmt[])
{
	int n = -1;
	sscanf(request, fmt, &n);
	return (n > 0 && request[n] == '\0');
}

static void cmd_exec(FILE *fp, const char request[], int allow_debug)
{
	struct value_t *value;
	int minutes;
	IP addrs[16];
	char hostname[256];
	int count;
	int port;
	size_t i;
	size_t num;
	char d; // dummy marker
	int rc = 0;

	if (sscanf(request, "ping %255s %c", hostname, &d) == 1) {
		cmd_ping(fp, hostname);
	} else if (sscanf(request, "lookup %255s %c", hostname, &d) == 1) {
		// Check searches for node
		num = ARRAY_SIZE(addrs);
		rc = kad_lookup(hostname, addrs, &num);

		if (rc == EXIT_SUCCESS) {
			// Print results
			for (i = 0; i < num; ++i) {
				fprintf(fp, "%s\n", str_addr(&addrs[i]));
			}

			if (num == 0) {
				fprintf(fp ,"Search in progress.\n");
			}
		} else {
			fprintf(fp ,"Some error occured.\n");
		}
	} else if (match(request, "status %n")) {
		// Print node id and statistics
		kad_status(fp);
	} else if (match(request, "announce %n")) {
		// Announce all values
		count = 0;
		value = announces_get();
		while (value) {
			kad_announce_once(value->id, value->port);
			count += 1;
			value = value->next;
		}
		fprintf(fp, "%d announcements started.\n", count);
	} else if (sscanf(request, "announce %255s %c", hostname, &d) == 1) {
		cmd_announce(fp, hostname, 0, -1);
	} else if (sscanf(request, "announce %255[^: ] %d %c", hostname, &minutes, &d) == 2) {
		cmd_announce(fp, hostname, 0, minutes);
	} else if (sscanf(request, "announce %255[^: ]:%d %d %c", hostname, &port, &minutes, &d) == 3) {
		cmd_announce(fp, hostname, port, minutes);
	} else if (match(request, "list %*s %n") && allow_debug) {
		if (sscanf(request, "blacklist %255[^: ]", hostname) == 1) {
			cmd_blacklist(fp, hostname);
		} else if (match(request, "list blacklist %n")) {
			kad_debug_blacklist(fp);
		} else if (match(request, "list constants %n")) {
			kad_debug_constants(fp);
		} else if (match(request, "list nodes %n")) {
			rc = kad_export_nodes(fp);

			if (rc == 0) {
				fprintf(fp, "No good nodes found.\n");
			}
#ifdef FWD
		} else if (match(request, "list forwardings %n")) {
			fwd_debug(fp);
#endif
#ifdef BOB
		} else if (match(request, "list keys %n")) {
			bob_debug_keys(fp);
#endif
		} else if (match(request, "list searches %n")) {
			searches_debug(fp);
		} else if (match(request, "list announcements %n")) {
			announces_debug(fp);
		} else if (match(request, "list dht_buckets %n")) {
			kad_debug_buckets(fp);
		} else if (match(request, "list dht_searches %n")) {
			kad_debug_searches(fp);
		} else if (match(request, "list dht_storage %n")) {
			kad_debug_storage(fp);
		} else {
			fprintf(fp, "Unknown command.\n");
		}
	} else {
		// Print usage
		fprintf(fp, "%s", g_server_usage);

		if (allow_debug) {
			fprintf(fp, "%s", g_server_usage_debug);
		}
	}
}

static void cmd_client_handler(int rc, int clientsock)
{
	char request[256];
	ssize_t size;
	FILE* fp;

	if (rc <= 0) {
		return;
	}

	size = recv(clientsock, request, sizeof(request) - 1, 0);

	if (size > 0) {
		request[size] = '\0';
		// Execute command line
		fp = fdopen(clientsock, "w");

#ifdef DEBUG
		cmd_exec(fp, request, 1);
#else
		cmd_exec(fp, request, 0);
#endif
		fclose(fp);
	} else {
		close(clientsock);
	}

	net_remove_handler(clientsock, &cmd_client_handler);
}

static void cmd_server_handler(int rc, int serversock)
{
	socklen_t addrlen;
	int clientsock;
	struct sockaddr_un addr;

	if (rc <= 0) {
		return;
	}

	addrlen = sizeof(addr);
	clientsock = accept(serversock, (struct sockaddr *) &addr, &addrlen);
	if (clientsock < 0) {
		log_error("accept(): %s", strerror(errno));
		return;
	}

	net_add_handler(clientsock, &cmd_client_handler);
}

static void cmd_console_handler(int rc, int fd)
{
	char request[256];
	char *ptr;

	if (rc <= 0) {
		return;
	}

	// Read line
	ptr = fgets(request, sizeof(request), stdin);
	if (ptr == NULL) {
		return;
	}

	// Output to stdout (not stdin)
	cmd_exec(stdout, request, 1);
}

int cmd_setup(void)
{
	if (EXIT_FAILURE == unix_create_unix_socket(gconf->cmd_path, &g_cmd_sock)) {
		return EXIT_FAILURE;
	} else {
		log_info("CMD: Bind to %s", gconf->cmd_path);

		net_add_handler(g_cmd_sock, &cmd_server_handler);

		if (gconf->is_daemon == 0 && gconf->cmd_disable_stdin == 0) {
			fprintf(stdout, "Press Enter for help.\n");
			net_add_handler(STDIN_FILENO, &cmd_console_handler);
		}

		return EXIT_SUCCESS;
	}
}

void cmd_free(void)
{
	if (g_cmd_sock >= 0) {
		unix_remove_unix_socket(gconf->cmd_path, g_cmd_sock);
	}
}

#ifdef __CYGWIN__
static int select_read(int sockfd, char buffer[], int bufsize, struct timeval *tv)
{
	fd_set rfds;
	int retval;

	FD_ZERO(&rfds);
	FD_SET(sockfd, &rfds);

	retval = select(sockfd + 1, &rfds, NULL, NULL, tv);

	if (retval == -1) {
		// Error
		return -1;
	} else if (retval) {
		// Data available
		return read(sockfd, buffer, bufsize);
	} else {
		// Timeout reached
		return 0;
	}
}
#endif

int cmd_client(int argc, char *argv[])
{
	char buffer[256];
	const char *path;
	struct sockaddr_un addr;
	ssize_t size;
	size_t pos;
	int sock;
	int i;

	// Default unix socket path
	path = CMD_PATH;

	// Skip program name
	argc -= 1;
	argv += 1;

	if (argc >= 1) {
		if (strcmp(argv[0], "-h") == 0) {
			fprintf(stdout, "%s", g_client_usage);
			return EXIT_SUCCESS;
		} else if (strcmp(argv[0], "-p") == 0) {
			if (argc >= 2) {
				path = argv[1];
				// Skip option and path
				argc -= 2;
				argv += 2;
			} else {
				fprintf(stderr, "Path is missing!\n");
				return EXIT_FAILURE;
			}
		}
	}

	// Concatenate arguments
	buffer[0] = ' ';
	buffer[1] = '\0';
	for (i = 0, pos = 1; i < argc; i++) {
		pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s ", argv[i]);
		if (pos >= sizeof(buffer)) {
			fprintf(stderr, "Input too long\n");
			return EXIT_FAILURE;
		}
	}

	sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "socket(): %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, path);

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Failed to connect to '%s': %s\n", path, strerror(errno));
		goto error;
	}

#ifndef __CYGWIN__
	struct timeval tv;

	/* Set receive timeout: 200ms */
	tv.tv_sec = 0;
	tv.tv_usec = 200000;

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0) {
		fprintf(stderr, "setsockopt(): %s\n", strerror(errno));
		goto error;
	}
#endif

	// Send request
	send(sock, buffer, strlen(buffer) + 1, 0);

	while (1) {
		// Receive replies
#ifdef __CYGWIN__
		size = select_read(sock, buffer, strlen(buffer), &tv);
#else
		size = read(sock, buffer, strlen(buffer));
#endif
		if (size <= 0) {
			break;
		}

		buffer[size] = '\0';

		// Print to console
		printf("%s", buffer);
	}

	close(sock);

	return EXIT_SUCCESS;

error:
	if (sock > 0) {
		close(sock);
	}

	return EXIT_FAILURE;
}
