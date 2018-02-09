
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
#include <arpa/inet.h>
#include <sys/un.h>

#include "main.h"
#include "conf.h"
#include "utils.h"
#include "log.h"
#include "kad.h"
#include "net.h"
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

const char* g_server_usage_debug = "0"
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


static void r_printf(int fd, const char *format, ...)
{
	char buffer[512];
	va_list vlist;
	int rc;

	va_start(vlist, format);
	rc = vsnprintf(buffer, sizeof(buffer), format, vlist);
	va_end(vlist);

	if (rc > 0 && rc < sizeof(buffer)) {
		if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
			write(fd, buffer, strlen(buffer));
		} else {
			send(fd, buffer, strlen(buffer), 0);
		}
	} else {
		log_error("Command buffer too small");
	}
}

static void cmd_ping(int fd, const char addr_str[])
{
	IP addr;
	int rc;

	// If the address contains no port - use the default port
	if ((rc = addr_parse_full(&addr, addr_str, STR(DHT_PORT), gconf->af)) == 0) {
		if(kad_ping(&addr) == 0) {
			r_printf(fd, "Send ping to: %s\n", str_addr(&addr));
			return;
		}
		r_printf(fd, "Failed to send ping.\n");
	} else if (rc == -1) {
		r_printf(fd, "Failed to parse address.\n");
	} else {
		r_printf(fd, "Failed to resolve address.\n");
	}
}

static void cmd_print_status(int fd)
{
	char buffer[512];
	int rc;

	rc = kad_status(buffer, sizeof(buffer));

	if (rc > 0 && rc < sizeof(buffer)) {
		r_printf(fd, buffer);
	} else {
		log_error("Command buffer too small");
	}
}

static void cmd_blacklist(int fd, const char *addr_str)
{
	IP addr;

	if (addr_parse(&addr, addr_str, NULL, gconf->af) == 0) {
		kad_blacklist(&addr);
		r_printf(fd, "Added to blacklist: %s\n", str_addr(&addr));
	} else {
		r_printf(fd, "Invalid address.\n");
	}
}

static void cmd_announce(int fd, const char hostname[], int port, int minutes)
{
	time_t lifetime;

	if (minutes < 0) {
		lifetime = LONG_MAX;
	} else {
		// Round up to multiple of 30 minutes
		minutes = (30 * (minutes / 30 + 1));
		lifetime = (time_now_sec() + (minutes * 60));
	}

	if (kad_announce(hostname, port, lifetime) >= 0) {
#ifdef FWD
		// Add port forwarding
		fwd_add(port, lifetime);
#endif
		if (minutes < 0) {
			r_printf(fd ,"Start regular announcements for the entire run time (port %d).\n", port);
		} else {
			r_printf(fd ,"Start regular announcements for %d minutes (port %d).\n", minutes, port);
		}
	} else {
		r_printf(fd ,"Invalid port or query too long.\n");
	}
}

// Match a format string with only %n at the end
static int match(const char request[], const char fmt[])
{
	int n = -1;
	sscanf(request, fmt, &n);
	return (n > 0 && request[n] == '\0');
}

static void cmd_exec(int fd, const char request[], int allow_debug)
{
	struct value_t *value;
	int minutes;
	IP addrs[16];
	char hostname[256];
	int count;
	int port;
	size_t i;
	char d; // dummy marker
	int rc = 0;

	if (sscanf(request, "ping %255s %c", hostname, &d) == 1) {
		cmd_ping(fd, hostname);
	} else if (sscanf(request, "lookup %255s %c", hostname, &d) == 1) {
		// Check searches for node
		rc = kad_lookup(hostname, addrs, ARRAY_SIZE(addrs));

		if (rc > 0) {
			// Print results
			for (i = 0; i < rc; ++i) {
				r_printf(fd, "%s\n", str_addr( &addrs[i] ));
			}
		} else if (rc < 0) {
			r_printf(fd ,"Some error occured.\n");
		} else {
			r_printf(fd ,"Search in progress.\n");
		}
	} else if (match(request, "status %n")) {
		// Print node id and statistics
		cmd_print_status(fd);
	} else if (match(request, "announce %n")) {
		// Announce all values
		count = 0;
		value = announces_get();
		while (value) {
			kad_announce_once(value->id, value->port);
			count += 1;
			value = value->next;
		}
		r_printf(fd, "%d announcements started.\n", count);
	} else if (sscanf(request, "announce %255s %c", hostname, &d) == 1) {
		cmd_announce(fd, hostname, 0, -1);
	} else if (sscanf( request, "announce %255[^: ] %d %c", hostname, &minutes, &d) == 2) {
		cmd_announce(fd, hostname, 0, minutes);
	} else if (sscanf( request, "announce %255[^: ]:%d %d %c", hostname, &port, &minutes, &d) == 3) {
		cmd_announce(fd, hostname, port, minutes );
	} else if (match(request, "list %*s %n") && allow_debug) {
		if (match(request, "blacklist %255[^: ]%n")) {
			cmd_blacklist(fd, hostname);
		} else if (gconf->is_daemon == 1) {
			r_printf(fd ,"The 'list' command is not available while KadNode runs as daemon.\n" );
		} else if (match(request, "list blacklist %n")) {
			kad_debug_blacklist(fd);
		} else if (match(request, "list constants %n")) {
			kad_debug_constants(fd);
		} else if (match(request, "list nodes %n")) {
			rc = kad_export_nodes(fd);

			if (rc == 0) {
				r_printf(fd, "No good nodes found.\n" );
			}
#ifdef FWD
		} else if (match(request, "list forwardings %n")) {
			fwd_debug(fd);
#endif
#ifdef BOB
		} else if (match(request, "list keys %n")) {
			bob_debug_keys(fd);
#endif
		} else if (match(request, "list searches %n")) {
			searches_debug(fd);
		} else if (match(request, "list announcements %n")) {
			announces_debug(fd);
		} else if (match(request, "list dht_buckets %n")) {
			kad_debug_buckets(fd);
		} else if (match(request, "list dht_searches %n")) {
			kad_debug_searches(fd);
		} else if (match(request, "list dht_storage %n")) {
			kad_debug_storage(fd);
		} else {
			dprintf(fd, "Unknown command.\n");
		}
		r_printf(fd ,"\nOutput send to console.\n" );
	} else {
		// Print usage
		r_printf(fd, g_server_usage);

		if (allow_debug) {
			r_printf(fd, g_server_usage_debug);
		}
	}
}


static void cmd_client_handler(int rc, int clientsock)
{
	char request[256];
	ssize_t size;

	if (rc <= 0) {
		return;
	}

	size = recv(clientsock, request, sizeof(request) - 1, 0);
	if (size > 0) {
		request[size] = '\0';
		// Execute command line
		cmd_exec(clientsock, request, 0);
	}

	// Close connection after the request was processed
	close(clientsock);
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

	addrlen = sizeof(struct sockaddr_in);
	clientsock = accept(serversock, (struct sockaddr *) &addr, &addrlen);
	if (clientsock < 0) {
		log_error("accept(): %s\n", strerror(errno));
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

	// Execute command line
	cmd_exec(fd, request, 1);
}

void cmd_setup( void)
{
	struct sockaddr_un addr;
	int sock;

	if (gconf->cmd_path == NULL || strlen(gconf->cmd_path) == 0) {
		return;
	}

	sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		log_error("socket(): %s\n", strerror(errno));
		return;
	}

	unlink(gconf->cmd_path);
	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, gconf->cmd_path);

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		log_error("bind(): %s\n", strerror(errno));
		return;
	}

	listen(sock, 5);

	net_add_handler(sock, &cmd_server_handler);

	if (gconf->is_daemon == 0 && gconf->cmd_disable_stdin == 0) {
		// Wait for other messages to be displayed
		sleep(1);

		fprintf(stdout, "Press Enter for help.\n");
		net_add_handler(STDIN_FILENO, &cmd_console_handler);
	}
}

void cmd_free(void)
{
	unlink(gconf->cmd_path);
}

static __attribute__ ((unused)) int select_read(int sockfd, char buffer[], int bufsize, struct timeval *tv)
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

int cmd_client(int argc, char *argv[])
{
	char buffer[256];
	const char *path;
	struct sockaddr_un addr;
	struct timeval tv;
	ssize_t size;
	int sock;
	size_t i;

	// Default unix socket path
	path = CMD_PATH;

	// Skip program name
	argc -= 1;
	argv += 1;

	if (argc >= 1) {
		if (strcmp(argv[0], "-h") == 0) {
			fprintf(stdout, "%s", g_client_usage);
			return 0;
		} else if (strcmp( argv[0], "-p") == 0) {
			if (argc >= 2) {
				path = argv[1];
				// Skip option and path
				argc -= 2;
				argv += 2;
			} else {
				fprintf(stderr, "Path is missing!\n");
				return 1;
			}
		}
	}

	// Construct request string from args
	buffer[0] = '\0';
	for (i = 0; i < argc; ++i) {
		if (i) {
			strcat(buffer, " ");
		}
		strcat(buffer, argv[i]);
	}
	strcat(buffer, "\n");

	sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "socket(): %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, path);

	if (!connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == 0) {
		fprintf(stderr, "connect(): %s\n", strerror(errno));
		goto error;
	}

	/* Set receive timeout: 200ms */
	tv.tv_sec = 0;
	tv.tv_usec = 200000;

#ifndef __CYGWIN__
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0) {
		fprintf(stderr, "setsockopt(): %s\n", strerror(errno));
		goto error;
	}
#endif

	// Send request
	send(sock, buffer, strlen(buffer), 0);

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
