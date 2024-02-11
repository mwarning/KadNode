
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h> // close()
#include <net/if.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"


static struct pollfd g_fds[16] = { 0 };
static net_callback* g_cbs[16] = { NULL };
static int g_count = 0;
static bool g_entry_removed = false;


// Set a socket non-blocking
int net_set_nonblocking(int fd)
{
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

void net_add_handler(int fd, net_callback *cb)
{
	if (cb == NULL) {
		log_error("net_add_handler() Callback is null.");
		exit(1);
	}

	if (g_count == ARRAY_SIZE(g_cbs)) {
		log_error("net_add_handler() No more space for handlers.");
		exit(1);
	}

	if (fd >= 0) {
		net_set_nonblocking(fd);
	}

	g_cbs[g_count] = cb;
	g_fds[g_count].fd = fd;
	g_fds[g_count].events = POLLIN;

	g_count += 1;
}

void net_remove_handler(int fd, net_callback *cb)
{
	if (cb == NULL) {
		log_error("net_remove_handler() callback is null");
		exit(1);
	}

	for (size_t i = 0; i < g_count; i++) {
		if (g_cbs[i] == cb && g_fds[i].fd == fd) {
			// mark for removal in compress_entries()
			g_cbs[i] = NULL;
			g_entry_removed = true;
			return;
		}
	}

	log_error("net_remove_handler() handler not found");
	exit(1);
}

static void compress_entries()
{
	for (size_t i = 0; i < g_count; i += 1) {
		while (g_cbs[i] == NULL && i < g_count) {
			g_count -= 1;
			g_cbs[i] = g_cbs[g_count];
			g_fds[i].fd = g_fds[g_count].fd;
			g_fds[i].events = g_fds[g_count].events;
		}
	}
}

void net_loop(void)
{
	bool call_all = false;
	time_t call_all_time = time(NULL);

	// call all callbacks immediately
	for (size_t i = 0; i < g_count; i++) {
		g_cbs[i](-1, g_fds[i].fd);
	}

	while (gconf->is_running) {
		int rc = poll(g_fds, g_count, 1000);

		if (rc < 0) {
			//log_error("poll(): %s", strerror(errno));
			break;
		}

		gconf->time_now = time(NULL);

		if ((gconf->time_now - call_all_time) >= 1) {
			call_all = true;
			call_all_time = gconf->time_now;
		} else {
			call_all = false;
		}

		for (size_t i = 0; i < g_count; i++) {
			int revents = g_fds[i].revents;
			if (revents || call_all) {
				g_cbs[i](revents, g_fds[i].fd);
			}
		}

		if (g_entry_removed) {
			compress_entries();
			g_entry_removed = false;
		}
	}
}

int net_socket(const char name[], const char ifname[], const int protocol, const int af)
{
	const int opt_on = 1;
	int sock = -1;

	// Disable IPv6 or IPv4
	if (gconf->af != AF_UNSPEC && gconf->af != af) {
		goto fail;
	}

	if ((sock = socket(af, (protocol == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM, protocol)) < 0) {
		log_error("%s: Failed to create socket: %s", name, strerror(errno));
		goto fail;
	}

	if (net_set_nonblocking(sock) < 0) {
		log_error("%s: Failed to make socket nonblocking: %s", name, strerror(errno));
		goto fail;
	}

#if defined(__APPLE__) || defined(__CYGWIN__) || defined(__FreeBSD__)
	if (ifname) {
		log_error("%s: Bind to device not supported on Windows and MacOSX.", name);
		goto fail;
	}
#else
	if (ifname && setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname))) {
		log_error("%s: Unable to bind to device %s: %s", name, ifname, strerror(errno));
		goto fail;
	}
#endif

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_on, sizeof(opt_on)) < 0) {
		log_error("%s: Unable to set SO_REUSEADDR for %s: %s", name, ifname, strerror(errno));
		goto fail;
	}

	return sock;

fail:
	close(sock);

	return -1;
}

int net_bind(
	const char name[],
	const char addr[],
	const int port,
	const char ifname[],
	const int protocol)
{
	const int opt_on = 1;
	socklen_t addrlen;
	IP sockaddr;
	int sock = -1;

	if (!addr_parse(&sockaddr, addr, "0", AF_UNSPEC)) {
		log_error("%s: Failed to parse IP address '%s'", name, addr);
		goto fail;
	}

	port_set(&sockaddr, port);

	if ((sock = net_socket(name, ifname, protocol, sockaddr.ss_family)) < 0) {
		goto fail;
	}

	if (sockaddr.ss_family == AF_INET6) {
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt_on, sizeof(opt_on)) < 0) {
			log_error("%s: Failed to set IPV6_V6ONLY for %s: %s",
				name, str_addr(&sockaddr), strerror(errno));
			goto fail;
		}
	}

	addrlen = addr_len(&sockaddr);
	if (bind(sock, (struct sockaddr*) &sockaddr, addrlen) < 0) {
		log_error("%s: Failed to bind socket to %s: %s",
			name, str_addr(&sockaddr), strerror(errno)
		);
		goto fail;
	}

	if (protocol == IPPROTO_TCP && listen(sock, 5) < 0) {
		log_error("%s: Failed to listen on %s: %s (%s)",
			name, str_addr(&sockaddr), strerror(errno)
		);
		goto fail;
	}

	log_info(ifname ? "%s: Bind to %s, interface %s" : "%s: Bind to %s",
		name, str_addr(&sockaddr), ifname
	);

	return sock;

fail:
	close(sock);
	return -1;
}

void net_free(void)
{
	int i;

	for (i = 0; i < g_count; i++) {
		g_cbs[i] = NULL;
		close(g_fds[i].fd);
		g_fds[i] = (struct pollfd){ 0 };
	}
}
