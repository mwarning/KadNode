
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "unix.h"
#include "kad.h"
#include "net.h"
#include "ext-nss.h"

#define MAX_ADDRS 32


static int g_nss_sock = -1;

static void nss_client_handler(int rc, int clientsock)
{
	char hostname[QUERY_MAX_SIZE];
	IP addrs[MAX_ADDRS];
	ssize_t size;
	size_t num;

	if (rc <= 0) {
		return;
	}

	size = recv(clientsock, hostname, sizeof(hostname) - 1, 0);
	if (size <= 0) {
		goto end;
	}

	hostname[size] = '\0';
	if (!has_ext(hostname, gconf->query_tld)) {
		goto end;
	}

	num = ARRAY_SIZE(addrs);
	rc = kad_lookup(hostname, addrs, &num);
	if (EXIT_SUCCESS == rc) {
		// Found addresses
		log_debug("NSS: Found %lu addresses.", num);
	} else {
		num = 0;
	}

	write(clientsock, (uint8_t *) addrs, num * sizeof(IP));

end:
	close(clientsock);
	net_remove_handler(clientsock, &nss_client_handler);
}

static void nss_server_handler(int rc, int serversock)
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
		log_error("accept(): %s", strerror(errno));
		return;
	}

	net_add_handler(clientsock, &nss_client_handler);
}

int nss_setup(void)
{
	if (EXIT_FAILURE == unix_create_unix_socket(gconf->nss_path, &g_nss_sock)) {
		return EXIT_FAILURE;
	} else {
		log_info("NSS: Bind to %s", gconf->nss_path);

		net_add_handler(g_nss_sock, &nss_server_handler);

		return EXIT_SUCCESS;
	}
}

void nss_free(void)
{
	if (g_nss_sock >= 0) {
		unix_remove_unix_socket(gconf->nss_path, g_nss_sock);
	}
}
