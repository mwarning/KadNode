
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "ext-nss.h"

#define MAX_ADDRS 32


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
	if ( EXIT_SUCCESS == rc) {
		// Found addresses
		log_debug( "NSS: Found %lu addresses.", num);
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
		log_error("accept(): %s\n", strerror(errno));
		return;
	}

	net_add_handler(clientsock, &nss_client_handler);
}

void nss_setup(void)
{
	struct sockaddr_un addr;
	int sock;

	if (gconf->nss_path == NULL || strlen(gconf->nss_path) == 0) {
		return;
	}

	sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		log_error("socket(): %s\n", strerror(errno));
		return;
	}

	unlink(gconf->nss_path);
	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, gconf->nss_path);

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		log_error("bind(): %s\n", strerror(errno));
		return;
	}

	listen(sock, 5);

	log_info("NSS: Bind to %s", gconf->nss_path);

	net_add_handler(sock, &nss_server_handler);
}

void nss_free(void)
{
	unlink(gconf->nss_path);
}
