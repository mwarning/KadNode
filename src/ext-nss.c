
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
#include "ext-libnss.h"
#include "ext-nss.h"


static int g_nss_sock = -1;

static void nss_client_handler(int rc, int clientsock)
{
	const struct search_t *search;
	const struct result_t *result;
	struct kadnode_nss_request req = {0};
	struct kadnode_nss_response res = {0};
	int count;
	int af;

	if (rc <= 0) {
		return;
	}

	rc = recv(clientsock, &req, sizeof(req), 0);
	if (rc != sizeof(req)) {
		goto abort;
	}

	// Make sure name is null terminated
	req.name[QUERY_MAX_SIZE - 1] = '\0';

	// Check name extensions (*.p2p)
	if (!has_ext(&req.name[0], gconf->query_tld)) {
		goto finish;
	}

printf("nss lookup: %s\n", &req.name[0]);

	search = kad_lookup(&req.name[0]);


	if (search == NULL) {
		printf("no search found\n");
		goto finish;
	}

printf("found search; request.af: %s\n", str_af(req.af));

	af = req.af;
	count = 0;

	// Collect either IPv4 or IPv6 addresses
	for (result = search->results; result; result = result->next) {
		if (is_valid_result(result) && count < MAX_ENTRIES) {
			if (af == AF_UNSPEC) {
				af = result->addr.ss_family;
			}

			if (af != result->addr.ss_family) {
				continue;
			}

			if (af == AF_INET6) {
				memcpy(&res.data.ipv6[count], &((IP6 *)&result->addr)->sin6_addr, sizeof(struct in6_addr));
				count += 1;
			}

			if (af == AF_INET) {
				memcpy(&res.data.ipv4[count], &((IP4 *)&result->addr)->sin_addr, sizeof(struct in_addr));
				count += 1;
			}
		}
	}

	res.af = af;
	res.count = count;

printf("found results; response.af: %s, count: %d\n", str_af(res.af), count);


finish:
	write(clientsock, &res, sizeof(res));

abort:
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
