
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
    kadnode_nss_request_t req = {0};
    kadnode_nss_response_t res = {0};

    if (rc <= 0) {
        return;
    }

    log_debug("nss_client_handler");

    rc = recv(clientsock, &req, sizeof(kadnode_nss_request_t), 0);
    if (rc != sizeof(req)) {
        goto abort;
    }

    // Make sure name is null terminated
    req.name[QUERY_MAX_SIZE - 1] = '\0';

    // Check name extensions (*.p2p)
    if (!has_tld(&req.name[0], gconf->query_tld)) {
        // not for us (missing TLD)
        goto abort;
    }

    search = kad_lookup(&req.name[0]);

    if (search == NULL) {
        // not for us or invalid query
        goto abort;
    }

    if (search->done && search->results == NULL) {
        // we have given up
        goto abort;
    }

    // Collect either IPv4 or IPv6 addresses
    for (result = search->results; result != NULL; result = result->next) {
        if (is_valid_result(result) && res.count < MAX_ENTRIES) {
            int af = result->addr.ss_family;
            int count = res.count;

            if (req.af != AF_UNSPEC && req.af != af) {
                // About req.allow_mixed_af; ignore it
                // since the system can do that for us.
                continue;
            }

            if (af == AF_INET6) {
                IP6 *addr = (IP6 *)&result->addr;
                res.result[count].af = af;
                res.result[count].scopeid = addr->sin6_scope_id;
                memcpy(&res.result[count].address.ipv6, &addr->sin6_addr, 16);
                res.count += 1;
            }

            if (af == AF_INET) {
                IP4 *addr = (IP4 *)&result->addr;
                res.result[count].af = af;
                res.result[count].scopeid = 0;
                memcpy(&res.result[count].address.ipv4, &addr->sin_addr, 4);
                res.count += 1;
            }
        }
    }

    rc = write(clientsock, &res, sizeof(res));

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

bool nss_setup(void)
{
    if (unix_create_unix_socket(gconf->nss_path, &g_nss_sock)) {
        log_info("NSS: Bind to %s", gconf->nss_path);
        net_add_handler(g_nss_sock, &nss_server_handler);
        return true;
    }

    return false;
}

void nss_free(void)
{
    if (g_nss_sock >= 0) {
        unix_remove_unix_socket(gconf->nss_path, g_nss_sock);
    }
}
