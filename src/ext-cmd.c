
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
PROGRAM_NAME" Control Program - Send commands to a KadNode instance.\n\n"
"Usage: kadnode-ctl [OPTIONS] [COMMANDS]\n"
"\n"
" -p <file>	Connect to this unix socket (Default: "CMD_PATH")\n"
" -h		Print this help.\n"
"\n";

static const char* g_server_usage =
    "Usage:\n"
    "	status\n"
    "	lookup <query>\n"
    "	announce <query>[:<port>]\n"
    "	ping <addr>\n"
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

static const char* g_server_help = "TODO";

static int g_cmd_sock = -1;


static int cmd_peer(FILE *fp, const char addr_str[], int af)
{
    IP addr;

    if (addr_parse(&addr, addr_str, STR(DHT_PORT), af)) {
        if (kad_ping(&addr)) {
            fprintf(fp, "Send ping to: %s\n", str_addr(&addr));
            return 1;
        } else {
            fprintf(fp, "Failed to send ping.\n");
        }
    }

    return 0;
}

/*
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

    if (port < 1 || port > 65535) {
        port = gconf->dht_port;
    }

    if (kad_announce(hostname, port, lifetime)) {
#ifdef FWD
        // Add port forwarding
        fwd_add(port, lifetime);
#endif
        if (minutes < 0) {
            fprintf(fp, "Start regular announcements for the entire run time (port %d).\n", port);
        } else {
            fprintf(fp, "Start regular announcements for %d minutes (port %d).\n", minutes, port);
        }
    } else {
        fprintf(fp, "Invalid query: %s (no domain, hex key or hex hash)\n", hostname);
    }
}*/

enum {
    oHelp,
    oPeer,
    oLookup,
    oStatus,
    oAnnounceStart,
    oAnnounceStop,
    oPrintBlocked,
    oPrintConstants,
    oPrintPeers,
    oPrintAnnouncements,
    oPrintBuckets,
    oPrintSearches,
    oPrintStorage,
    oPrintForwardings,
    oPrintKeys
};

static const option_t g_options[] = {
    {"h", 1, oHelp},
    {"help", 1, oHelp},
    {"peer", 2, oPeer},
    {"lookup", 2, oLookup},
    {"announce-start", 2, oAnnounceStart},
    {"announce-stop", 2, oAnnounceStop},
    {"blocklist", 1, oPrintBlocked},
    {"constants", 1, oPrintConstants},
    {"peers", 1, oPrintPeers},
    {"announcements", 1, oPrintAnnouncements},
    {"buckets", 1, oPrintBuckets},
    {"searches", 1, oPrintSearches},
    {"storage", 1, oPrintStorage},
    {"forwardings", 1, oPrintForwardings},
    {"keys", 1, oPrintKeys},
    {NULL, 0, 0}
};

static void cmd_exec(FILE *fp, char request[], int allow_debug)
{
    uint8_t id[SHA1_BIN_LENGTH];
    const char *argv[8];
    int argc = setargs(&argv[0], ARRAY_SIZE(argv), request);

    if (argc == 0) {
        // Print usage
        fprintf(fp, "%s", g_server_usage);
        return;
    }

    const option_t *option = find_option(g_options, argv[0]);

    if (option == NULL) {
        fprintf(fp, "Unknown command.\n");
        return;
    }

    if (option->num_args != argc) {
        fprintf(fp, "Unexpected number of arguments.\n");
        return;
    }

    // parse identifier
    if (option->code == oAnnounceStop) {
        if (!parse_id(id, sizeof(id), argv[1], strlen(argv[1]))) {
            fprintf(fp, "Failed to parse identifier.\n");
            return;
        }
    }

    switch (option->code) {
    case oHelp:
        fprintf(fp, "%s", g_server_help);
        break;
    case oPeer: {
        const char *address = argv[1];
        int count = 0;

        if (gconf->af == AF_UNSPEC) {
            count += cmd_peer(fp, address, AF_INET);
            count += cmd_peer(fp, address, AF_INET6);
        } else {
            count += cmd_peer(fp, address, gconf->af);
        }

        if (count == 0) {
            fprintf(fp, "Failed to parse/resolve address.\n");
        }
        break;
    }
    case oLookup: {
        // Lookup hostname
        const struct search_t *search = kad_lookup(argv[1]);

        if (search) {
            int found = 0;
            for (const struct result_t *result = search->results; result; result = result->next) {
                if (is_valid_result(result)) {
                    fprintf(fp, "%s\n", str_addr(&result->addr));
                    found = 1;
                }
            }

            if (!found) {
                if (search->start_time == time_now_sec()) {
                    fprintf(fp, "Search started.\n");
                } else {
                    fprintf(fp, "Search in progress.\n");
                }
            }
        } else {
            fprintf(fp, "Some error occurred.\n");
        }
        break;
    }
    case oStatus:
        // Print node id and statistics
        kad_status(fp);
        break;
    case oAnnounceStart: {
        int port;
        if (parse_annoucement(&id[0], &port, argv[1], gconf->dht_port)) {
            announces_add(fp, id, port, LONG_MAX);
        } else {
            fprintf(fp, "Invalid announcement.\n");
        }
        break;
    }
    case oAnnounceStop:
        announcement_remove(id);
        break;
    case oPrintSearches:
        kad_print_searches(fp);
        break;
    case oPrintAnnouncements:
        announces_print(fp);
        break;
    case oPrintBlocked:
        kad_print_blocklist(fp);
        break;
    case oPrintConstants:
        kad_print_constants(fp);
        break;
    case oPrintPeers:
        kad_export_peers(fp);
        break;
    case oPrintBuckets:
        kad_print_buckets(fp);
        break;
    case oPrintStorage:
        kad_print_storage(fp);
        break;
#ifdef FWD
    case oPrintForwardings:
        fwd_debug(fp);
        break;
#endif
#ifdef BOB
    case oPrintKeys:
        bob_debug_keys(fp);
        break;
#endif
    }
}

static void cmd_client_handler(int rc, int clientsock)
{
    // save state since a line and come in multiple calls
    static char request[256];
    static ssize_t request_length = 0;
    static int current_clientsock = -1;
    static FILE* current_clientfd = NULL;

    if (rc <= 0) {
        return;
    }

    ssize_t remaining = sizeof(request) - request_length;
    ssize_t size = read(clientsock, &request[request_length], remaining);

    if (size == -1) {
        return;
    } else {
        request_length += size;
    }

    if (current_clientfd == NULL) {
        current_clientfd = fdopen(clientsock, "w");
    }

    if (request_length > 0 && size != 0) {
        // split lines
        char* beg = request;
        const char* end = request + request_length;
        char *cur = beg;
        while (true) {
            char *next = memchr(cur, '\n', end - cur);
            if (next) {
                *next = '\0'; // replace newline with 0
                #ifdef DEBUG
                    cmd_exec(current_clientfd, cur, true);
                #else
                    cmd_exec(current_clientfd, cur, false);
                #endif
                fflush(current_clientfd);
                cur = next + 1;

                // force connection to be
                // closed after one command
                size = 0;
            } else {
                break;
            }
        }

        // move unhandled data to the front of the buffer
        if (cur > beg) {
            memmove(beg, cur, cur - beg);
            request_length = end - cur;
            remaining = sizeof(request) - request_length;
        }
    }

    if (size == 0 || remaining == 0) {
        // socket closed
        if (current_clientfd) {
            fclose(current_clientfd);
        } else {
            close(current_clientsock);
        }

        current_clientsock = -1;
        current_clientfd = NULL;
        request_length = 0;

        net_remove_handler(clientsock, &cmd_client_handler);
    }
}

static void cmd_server_handler(int rc, int serversock)
{
    if (rc <= 0) {
        return;
    }

    int clientsock = accept(serversock, NULL, NULL);
    if (clientsock < 0) {
        log_error("accept(): %s", strerror(errno));
        return;
    }

    net_add_handler(clientsock, &cmd_client_handler);
}

// special case for local console
static void cmd_console_handler(int rc, int fd)
{
    char request[256];

    if (rc <= 0) {
        return;
    }

    // Read line
    char *ptr = fgets(request, sizeof(request), stdin);
    if (ptr == NULL) {
        return;
    }

    // Output to stdout (not stdin)
    cmd_exec(stdout, request, true);
}

bool cmd_setup(void)
{
    if (!unix_create_unix_socket(gconf->cmd_path, &g_cmd_sock)) {
        return false;
    } else {
        log_info("CLI: Bind to %s", gconf->cmd_path);

        net_add_handler(g_cmd_sock, &cmd_server_handler);

        if (!gconf->is_daemon && !gconf->cmd_disable_stdin) {
            fprintf(stdout, "Press Enter for help.\n");
            net_add_handler(STDIN_FILENO, &cmd_console_handler);
        }

        return true;
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

    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);

    int retval = select(sockfd + 1, &rfds, NULL, NULL, tv);

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
    char buffer[1024];
    struct sockaddr_un addr = { 0 };

    // Default unix socket path
    const char *path = CMD_PATH;

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

    if (strlen(path) >= FIELD_SIZEOF(struct sockaddr_un, sun_path)) {
        fprintf(stderr, "Path too long!\n");
        return EXIT_FAILURE;
    }

    size_t pos = 0;
    if (!isatty(fileno(stdin))) {
        int c = 0;
        while (pos < sizeof(buffer)) {
            c = getchar();
            if (c == -1) {
                break;
            }
            buffer[pos++] = c;
        }

        if (c != -1) {
            fprintf(stderr, "Input too long!\n");
            return EXIT_FAILURE;
        }

        if (pos == 0 || buffer[pos-1] != '\n') {
            // Append newline if not present
            buffer[pos++] = '\n';
        }
    } else {
        // Concatenate arguments
        for (size_t i = 0; i < argc; i++) {
            size_t len = strlen(argv[i]);
            if ((pos + len + 1) >= sizeof(buffer)) {
                fprintf(stderr, "Input too long!\n");
                return EXIT_FAILURE;
            }
            memcpy(&buffer[pos], argv[i], len);
            pos += len;
            buffer[pos++] = ' ';
        }
        // Append newline
        buffer[pos++] = '\n';
    }

    int sock = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket() %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to connect to '%s': %s\n", path, strerror(errno));
        goto error;
    }

#ifdef __CYGWIN__
    struct timeval tv;

    /* Set receive timeout: 200ms */
    tv.tv_sec = 0;
    tv.tv_usec = 200000;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0) {
        fprintf(stderr, "setsockopt() %s\n", strerror(errno));
        goto error;
    }
#endif

    // Write request
    size_t ret = write(sock, buffer, pos);

    if (ret < 0) {
        fprintf(stderr, "write() %s\n", strerror(errno));
        goto error;
    }

    while (true) {
        // Receive replies
#ifdef __CYGWIN__
        ssize_t size = select_read(sock, buffer, sizeof(buffer), &tv);
#else
        ssize_t size = read(sock, buffer, sizeof(buffer));
#endif
        if (size > 0 && size <= sizeof(buffer)) {
            // Print to console
            printf("%.*s", (int) size, buffer);
        } else {
            // socket closed (0) or error
            break;
        }
    }

    close(sock);

    return EXIT_SUCCESS;

error:
    if (sock > 0) {
        close(sock);
    }

    return EXIT_FAILURE;
}
