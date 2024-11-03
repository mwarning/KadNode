
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#ifdef __CYGWIN__
#include <windows.h>
#endif

#include "main.h"
#include "conf.h"
#include "log.h"
#include "kad.h"
#include "utils.h"
#include "unix.h"
#include "net.h"
#include "announces.h"
#include "searches.h"
#include "peerfile.h"
#ifdef DEBUG
#include "tests.h"
#endif
#ifdef __CYGWIN__
#include "windows.h"
#endif

#ifdef LPD
#include "ext-lpd.h"
#endif
#ifdef BOB
#include "ext-bob.h"
#endif
#ifdef DNS
#include "ext-dns.h"
#endif
#ifdef NSS
#include "ext-nss.h"
#endif
#ifdef CMD
#include "ext-cmd.h"
#endif
#ifdef FWD
#include "ext-fwd.h"
#endif
#ifdef TLS
#include "ext-tls-client.h"
#include "ext-tls-server.h"
#endif

static bool g_pidfile_written = false;


int main_run(void)
{
    /* Run setup */

    // Early exit
    if (!conf_load()) {
        return EXIT_FAILURE;
    }

    // Setup port-forwarding
#ifdef FWD
    if (!fwd_setup()) {
        return EXIT_FAILURE;
    }
#endif

    // Setup the Kademlia DHT
    if (!kad_setup()) {
        return EXIT_FAILURE;
    }

    // Setup handler to announces
    announces_setup();

    // Setup handler to expire results
    searches_setup();

    // Setup import of peerfile
    peerfile_setup();

    // Setup extensions
#ifdef LPD
    if (!lpd_setup()) {
        return EXIT_FAILURE;
    }
#endif

#ifdef BOB
    if (!bob_setup()) {
        return EXIT_FAILURE;
    }
#endif
#ifdef DNS
    if (!dns_setup()) {
        return EXIT_FAILURE;
    }
#endif
#ifdef NSS
    if (!nss_setup()) {
        return EXIT_FAILURE;
    }
#endif
#ifdef TLS
    if (!tls_client_setup()) {
        return EXIT_FAILURE;
    }

    if (!tls_server_setup()) {
        return EXIT_FAILURE;
    }
#endif
#ifdef CMD
    if (!cmd_setup()) {
        return EXIT_FAILURE;
    }
#endif

    /* Run program */

    // Loop over all sockets and file descriptors
    net_loop();
    log_info("Shutting down...");

    // Export peers if a file is provided
    peerfile_export();

    /* Free resources */

#ifdef CMD
    cmd_free();
#endif
#ifdef NSS
    nss_free();
#endif
#ifdef DNS
    dns_free();
#endif
#ifdef BOB
    bob_free();
#endif
#ifdef LPD
    lpd_free();
#endif
#ifdef TLS
    tls_server_free();
    tls_client_free();
#endif

    peerfile_free();

    searches_free();

    announces_free();

    kad_free();

#ifdef FWD
    fwd_free();
#endif

    conf_free();

    net_free();

    if (g_pidfile_written) {
        unlink(gconf->pidfile);
    }

    return EXIT_SUCCESS;
}

#ifdef __CYGWIN__
int main(int argc, char *argv[])
{
    char cmd[512];
    char path[256];
    int rc = 0;
    char *p;

#ifdef CMD
    if (strstr(argv[0], "kadnode-ctl")) {
        return cmd_client(argc, argv);
    }
#endif

    if (!conf_setup(argc, argv)) {
        return EXIT_FAILURE;
    }

    if (gconf->service_start) {
        gconf->use_syslog = 1;

        // Get kadnode.exe binary lcoation
        if (GetModuleFileNameA(NULL, path, sizeof(path)) && (p = strrchr(path, '\\'))) {
            *(p + 1) = '\0';
        } else {
            log_error("Cannot get location of KadNode binary.");
            exit(1);
        }

        // Set DNS server to localhost
        snprintf(cmd, sizeof(cmd), "cmd.exe /c \"%s\\dns_setup.bat\"", path);
        windows_exec(cmd);

        rc = windows_service_start((void (*)()) main_run);

        // Reset DNS settings to DHCP
        snprintf(cmd, sizeof(cmd), "cmd.exe /c \"%s\\dns_reset.bat\"", path);
        windows_exec(cmd);

        return rc;
    }

    if (gconf->is_daemon) {
        gconf->use_syslog = 1;

        // Close pipes
        fclose(stderr);
        fclose(stdout);
        fclose(stdin);

        // Fork before any threads are started
        unix_fork();

        // Change working directory to C:\ directory or disk equivalent
        if (GetModuleFileNameA(NULL, path, sizeof(path)) && (p = strchr(path, '\\'))) {
            *(p + 1) = 0;
            SetCurrentDirectoryA(path);
        }

    } else {
        conf_info();
    }

    // Catch signals
    windows_signals();

    // Write pid file
    if (gconf->pidfile) {
        unix_write_pidfile(GetCurrentProcessId(), gconf->pidfile);
        g_pidfile_written = true;
    }

    // Drop privileges
    unix_dropuid0();

    return main_run();
}
#else
int main(int argc, char *argv[])
{
#ifdef CMD
    if (strstr(argv[0], "kadnode-ctl")) {
        return cmd_client(argc, argv);
    }
#endif

#ifdef DEBUG
    run_tests();
#endif

    if (!conf_setup(argc, argv)) {
        return EXIT_FAILURE;
    }

    if (gconf->is_daemon) {
        gconf->use_syslog = 1;

        // Close pipes
        fclose(stderr);
        fclose(stdout);
        fclose(stdin);

        // Fork before any threads are started
        unix_fork();

        if (chdir("/") != 0) {
            log_error("Changing working directory to '/' failed: %s", strerror(errno));
            exit(1);
        }
    } else {
        conf_info();
    }

    // Catch signals
    unix_signals();

    // Write pid file
    if (gconf->pidfile) {
        unix_write_pidfile(getpid(), gconf->pidfile);
        g_pidfile_written = true;
    }

    // Drop privileges
    unix_dropuid0();

    return main_run();
}
#endif
