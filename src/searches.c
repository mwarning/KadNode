
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "log.h"
#include "main.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#ifdef BOB
#include "ext-bob.h"
#endif
#ifdef TLS
#include "ext-tls-client.h"
#endif
#include "searches.h"


/*
* The DHT implementation in KadNode does not store
* results (IP addresses) from hash id searches.
* Therefore, results are collected and stored here.
*/

// Expected lifetime of announcements
#define MAX_SEARCH_LIFETIME (20*60)
#define MAX_RESULTS_PER_SEARCH 16


// A ring buffer for all searches
static struct search_t *g_searches = NULL;

// TODO: are searches deleted?

static const char *str_state(int state)
{
    switch(state) {
    case AUTH_OK: return "OK";
    case AUTH_AGAIN: return "AGAIN";
    case AUTH_FAILED: return "FAILED";
    case AUTH_ERROR: return "ERROR";
    case AUTH_SKIP: return "SKIP";
    case AUTH_PROGRESS: return "PROGRESS";
    case AUTH_WAITING: return "WAITING";
    default:
        log_error("Invalid state: %d", state);
        exit(1);
    }
}

struct search_t *searches_find_by_id(const uint8_t id[])
{
    struct search_t *search;

    search = g_searches;
    while (search) {
        if (memcmp(search->id, id, SHA1_BIN_LENGTH) == 0) {
            return search;
        }
        search = search->next;
    }

    return NULL;
}

static struct search_t *searches_find_by_query(const char query[])
{
    struct search_t *search;

    search = g_searches;
    while (search) {
        if (0 == strcmp(query, &search->query[0])) {
            return search;
        }
        search = search->next;
    }

    return NULL;
}

// Free a search_t struct
void search_free(struct search_t *search)
{
    struct result_t *cur;
    struct result_t *next;

    cur = search->results;
    while (cur) {
        next = cur->next;
        free(cur);
        cur = next;
    }

    free(search);
}

// Get next address to authenticate
static struct result_t *find_next_result(struct search_t *search)
{
    struct result_t *result;

    result = search->results;
    while (result) {
        if (result->state == AUTH_WAITING || result->state == AUTH_AGAIN) {
            return result;
        }
        result = result->next;
    }

    return NULL;
}

// Get next search to authenticate
static struct search_t *find_next_search(auth_callback *callback)
{
    struct search_t *search;

    search = g_searches;
    while (search) {
        if (!search->done && search->callback == callback) {
            return search;
        }
        search = search->next;
    }
    return NULL;
}

// Find query/IP-address to authenticate; callback is used as a marker.
struct result_t *searches_get_auth_target(char query[], IP *addr, auth_callback *callback)
{
    struct search_t *search;
    struct result_t *result;

    // Get next search to authenticate
    search = find_next_search(callback);
    if (search == NULL) {
        return NULL;
    }

    // Get next result to authenticate
    result = find_next_result(search);
    if (result == NULL) {
        return NULL;
    }

    // Set query and address to authenticate
    memcpy(query, &search->query, sizeof(search->query));
    memcpy(addr, &result->addr, sizeof(IP));

    return result;
}

// Set the authentication state of a result
void searches_set_auth_state(const char query[], const IP *addr, const int state)
{
    struct search_t *search;
    struct result_t *result;

    log_debug("Searches: Set authentication state for %s (%s): %s", str_addr(addr), query, str_state(state));

    search = searches_find_by_query(query);

    if (search) {
        // Search and set authentication state of result
        result = search->results;
        while (result) {
            if (addr_equal(&result->addr, addr)) {
                result->state = state;
                break;
            }
            result = result->next;
        }

        // Skip all other results if we found one that is ok
        if (state == AUTH_OK) {
            search->done = true;
            result = search->results;
            while (result) {
                if (result->state == AUTH_WAITING) {
                    result->state = AUTH_SKIP;
                }
                result = result->next;
            }
        }
    }
}

static const char* str_callback(auth_callback *cb) {
    if (cb == &tls_client_trigger_auth) {
        return "tls";
    }

    if (cb == &bob_trigger_auth) {
        return "bob";
    }

    return cb ? "???" : "none";
}

void searches_debug(FILE *fp)
{
    struct search_t *search;
    struct result_t *result;
    int result_counter;
    int search_counter;

    search_counter = 0;
    search = g_searches;

    fprintf(fp, "Result buckets:\n");
    while (search) {
        fprintf(fp, " query: '%s'\n", &search->query[0]);
        fprintf(fp, "  id: %s\n", str_id(search->id));
        fprintf(fp, "  done: %s\n", search->done ? "true" : "false");
        fprintf(fp, "  auth: %s\n", str_callback(search->callback));
        fprintf(fp, "  started: %ldm ago\n", (time_now_sec() - search->start_time) / 60);
        result_counter = 0;
        result = search->results;
        while (result) {
            fprintf(fp, "   addr: %s\n", str_addr(&result->addr));
            fprintf(fp, "    state: %s\n", str_state(result->state));
            result_counter += 1;
            result = result->next;
        }
        fprintf(fp, "  Found %d results.\n", result_counter);
        result_counter += 1;
        search_counter += 1;
        search = search->next;
    }

    fprintf(fp, " Found %d searches.\n", search_counter);
}

static void search_restart(struct search_t *search)
{
    struct result_t *result;
    struct result_t *prev;
    struct result_t *next;
    bool remove;

    log_debug("Searches: Restart search for query: %s", search->query);

    search->start_time = time_now_sec();
    search->done = false;

    remove = false;
    next = NULL;
    prev = NULL;

    // Remove all failed searches
    result = search->results;
    while (result) {
        switch (result->state) {
        case AUTH_ERROR:
        case AUTH_AGAIN:
        case AUTH_FAILED:
            remove = true;
            // Remove result
            break;
        case AUTH_OK:
            // Check again on another search
            result->state = AUTH_AGAIN;
            break;
        case AUTH_SKIP:
            // Continue check
            result->state = AUTH_WAITING;
            break;
        case AUTH_PROGRESS:
            // Continue progress state
            break;
        case AUTH_WAITING:
            // Continue wait state
            break;
        }

        if (remove) {
            next = result->next;
            if (prev) {
                prev->next = next;
            } else {
                search->results = next;
            }
            free(result);
            result = next;
            remove = false;
        } else {
            prev = result;
            result = result->next;
        }
    }
}

// Start a new search for a sanitized query
struct search_t* searches_start(const char query[])
{
    uint8_t id[SHA1_BIN_LENGTH];
    auth_callback *callback;
    struct search_t* search;

    // Find existing search
    if ((search = searches_find_by_query(query)) != NULL) {
        // Restart search after half of search lifetime
        if ((time_now_sec() - search->start_time) > (MAX_SEARCH_LIFETIME / 2)) {
            search_restart(search);
        }

        return search;
    }

#ifdef TLS
    if (tls_client_get_id(id, sizeof(id), query)) {
        // Use TLS authentication
        // For e.g. example.com.p2p
        callback = &tls_client_trigger_auth;
    } else
#endif
#ifdef BOB
    if (bob_get_id(id, sizeof(id), query)) {
        // Use Bob authentication
        // For e.g. <32BytePublicKey>.p2p
        callback = &bob_trigger_auth;
    } else
#endif
    if (hex_get_id(id, sizeof(id), query)) {
        // Use no authentication
        // For e.g. <20ByteHashKey>.p2p
        callback = NULL;
    } else {
        // No idea what to do
        log_debug("Searches: No idea how what method to use for %s", query);
        return NULL;
    }

    search = calloc(1, sizeof(struct search_t));
    memcpy(search->id, id, sizeof(id));
    search->callback = callback;
    memcpy(&search->query, query, sizeof(search->query));
    search->start_time = time_now_sec();

    log_debug("Searches: Create new search for query: %s", query);

    search->next = g_searches;
    g_searches = search;

    return search;
}

// Add a resolved address to the search (and continue with verification if needed)
void searches_add_addr(struct search_t *search, const IP *addr)
{
    struct result_t *cur;
    struct result_t *new;
    struct result_t *last;
    int count;

    if (search->done) {
        // No need to add more addresses
        return;
    }

    // Check if result already exists
    // or maximum result count is reached
    count = 0;
    last = NULL;
    cur = search->results;
    while (cur) {
        last = cur;

        if (addr_equal(&cur->addr, addr)) {
            // Address already listed
            return;
        }

        if (count > MAX_RESULTS_PER_SEARCH) {
            return;
        }

        count += 1;
        cur = cur->next;
    }

    new = calloc(1, sizeof(struct result_t));
    memcpy(&new->addr, addr, sizeof(IP));
    new->state = search->callback ? AUTH_WAITING : AUTH_OK;

    // Append new entry to list
    if (last) {
        last->next = new;
    } else {
        search->results = new;
    }

    if (search->callback) {
        search->callback();
    }
}

int is_valid_result(const struct result_t *result) {
    const int state = result->state;
    return state == AUTH_OK || state == AUTH_AGAIN;
}

void searches_setup(void)
{
    // Nothing to do
}

void searches_free(void)
{
    struct search_t *search;
    struct search_t *prev;

    search = g_searches;
    while (search) {
        prev = search;
        search = search->next;
        search_free(prev);
    }
}
