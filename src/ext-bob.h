
#ifndef _EXT_BOB_H_
#define _EXT_BOB_H_

#include <stdio.h>

// Decide if the query is meant to be authorized via BOB
bool bob_parse_id(uint8_t id[], const char query[], size_t querylen);
void bob_trigger_auth(void);

// .. for kad.c - remove?
bool bob_handler(int sock, uint8_t buf[], uint32_t buflen, IP *from);

// Load a key file
bool bob_load_key(const char path[]);

// Create a key file
bool bob_create_key(const char path[]);

// Print secret/public keys to file descriptor
void bob_debug_keys(FILE *fp);

bool bob_setup(void);
void bob_free(void);


#endif // _EXT_BOB_H_
