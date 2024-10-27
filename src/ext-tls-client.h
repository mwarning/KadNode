
#ifndef _EXT_TLS_CLIENT_H_
#define _EXT_TLS_CLIENT_H_


// Add Certifiacte Authorities (CAs)
bool tls_client_add_ca(const char ca_path[]);

// Decide if the query is meant to be authorized via an CA
bool tls_client_parse_id(uint8_t id[], size_t idlen, const char query[], size_t querylen);

// Trigger authorisation of results; need to be called multiple times.
void tls_client_trigger_auth(void);

bool tls_client_setup(void);
void tls_client_free(void);


#endif // _EXT_TLS_CLIENT_H_
