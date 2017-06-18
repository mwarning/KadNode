
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

#include <unistd.h>

#include "main.h"
#include "log.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "results.h"
#include "ext-filter.h"

/*
gcc -fPIC -c -o test.o test.c
gcc -fPIC -shared -Wl,-soname,test.so.2 -o test.so.2 test.o
*/

/*
be able to set a default status for each search?

filter returns verified, unverified, blacklist
*/

struct action {
	struct action *next;
	int state; // state to set
	uint8_t id[SHA1_BIN_LENGTH];
	IP addr;
};

//typedef int (__attribute__ ((__may_alias__)) *filter_func_t)( const uint8_t id[], const IP *addr );
typedef int (*filter_func_t)( const uint8_t id[], const IP *addr );

filter_func_t g_filter_func = NULL;
struct action *g_actions = NULL;

int filter_on_result( const uint8_t id[SHA1_BIN_LENGTH], const IP addr ) {
	//uint8_t id[SHA1_BIN_LENGTH];
	//IP addr;
	struct action *new;
	int state;
	pid_t pid;
	int rc;

	if( gconf->filter_call == NULL ) {
		return 0;
	}

	pid = fork();
	if( pid != 0 ) {
		/* Parent or Error */
		return 0; //mark as wait for verfication
	}

	/* Blocking calls */
	if( g_filter_func ) {
		rc = g_filter_func( &id[0], &addr );
	} else {
		rc = system( gconf->filter_call );
		rc = WEXITSTATUS( rc );
	}

	/* Interpret return code */
	switch( rc ) {
		case 0:
			state = RESULT_STATE_VERIFIED;
			break;
		case 1:
			state = RESULT_STATE_BLACKLIST;
			break;
		default:
			return 0;
	}

	new = (struct action*) malloc( sizeof(struct action) );
	memcpy( &new->id, &id, SHA1_BIN_LENGTH );
	new->addr = addr;
	new->state = state;

	/* Prepend action */
	new->next = g_actions;
	g_actions = new;

	return 0;
}

void filter_apply_actions( int sock_, int rc_ ) {
	struct action *cur;
	struct action *next;

	cur = g_actions;
	g_actions = NULL;

	/* Apply and remove actions */
	while( cur ) {
		next = cur->next;
		results_set_state( &cur->id, &cur->addr, state );
		free( cur );
		cur = next;
	}
}

/* Prepare to call a program/script */
void filter_setup_program( const char target[] ) {
	/* Test if file exists */
	FILE *file;

	file = fopen( target, "r" );
	if( file == NULL ) {
		log_err( "FILTER: Cannot open file: %s", strerror( errno ) );
		return;
	}

	fclose( file );

	if( system( NULL ) == 0 ) {
		log_err( "FILTER: No command processor available." );
		return;
	}
}

/* Prepare to call a function in a shared object */
void filter_setup_object( const char target[] ) {
	void *sobj;

#ifdef __CYGWIN__
	sobj = LoadLibrary( target, RTLD_NOW );
		if( sobj == NULL ) {
		log_err("FILTER: Cannot load shared object: %s", dlerror() );
		return;
	}

	g_filter_func = /*(filter_func_t)*/ GetProcAddress( sobj, "kadnode_filter" );
	if( g_filter_func == NULL ) {
		dlclose( sobj );
		log_err( "Filter : Cannot find function kadnode_filter: %s", dlerror() );
		return;
	}

	dlclose( sobj );
#else
	sobj = dlopen( target, RTLD_NOW );
	if( sobj == NULL ) {
		log_err("FILTER: Cannot load shared object: %s", dlerror() );
		return;
	}

	*(void **) &g_filter_func = dlsym( sobj, "kadnode_filter" );
	if( g_filter_func == NULL ) {
		dlclose( sobj );
		log_err( "Filter : Cannot find function kadnode_filter: %s", dlerror() );
		return;
	}

	dlclose( sobj ); //close on exit???
#endif
}

void filter_setup( void ) {
	const char *target;

	target = gconf->filter_call;

	if( target == NULL) {
		if( is_suffix( target, ".so" ) || is_suffix( target, ".dll" ) ) {
			filter_setup_object( target );
		} else {
			filter_setup_program( target );
		}

		net_add_handler( -1, &filter_apply_actions );
	}
}

void filter_free( void ) {
	/* Nothing to do */
}
