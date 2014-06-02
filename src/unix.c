
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <fcntl.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "unix.h"


void unix_signal( void ) {

	/* STRG+C aka SIGINT => Stop the program */
	gconf->sig_stop.sa_handler = unix_sig_stop;
	gconf->sig_stop.sa_flags = 0;
	if( ( sigemptyset( &gconf->sig_stop.sa_mask ) == -1) || (sigaction( SIGINT, &gconf->sig_stop, NULL ) != 0) ) {
		log_err( "UNX: Failed to set SIGINT to handle Ctrl-C" );
	}

	/* SIGTERM => Stop the program gracefully */
	gconf->sig_term.sa_handler = unix_sig_term;
	gconf->sig_term.sa_flags = 0;
	if( ( sigemptyset( &gconf->sig_term.sa_mask ) == -1) || (sigaction( SIGTERM, &gconf->sig_term, NULL ) != 0) ) {
		log_err( "UNX: Failed to set SIGTERM to handle Ctrl-C" );
	}
}

void unix_sig_stop( int signo ) {
	gconf->is_running = 0;
	log_info( "Shutting down..." );
}

void unix_sig_term( int signo ) {
	gconf->is_running = 0;
}

void unix_fork( void ) {
	pid_t pid;
	pid_t sid;

	pid = fork();

	if( pid < 0 ) {
		log_err( "UNX: Failed to fork." );
	} else if( pid != 0 ) {
		/* Child process */
		exit( 0 );
	}

	/* Become session leader */
	sid = setsid();
	if( sid < 0 ) {
		exit( 1);
	}

	/* Clear out the file mode creation mask */
	umask( 0 );
}

void unix_write_pidfile( pid_t pid ) {
	FILE *file;

	if( gconf->pidfile == NULL ) {
		return;
	}

	file = fopen( gconf->pidfile, "r" );
	if( file ) {
		fclose( file );
		log_err( "UNX: PID file already exists: %s", gconf->pidfile );
		return;
	}

	file = fopen( gconf->pidfile, "w" );
	if( file == NULL ) {
		log_err( "UNX: Failed to open PID file." );
	}

	if( fprintf( file, "%i", pid ) < 0 ) {
		log_err( "UNX: Failed to write PID file." );
	}

	if( fclose( file ) < 0 ) {
		log_err( "UNX: Failed to close PID file." );
	}
}

void unix_dropuid0( void ) {
	struct passwd *pw;

	/* Return if no user is set */
	if( gconf->user == NULL ) {
		return;
	}

	/* Return if we are not root */
	if( getuid() != 0 ) {
		return;
	}

	/* Process is running as root, drop privileges */
	if( (pw = getpwnam( gconf->user )) == NULL ) {
		log_err( "UNX: Dropping uid 0 failed. Set a valid user." );
	}

	if( setenv( "HOME", pw->pw_dir, 1 ) != 0 ) {
		log_err( "UNX: Setting new $HOME failed." );
	}

	if( setgid( pw->pw_gid ) != 0 ) {
		log_err( "UNX: Unable to drop group privileges" );
	}

	if( setuid( pw->pw_uid ) != 0 ) {
		log_err( "UNX: Unable to drop user privileges" );
	}

	/* Test permissions */
	if( setuid( 0 ) != -1 || setgid( 0 ) != -1 ) {
		log_err( "UNX: We still have root privileges" );
	}
}
