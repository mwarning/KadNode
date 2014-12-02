
#include "windows.h"
#include "main.h"
#include "conf.h"
#include "log.h"

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


static BOOL WINAPI windows_console_handler( int event ) {
	switch(event) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
			gconf->is_running = 0;
			return TRUE;
		default:
			return FALSE;
	}
}

/* Install singal handlers to exit KadNode on CTRL+C */
void windows_signals( void ) {
	if( !SetConsoleCtrlHandler( (PHANDLER_ROUTINE) windows_console_handler, TRUE ) ) {
		log_warn( "WIN: Cannot set console handler. Error: %d", GetLastError() );
	}
}
