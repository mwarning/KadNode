
#include "windows.h"
#include "main.h"
#include "conf.h"
#include "log.h"

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

static SERVICE_STATUS sStatus;
static SERVICE_STATUS_HANDLE hServiceStatus = 0;

static void (*svc_main_func)();


void windows_service_control( DWORD dwControl ) {
	switch (dwControl) {
		case SERVICE_CONTROL_SHUTDOWN:
		case SERVICE_CONTROL_STOP:
			sStatus.dwCurrentState = SERVICE_STOP_PENDING;
			sStatus.dwCheckPoint = 0;
			sStatus.dwWaitHint = 3000; /* Three seconds */
			sStatus.dwWin32ExitCode = 0;
			gconf->is_running = 0;
		default:
			sStatus.dwCheckPoint = 0;
	}
	SetServiceStatus( hServiceStatus, &sStatus );
}

void windows_service_main( int argc, char **argv ) {

	hServiceStatus = RegisterServiceCtrlHandler( argv[0], (LPHANDLER_FUNCTION) windows_service_control );
	if( hServiceStatus == 0 ) {
		return;
	}

	sStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	sStatus.dwCurrentState = SERVICE_START_PENDING;
	sStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	sStatus.dwWin32ExitCode = 0;
	sStatus.dwServiceSpecificExitCode = 0;
	sStatus.dwCheckPoint = 0;
	sStatus.dwWaitHint = 3000; /* Allow us to wait three seconds */
	sStatus.dwCurrentState = SERVICE_RUNNING;

	SetServiceStatus( hServiceStatus, &sStatus );

	/* The main program */
	svc_main_func();

	/* cleanup */
	sStatus.dwCurrentState  = SERVICE_STOPPED;
	SetServiceStatus( hServiceStatus, &sStatus );
}

int windows_service_start( void (*func)() ) {
	static SERVICE_TABLE_ENTRY services[] = {
		{ MAIN_SRVNAME,  (LPSERVICE_MAIN_FUNCTIONA) windows_service_main },
		{ NULL, NULL }
	};

	/* Safe args for later call in windows_service_main() */
	svc_main_func = func;
	
	if( !StartServiceCtrlDispatcher( services ) ) {
		log_warn( "WIN: Can not start service: Error %d", GetLastError() );
		return 1;
	} else {
		return 0;
	}
}

/*
* Similar to:
* sc create KadNode type= own DisplayName= KadNode start= auto error= normal binPath= C:\...\kadnode.exe
*/
void windows_service_install( void ) {
	char path[MAX_PATH];

	GetModuleFileName( NULL, path, sizeof(path) );

	SC_HANDLE hSCManager = OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
	SC_HANDLE hService = CreateService(
		hSCManager,
		MAIN_SRVNAME, /* name of service */
		MAIN_SRVNAME, /* name to display */
		SERVICE_ALL_ACCESS, /* desired access */
		SERVICE_WIN32_OWN_PROCESS, /* service type */
		SERVICE_AUTO_START, /* start type */
		SERVICE_ERROR_NORMAL, /* error control type */
		path, /* service binary */
		NULL, /* no load order group */
		NULL, /* no tag identifier */
		"", /* dependencies */
		0,	/* LocalSystem account */
		0	/* no password */
	);

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	log_info( "WIN: Service installed." );
}

/*
* Similar to:
* sc delete KadNode
*/
void windows_service_remove( void ) {
	SC_HANDLE hService = 0;
	SC_HANDLE hSCManager = OpenSCManager( 0, 0, 0 );
	hService = OpenService( hSCManager, MAIN_SRVNAME, DELETE );
	DeleteService( hService );
	CloseServiceHandle( hService );
	CloseServiceHandle( hSCManager );
	log_info( "WIN: Service removed." );
}

static BOOL WINAPI windows_console_handler( int event ) {
	switch( event ) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
			gconf->is_running = 0;
			log_info( "Shutting down..." );
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

int windows_exec( const char* cmd ) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );

	/* Start the child process */
	if( !CreateProcess( NULL, // No module name (use command line)
		(char*) cmd, // Command line
		NULL, // Process handle not inheritable
		NULL, // Thread handle not inheritable
		FALSE, // Set handle inheritance to FALSE
		0, // No creation flags
		NULL, // Use parent's environment block
		NULL, // Use parent's starting directory
		&si, // Pointer to STARTUPINFO structure
		&pi ) // Pointer to PROCESS_INFORMATION structure
	) {
		log_warn( "CreateProcess failed: Error %d", GetLastError() );
		return 1;
	}

	// Wait until child process exits.
	WaitForSingleObject( pi.hProcess, INFINITE );

	// Close process and thread handles.
	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );

	return 0;
}
