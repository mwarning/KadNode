
#ifndef _WINDOWS_H_
#define _WINDOWS_H_

/* Setup a Windows Service */
void windows_service_install( void );
void windows_service_remove( void );
int windows_service_start( int (*func)(int, char **), int argc, char** argv );

void windows_signals( void );

#endif /* _WINDOWS_H_ */
