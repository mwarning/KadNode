
#ifndef _UNIX_H_
#define _UNIX_H_

void unix_signals( void );
void unix_fork( void );
void unix_write_pidfile( int pid, const char* pidfile );
void unix_dropuid0( void );

#endif /* _UNIX_H_ */
