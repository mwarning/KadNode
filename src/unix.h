

#ifndef _UNIX_H_
#define _UNIX_H_

void unix_signal( void );
void unix_sig_stop( int signo );
void unix_sig_term( int signo );
void unix_fork( void );
void unix_write_pidfile( pid_t );
void unix_dropuid0( void );

#endif /* _UNIX_H_ */
