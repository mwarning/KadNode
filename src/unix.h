
#ifndef _UNIX_H_
#define _UNIX_H_

void unix_signals(void);
int unix_create_unix_socket(const char path[], int *sock_out);
void unix_remove_unix_socket(const char path[], int sock_in);
void unix_fork(void);
void unix_write_pidfile(int pid, const char pidfile[]);
void unix_dropuid0(void);

#endif /* _UNIX_H_ */
