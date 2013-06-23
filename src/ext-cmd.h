
#ifndef _EXT_CMD_H_
#define _EXT_CMD_H_

/* A UDP packet sized reply */
typedef struct Reply {
	char data[1472];
	ssize_t size;
} REPLY;

void cmd_console_loop( void );

/* Start the remote console interface */
void cmd_start( void );
void cmd_stop( void );

#endif /* _EXT_CMD_H_ */
