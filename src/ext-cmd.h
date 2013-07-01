
#ifndef _EXT_CMD_H_
#define _EXT_CMD_H_

/* A UDP packet sized reply */
typedef struct Reply {
	char data[1472];
	ssize_t size;
} REPLY;

/* Start the remote console interface */
void cmd_setup( void );

#endif /* _EXT_CMD_H_ */
