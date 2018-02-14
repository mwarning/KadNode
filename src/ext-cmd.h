
#ifndef _EXT_CMD_H_
#define _EXT_CMD_H_

// kadnode-ctl
int cmd_client(int argc, char *argv[]);

// Start the remote console interface
int cmd_setup(void);
void cmd_free(void);

#endif // _EXT_CMD_H_
