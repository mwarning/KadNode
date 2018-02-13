
#ifndef _WINDOWS_H_
#define _WINDOWS_H_

// Setup a Windows Service
void windows_service_install(void);
void windows_service_remove(void);
int windows_service_start(void (*func)());

void windows_signals(void);
int windows_exec(const char* cmd);

#endif // _WINDOWS_H_
