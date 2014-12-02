:: Reset DNS settings and stop KadNode
@ECHO OFF


SETLOCAL EnableDelayedExpansion

FOR /F "tokens=* delims=:" %%a IN ('IPCONFIG ^| FIND /I "ETHERNET ADAPTER"') DO (
SET adapterName=%%a

REM Removes "Ethernet adapter" from the front of the adapter name
SET adapterName=!adapterName:~17!

REM Removes the colon from the end of the adapter name
SET adapterName=!adapterName:~0,-1!

netsh interface ip set address "!adapterName!" dhcp
)

ipconfig /flushdns

taskkill.exe /f /im kadnode.exe >nul 2>&1
