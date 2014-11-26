:: Reset DNS settings and stop KadNode
@ECHO OFF



:: Check privileges
net session >nul 2>&1
if NOT %errorLevel% == 0 (
  echo Failure: Need to be run as administrator.
  exit /B 1
)

SETLOCAL EnableDelayedExpansion

FOR /F "tokens=* delims=:" %%a IN ('IPCONFIG ^| FIND /I "ETHERNET ADAPTER"') DO (
SET adapterName=%%a


REM Removes "Ethernet adapter" from the front of the adapter name

SET adapterName=!adapterName:~17!




REM Removes the colon from the end of the adapter name

SET adapterName=!adapterName:~0,-1!




netsh interface ip set address "!adapterName!" dhcp

netsh interface ip delete dnsserver "!adapterName!" all
)



ipconfig /flushdns



taskkill.exe /f /im kadnode.exe
