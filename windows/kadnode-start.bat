:: Set DNS settings and start KadNode so that KadNode can answer specific DNS queries
@ECHO OFF

:: Check privileges
net session >nul 2>&1
if NOT %errorLevel% == 0 (
  echo Failure: Need to be run as administrator.
  exit /B 1
)

:: Set DNS
SETLOCAL EnableDelayedExpansion

FOR /F "tokens=* delims=:" %%a IN ('IPCONFIG ^| FIND /I "ETHERNET ADAPTER"') DO (
SET adapterName=%%a

REM Removes "Ethernet adapter" from the front of the adapter name
SET adapterName=!adapterName:~17!

REM Removes the colon from the end of the adapter name
SET adapterName=!adapterName:~0,-1!

REM Set fixed DNS server (Google) and KadNode as second
netsh interface ipv4 add dns name="!adapterName!" 8.8.8.8 index=1
netsh interface ipv4 add dns name="!adapterName!" 127.0.0.1 index=2
netsh interface ipv6 add dns name="!adapterName!" 2001:4860:4860::8888 index=1
netsh interface ipv6 add dns name="!adapterName!" ::1 index=2
)

ipconfig /flushdns

:: Get script path
SET path=%~dp0%
path=!path:~0,-1!

:: Kill running instances
taskkill.exe /f /im kadnode.exe

:: Start KadNode
"!path!\kadnode.exe" --config "!path!\config.txt" --peerfile "!path!\peers.txt" --port 53 --daemon
