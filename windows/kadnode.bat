:: Set primary and alternate DNS for IPv4/IPv6 on Windows Server 2000/2003/2008 & Windows XP/Vista/7
@ECHO OFF
SETLOCAL EnableDelayedExpansion

SET adapterName=

FOR /F "tokens=* delims=:" %%a IN ('IPCONFIG ^| FIND /I "ETHERNET ADAPTER"') DO (
SET adapterName=%%a

REM Removes "Ethernet adapter" from the front of the adapter name
SET adapterName=!adapterName:~17!

REM Removes the colon from the end of the adapter name
SET adapterName=!adapterName:~0,-1!

netsh interface ipv4 add dns name="!adapterName!" 127.0.0.1 index=1
netsh interface ipv6 add dns name="!adapterName!" ::1 index=1
)

ipconfig /flushdns

::Start KadNode
kadnode --config config.txt --peerfile peers.txt --port 53 --daemon
