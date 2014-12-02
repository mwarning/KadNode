:: Set DNS settings and start KadNode so that KadNode can answer specific DNS queries

@ECHO OFF


SETLOCAL EnableDelayedExpansion

FOR /F "tokens=* delims=:" %%a IN ('IPCONFIG ^| FIND /I "ETHERNET ADAPTER"') DO (
SET adapterName=%%a

REM Removes "Ethernet adapter" from the front of the adapter name
SET adapterName=!adapterName:~17!

REM Removes the colon from the end of the adapter name
SET adapterName=!adapterName:~0,-1!

REM Set fixed DNS server (Google) and KadNode as second

netsh interface ipv4 add dns name="!adapterName!" 8.8.8.8 index=1 validate=no
netsh interface ipv4 add dns name="!adapterName!" 127.0.0.1 index=2 validate=no
netsh interface ipv6 add dns name="!adapterName!" 2001:4860:4860::8888 index=1 validate=no
netsh interface ipv6 add dns name="!adapterName!" ::1 index=2 validate=no
)

ipconfig /flushdns
