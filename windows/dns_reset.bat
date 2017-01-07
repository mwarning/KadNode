:: Reset DNS settings of all interfaces to DHCP.
:: This script is executed by KadNode.

@ECHO OFF


SETLOCAL EnableDelayedExpansion

FOR /F "tokens=* delims=:" %%a IN ('IPCONFIG ^| FIND /I "ETHERNET ADAPTER"') DO (
SET adapterName=%%a

REM Removes "Ethernet adapter" from the front of the adapter name
SET adapterName=!adapterName:~17!

REM Removes the colon from the end of the adapter name
SET adapterName=!adapterName:~0,-1!

set skip=0

ECHO.!adapterName!| FIND /I "vpn">Nul && ( set skip=1 )
ECHO.!adapterName!| FIND /I "virtual">Nul && ( set skip=1 )

if !skip! == 0 (
    netsh interface ipv4 set dnsservers name="!adapterName!" source= dhcp
    netsh interface ipv6 set dnsservers name="!adapterName!" source= dhcp
    )
)

start sc config dnscache start= auto
start net start dnscache
start ipconfig /flushdns
