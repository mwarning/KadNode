cmake_minimum_required(VERSION 3.23)
project(KadNode C)

OPTION(DNS "DNS Proxy" ON)
OPTION(TLS "TLS Authentication" ON)
OPTION(BOB "BOB Authentication" ON)
OPTION(LPD "Local Peer Discovery (LPD) Support" ON)
OPTION(CMD "kadnode-ctl KadNode Control Program" ON)
OPTION(NATPMP "Port Forwarding NAT-PMP/PCP" OFF)
OPTION(UPNP "Port Forwarding UPnP" OFF)

SET(CMAKE_C_STANDARD 11)
ADD_DEFINITIONS(-Os -Wall -Wwrite-strings -pedantic)

SET(SOURCES src/announces.c
        src/conf.c
        src/kad.c
        src/log.c
        src/main.c
        src/net.c
        src/peerfile.c
        src/searches.c
        src/utils.c
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    ADD_DEFINITIONS(-DDEBUG)
endif()

IF(UNIX)
    SET(SOURCES ${SOURCES} src/unix.c)
ENDIF()
IF(WIN32)
    SET(SOURCES ${SOURCES} src/unix.c src/windows.c)
ENDIF()


IF(CMD)
    SET(SOURCES ${SOURCES} src/ext-cmd.c)
    ADD_DEFINITIONS(-DCMD)
ENDIF()
IF(BOB)
    SET(SOURCES ${SOURCES} src/ext-bob.c src/ecc_point_compression.c)
    ADD_DEFINITIONS(-DBOB)
ENDIF()
IF(DNS)
    SET(SOURCES ${SOURCES} src/ext-dns.c)
    ADD_DEFINITIONS(-DDNS)
ENDIF()
IF(TLS)
    SET(SOURCES ${SOURCES} src/ext-tls-server.c src/ext-tls-client.c)
    ADD_DEFINITIONS(-DTLS)
ENDIF()
IF(LPD)
    SET(SOURCES ${SOURCES} src/ext-lpd.c)
    ADD_DEFINITIONS(-DLPD)
ENDIF()

IF(NATPMP)
    SET(SOURCES ${SOURCES} src/ext-fwd.c src/natpmp.c)
    ADD_DEFINITIONS(-DFWD -DFWD_NATPMP)
    ADD_LINK_OPTIONS(-Wl,-Bdynamic -lnatpmp)
ENDIF()
IF(UPNP)
    SET(SOURCES ${SOURCES} src/ext-fwd.c src/upnp.c)
    ADD_DEFINITIONS(-DFWD -DFWD_UPNP)
    ADD_LINK_OPTIONS(-Wl,-Bdynamic -lminiupnpc)
ENDIF()


add_executable(kadnode ${SOURCES})
target_link_libraries(kadnode mbedtls mbedx509 mbedcrypto)
