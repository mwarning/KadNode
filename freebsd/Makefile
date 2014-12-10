# Created by: Moritz Warning <moritzwarning@web.de>
# $FreeBSD$

PORTNAME=	kadnode
PORTVERSION=	0.9.2
PORTREVISION=	1
CATEGORIES=	dns
MASTER_SITES=	https://github.com/mwarning/KadNode/archive/
DISTNAME=	v${DISTVERSION}${DISTVERSIONSUFFIX}

MAINTAINER=	moritzwarning@web.de
COMMENT=	P2P name resolution daemon

LICENSE=	MIT

USES=	gmake
WRKSRC=		${WRKDIR}/KadNode-${DISTVERSION}

OPTIONS_DEFINE=	AUTH CMD DEBUG DNS LPD NATPMP NSS UPNP
AUTH_DESC=	Authorization support based on libsodium.
CMD_DESC=	Command line control tool kadnode-ctl.
DEBUG_DESC=	Build with debug messages and symbols.
DNS_DESC=	Include local DNS interface.
LPD_DESC=	Local peer discovery.
NATPMP_DESC=	 NAT-PMP support. Enables remote port forwarding on the router.
NSS_DESC=	Name Service Switch support to intercept host queries (/etc/nsswitch.conf).
UPNP_DESC=	UPnP support. Enable remote port forwarding on the router.

OPTIONS_DEFAULT=	AUTH CMD LPD NSS

.include <bsd.port.options.mk>

.if ${PORT_OPTIONS:MAUTH}
FEATURES+=auth
BUILD_DEPENDS+=	/usr/local/lib/libsodium.a:${PORTSDIR}/security/libsodium
.endif

.if ${PORT_OPTIONS:MCMD}
FEATURES+=cmd
.endif

.if ${PORT_OPTIONS:MDEBUG}
FEATURES+=debug
.endif

.if ${PORT_OPTIONS:MDNS}
FEATURES+=dns
.endif

.if ${PORT_OPTIONS:MLPD}
FEATURES+=lpd
.endif

.if ${PORT_OPTIONS:MNATPMP}
FEATURES+=natpmp
LIB_DEPENDS+=	libnatpmp.so:${PORTSDIR}/net/libnatpmp
.endif

.if ${PORT_OPTIONS:MNSS}
FEATURES+=nss
.endif

.if ${PORT_OPTIONS:MUPNP}
FEATURES+=upnp
LIB_DEPENDS+=	libminiupnpc.so:${PORTSDIR}/net/miniupnpc
.endif

MAKE_ENV+=	FEATURES="${FEATURES}"

do-install:
	${MKDIR} ${STAGEDIR}/usr/bin
	${INSTALL_PROGRAM} ${WRKSRC}/build/kadnode ${STAGEDIR}${PREFIX}/bin/
	${INSTALL_PROGRAM} ${WRKSRC}/build/kadnode-ctl ${STAGEDIR}${PREFIX}/bin/

	${INSTALL_LIB} ${WRKSRC}/build/libnss_kadnode.so.2 ${STAGEDIR}${PREFIX}/lib/nss_kadnode.so
	${LN} -sf ${STAGEDIR}${PREFIX}/lib/nss_kadnode.so ${STAGEDIR}${PREFIX}/lib/nss_kadnode.so.1

	${MKDIR} ${STAGEDIR}/etc/kadnode
	${INSTALL_DATA} ${WRKSRC}/misc/peers.txt ${STAGEDIR}/etc/kadnode/
	${INSTALL_DATA} ${WRKSRC}/misc/kadnode.conf ${STAGEDIR}/etc/kadnode/

	${MKDIR} ${STAGEDIR}/etc/rc.d/
	${INSTALL_SCRIPT} ${WRKSRC}/freebsd/files/kadnode.init ${STAGEDIR}/etc/rc.d/kadnode

	${INSTALL_MAN} ${WRKSRC}/misc/kadnode.1 ${STAGEDIR}${MANPREFIX}/man/man1/

.include <bsd.port.mk>
