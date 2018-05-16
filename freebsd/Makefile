# Created by: Moritz Warning <moritzwarning@web.de>
# $FreeBSD$

PORTNAME=	kadnode
PORTVERSION=	2.2.0
DISTVERSIONPREFIX=v
PORTREVISION=	0
CATEGORIES=	dns

MAINTAINER=	moritzwarning@web.de
COMMENT=	P2P name resolution daemon

LICENSE=	MIT
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		gmake

USE_GITHUB=	yes
GH_ACCOUNT=	mwarning
GH_PROJECT=	KadNode

OPTIONS_DEFINE=	AUTH CMD DEBUG DNS LPD NATPMP NSS UPNP
OPTIONS_DEFAULT= AUTH CMD LPD NSS
AUTH_DESC=	Authorization support based on mbedtls.
CMD_DESC=	Command line control tool kadnode-ctl.
DEBUG_DESC=	Build with debug messages and symbols.
DNS_DESC=	Include local DNS interface.
LPD_DESC=	Local peer discovery.
NATPMP_DESC=	NAT-PMP support. Enables remote port forwarding on the router.
NSS_DESC=	Name Service Switch support to intercept host queries (/etc/nsswitch.conf).
UPNP_DESC=	UPnP support. Enable remote port forwarding on the router.

SUB_FILES=	kadnode kadnode.conf

AUTH_LIB_DEPENDS=	libmbedtls.so:security/mbedtls
AUTH_VARS=		FEATURES+="bob tls"

CMD_VARS=		FEATURES+="cmd"

DEBUG_VARS=		FEATURES+="debug"

DNS_VARS=		FEATURES+="dns"

LPD_VARS=		FEATURES+="lpd"

NATPMP_LIB_DEPENDS=	libnatpmp.so:net/libnatpmp
NATPMP_VARS=		FEATURES+="natpmp"

NSS_VARS=		FEATURES+="nss"

UPNP_LIB_DEPENDS=	libminiupnpc.so:net/miniupnpc
UPNP_VARS=		FEATURES+="upnp"

MAKE_ENV+=		FEATURES="${FEATURES}"

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKSRC}/build/kadnode ${STAGEDIR}${PREFIX}/bin/
	${RLN} -s kadnode ${STAGEDIR}${PREFIX}/bin/kadnode-ctl

	${INSTALL_LIB} ${WRKSRC}/build/libnss_kadnode.so.2 ${STAGEDIR}${PREFIX}/lib/nss_kadnode.so
	${RLN} -s ${STAGEDIR}${PREFIX}/lib/nss_kadnode.so ${STAGEDIR}${PREFIX}/lib/nss_kadnode.so.1

	${MKDIR} ${STAGEDIR}${ETCDIR}
	${INSTALL_DATA} ${WRKSRC}/misc/peers.txt ${STAGEDIR}${ETCDIR}/peers.txt.sample
	${INSTALL_DATA} ${WRKDIR}/kadnode.conf ${STAGEDIR}${ETCDIR}/kadnode.conf.sample

	${MKDIR} ${STAGEDIR}${PREFIX}/etc/rc.d/
	${INSTALL_SCRIPT} ${WRKDIR}/kadnode ${STAGEDIR}${PREFIX}/etc/rc.d/kadnode

	${INSTALL_MAN} ${WRKSRC}/misc/manpage ${STAGEDIR}${MANPREFIX}/man/man1/kadnode.1

.include <bsd.port.mk>
