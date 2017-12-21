#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=kadnode
PKG_VERSION:=2.0.1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/mwarning/KadNode.git
PKG_SOURCE_VERSION:=08868a909d82bd4ad11a83f29665e7b69a311a60

PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_MIRROR_HASH:=cd68068a4bc0acf26a1304723704cf46dc8cc5327300bba6b8a6045d67d542f2
PKG_LICENSE:=MIT
#PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/kadnode
	SECTION:=net
	CATEGORY:=Network
	TITLE:=P2P DNS Server
	SUBMENU:=IP Addresses and Names
	URL:=https://github.com/mwarning/KadNode
	MENU:=1
	DEPENDS:=+KADNODE_ENABLE_BOB:libmbedtls +KADNODE_ENABLE_TLS:libmbedtls +KADNODE_ENABLE_UPNP:libminiupnpc +KADNODE_ENABLE_NATPMP:libnatpmp
	MAINTAINER:=Moritz Warning <moritzwarning@web.de>
endef

define Package/kadnode/description
	P2P DNS resolver
endef

define Package/kadnode/config
	source "$(SOURCE)/Config.in"
endef

FEATURES = 

ifeq ($(CONFIG_KADNODE_ENABLE_CMD),y)
FEATURES += cmd
endif

ifeq ($(CONFIG_KADNODE_ENABLE_LPD),y)
FEATURES += lpd
endif

ifeq ($(CONFIG_KADNODE_ENABLE_AUTH),y)
FEATURES += bob tls
endif

ifeq ($(CONFIG_KADNODE_ENABLE_DNS),y)
FEATURES += dns
endif

ifeq ($(CONFIG_KADNODE_ENABLE_UPNP),y)
FEATURES += upnp
endif

ifeq ($(CONFIG_KADNODE_ENABLE_NATPMP),y)
FEATURES += natpmp
endif

ifeq ($(CONFIG_KADNODE_ENABLE_DEBUG),y)
FEATURES += debug
endif

MAKE_FLAGS += FEATURES="$(FEATURES)"

define Package/kadnode/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/kadnode $(1)/usr/bin/
ifeq ($(CONFIG_KADNODE_ENABLE_CMD),y)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/kadnode-ctl $(1)/usr/bin/
endif
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) files/kadnode.init $(1)/etc/init.d/kadnode
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) files/kadnode.config $(1)/etc/config/kadnode
endef

define Package/kadnode/postinst
	[ -n "$$IPKG_INSTROOT" ] || /etc/init.d/kadnode enable
	exit 0
endef

$(eval $(call BuildPackage,kadnode))
