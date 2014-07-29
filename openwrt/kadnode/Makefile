#
# Copyright (C) 2013-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=kadnode
PKG_VERSION:=0.9.2
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/mwarning/KadNode.git
PKG_SOURCE_VERSION:=master
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/
PKG_BUILD_PARALLEL:=1
PKG_BUILD_DEPENDS:=libsodium

include $(INCLUDE_DIR)/package.mk

define Package/kadnode
	SECTION:=net
	CATEGORY:=Network
	TITLE:=P2P DNS Server
	DEPENDS:=
	SUBMENU:=IP Addresses and Names
	URL:=https://github.com/mwarning/KadNode
	MENU:=1
endef

define Package/kadnode/description
	P2P name resolution daemon
endef

define Package/kadnode/config
	source "$(SOURCE)/Config.in"
endef

FEATURES = cmd

ifeq ($(CONFIG_KADNODE_ENABLE_LPD),y)
FEATURES += lpd
endif

ifeq ($(CONFIG_KADNODE_ENABLE_AUTH),y)
FEATURES += auth
endif

ifeq ($(CONFIG_KADNODE_ENABLE_DNS),y)
FEATURES += dns
endif

ifeq ($(CONFIG_KADNODE_ENABLE_WEB),y)
FEATURES += web
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
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/kadnode-ctl $(1)/usr/bin/

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
