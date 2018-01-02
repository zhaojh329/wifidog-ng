#
# Copyright (C) 2014-2017 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wifidog-ng
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=https://github.com/zhaojh329/wifidog-ng.git
PKG_SOURCE_DATE:=2018-1-2
PKG_SOURCE_VERSION:=0e32a8d8fced72c1c54cf38241d5a43863c67747
PKG_MIRROR_HASH:=644ec0954dca7a93d23725a659ac5ea003cae619a6fa5fe0a10073b0f3be7efe

PKG_BUILD_DIR=$(BUILD_DIR)/$(PKG_NAME)-$(BUILD_VARIANT)/$(PKG_SOURCE_SUBDIR)

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE

PKG_MAINTAINER:=Jianhui Zhao <jianhuizhao329@gmail.com>

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/wifidog-ng/default
  SUBMENU:=Captive Portals
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Next generation WifiDog
  DEPENDS:=+kmod-wifidog +libuci +libuclient
endef

define Package/wifidog-ng-nossl
  $(Package/wifidog-ng/default)
  TITLE += (NO SSL)
  DEPENDS += +libuhttpd-nossl
  VARIANT:=nossl
endef

define Package/wifidog-ng-openssl
  $(Package/wifidog-ng/default)
  TITLE += (openssl)
  DEPENDS += +libuhttpd-openssl
  VARIANT:=openssl
endef

define Package/wifidog-ng-wolfssl
  $(Package/wifidog-ng/default)
  TITLE += (wolfssl)
  DEPENDS += +libuhttpd-wolfssl
  VARIANT:=wolfssl
endef

define Package/wifidog-ng-mbedtls
  $(Package/wifidog-ng/default)
  TITLE += (mbedtls)
  DEPENDS += +libuhttpd-mbedtls
  VARIANT:=mbedtls
endef

define Package/wifidog-ng/default/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/etc/wifidog
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/wifidog-ng $(1)/usr/bin
	$(INSTALL_BIN) ./files/wifidog.init $(1)/etc/init.d/wifidog
	$(INSTALL_CONF) ./files/wifidog.config $(1)/etc/config/wifidog
	$(INSTALL_DATA) ./files/wifidog.crt $(1)/etc/wifidog
	$(INSTALL_DATA) ./files/wifidog.key $(1)/etc/wifidog
endef

Package/wifidog-ng-nossl/install = $(Package/wifidog-ng/default/install)
Package/wifidog-ng-openssl/install = $(Package/wifidog-ng/default/install)
Package/wifidog-ng-wolfssl/install = $(Package/wifidog-ng/default/install)
Package/wifidog-ng-mbedtls/install = $(Package/wifidog-ng/default/install)

include $(INCLUDE_DIR)/kernel.mk

define KernelPackage/wifidog
  SUBMENU:=Other modules
  TITLE:=Kernel module for wifidog-ng
  DEPENDS:=+kmod-nf-nat
  FILES:=$(PKG_BUILD_DIR)/kmod/wifidog.ko
endef

include $(INCLUDE_DIR)/kernel-defaults.mk

define Build/Compile
	$(call Build/Compile/Default)
	$(MAKE) $(KERNEL_MAKEOPTS) SUBDIRS="$(PKG_BUILD_DIR)"/kmod modules
endef

$(eval $(call BuildPackage,wifidog-ng-nossl))
$(eval $(call BuildPackage,wifidog-ng-mbedtls))
$(eval $(call BuildPackage,wifidog-ng-wolfssl))
$(eval $(call BuildPackage,wifidog-ng-openssl))

$(eval $(call KernelPackage,wifidog))
