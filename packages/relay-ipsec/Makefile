# SPDX-License-Identifier: Apache-2.0
include $(TOPDIR)/rules.mk

PKG_NAME:=relay-ipsec
PKG_VERSION:=1
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
include $(INCLUDE_DIR)/package.mk

define Package/relay-ipsec
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=RelayOS native IKEv2 and kernel IPsec service
  PKGARCH:=all
  DEPENDS:=+strongswan +strongswan-charon +strongswan-swanctl \
    +strongswan-mod-kernel-netlink +strongswan-mod-socket-default +strongswan-mod-vici \
    +strongswan-mod-aes +strongswan-mod-sha2 +strongswan-mod-hmac +strongswan-mod-kdf \
    +strongswan-mod-random +strongswan-mod-drbg +strongswan-mod-curve25519 \
    +strongswan-mod-gcm +strongswan-mod-gmp \
    +kmod-ipsec +kmod-ipsec4 +kmod-xfrm-interface +kmod-crypto-hw-eip93 \
    +kmod-crypto-gcm +xfrm +ip-full
endef

define Package/relay-ipsec/description
  Installs the constrained RelayOS IPsec service controls and uses the upstream
  swanctl IKE daemon with Linux XFRM. EIP93 is a Crypto API accelerator, not
  SOE packet offload. The service is disabled by default.
endef

define Build/Compile
endef

define Package/relay-ipsec/install
	$(INSTALL_DIR) $(1)/usr/libexec $(1)/etc/init.d
	$(INSTALL_BIN) ./files/relay-ipsec $(1)/usr/libexec/relay-ipsec
	$(INSTALL_BIN) ./files/relay-ipsec-prepare $(1)/etc/init.d/relay-ipsec-prepare
endef

$(eval $(call BuildPackage,relay-ipsec))
