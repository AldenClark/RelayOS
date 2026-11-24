# SPDX-License-Identifier: Apache-2.0
include $(TOPDIR)/rules.mk

PKG_NAME:=relay-ipsec
PKG_VERSION:=1
PKG_RELEASE:=3
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
    +kmod-crypto-gcm +xfrm +ip-full +ucode +ucode-mod-fs +ucode-mod-uci +coreutils-timeout
endef

define Package/relay-ipsec/description
  Installs the constrained multi-peer RelayOS IKEv2 configuration manager,
  using one upstream swanctl daemon with per-peer Linux XFRM interfaces.
  EIP93 is a Crypto API accelerator, not SOE packet offload. Disabled by default.
endef

define Build/Compile
endef

define Package/relay-ipsec/install
	$(INSTALL_DIR) $(1)/usr/libexec $(1)/etc/init.d $(1)/usr/share/relay-ipsec $(1)/usr/libexec/rpcd $(1)/etc/strongswan.d
	$(INSTALL_BIN) ./files/relay-ipsec $(1)/usr/libexec/relay-ipsec
	$(INSTALL_BIN) ./files/relay-ipsec-prepare $(1)/etc/init.d/relay-ipsec-prepare
	$(INSTALL_BIN) ./files/relay.ipsec $(1)/usr/libexec/rpcd/relay.ipsec
	$(INSTALL_DATA) ./files/relay-ipsec-model.uc $(1)/usr/share/relay-ipsec/model.uc
	$(INSTALL_DATA) ./files/relay-ipsec-worker.uc $(1)/usr/share/relay-ipsec/worker.uc
	$(INSTALL_DATA) ./files/relay-ipsec.conf $(1)/etc/strongswan.d/relay-ipsec.conf
endef

$(eval $(call BuildPackage,relay-ipsec))
