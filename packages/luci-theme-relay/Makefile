# SPDX-License-Identifier: Apache-2.0

include $(TOPDIR)/rules.mk

LUCI_TITLE:=RelayOS Console (minimal node UI)
LUCI_DEPENDS:=+luci-base +luci-mod-network +luci-mod-system +luci-proto-wireguard
LUCI_PKGARCH:=all

# Keep CSS variables and the small UI sources intact across pinned LuCI updates.
LUCI_MINIFY_CSS:=0
LUCI_MINIFY_JS:=0

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=RelayOS Project

include $(TOPDIR)/feeds/luci/luci.mk

# OpenWrt's include/scan.mk discovers package directories by this signature,
# even when a helper include invokes BuildPackage on the package's behalf.
# call BuildPackage - OpenWrt buildroot signature
