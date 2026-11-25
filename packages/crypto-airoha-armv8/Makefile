# SPDX-License-Identifier: GPL-2.0-only
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=crypto-airoha-armv8
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define KernelPackage/crypto-airoha-armv8
  SUBMENU:=Cryptographic API modules
  TITLE:=ARMv8 AES and GHASH Crypto Extensions for Airoha
  DEPENDS:=@TARGET_airoha +kmod-crypto-gcm
  KCONFIG:=CONFIG_CRYPTO_AES_ARM64_CE CONFIG_CRYPTO_AES_ARM64_CE_BLK CONFIG_CRYPTO_GHASH_ARM64_CE
  FILES:= \
    $(LINUX_DIR)/arch/arm64/crypto/aes-ce-cipher.ko \
    $(LINUX_DIR)/arch/arm64/crypto/aes-ce-blk.ko \
    $(LINUX_DIR)/arch/arm64/crypto/ghash-ce.ko
  AUTOLOAD:=$(call AutoLoad,10,aes-ce-cipher aes-ce-blk ghash-ce)
endef

define KernelPackage/crypto-airoha-armv8/description
  Packages the ARM64 AES and GHASH drivers on Airoha. On CPUs with PMULL,
  ghash-ce also registers the fused RFC4106 AES-GCM implementation for ESP.
endef

define Build/Compile
endef

$(eval $(call KernelPackage,crypto-airoha-armv8))
