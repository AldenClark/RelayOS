#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_source
case "$device" in md) pcie_phy=PHY_AIROHA_PCIE ;; mf) pcie_phy=PHY_AIROHA_AN7583_PCIE ;; esac
cd "$ow"
[[ ! -e .config && ! -e files && ! -e env/kernel-config ]] || die "Refusing to overwrite existing build configuration"
[[ -e package/feeds/relayos/luci-theme-relay/Makefile ]] || die "Local product feed not installed"
cat "$product_root/configs/common.config" "$product_root/configs/$device.config" > .config
mkdir -p env files
cat "$product_root/configs/kernel/common.config" "$product_root/configs/kernel/$device.config" > env/kernel-config
cp -a "$product_root/overlay/." files/
make defconfig

# Check resolved OpenWrt metadata, not only the requested config fragments.
for feature in \
    "CONFIG_TARGET_airoha_${subtarget}_DEVICE_$profile" \
    CONFIG_TARGET_ROOTFS_INITRAMFS CONFIG_TARGET_ROOTFS_SQUASHFS \
    CONFIG_PACKAGE_kmod-wireguard CONFIG_PACKAGE_wireguard-tools \
    CONFIG_PACKAGE_firewall4 CONFIG_PACKAGE_kmod-nft-offload \
    CONFIG_PACKAGE_nftables-json CONFIG_PACKAGE_luci-mod-admin-full \
    CONFIG_PACKAGE_luci-theme-relay CONFIG_PACKAGE_luci-proto-wireguard \
    CONFIG_LUCI_LANG_zh_Hans CONFIG_PACKAGE_luci-i18n-relay-zh-cn \
    CONFIG_PACKAGE_fitblk CONFIG_PACKAGE_uboot-envtools \
    CONFIG_PACKAGE_uhttpd CONFIG_PACKAGE_uhttpd-mod-ubus \
    CONFIG_PACKAGE_relay-ipsec \
    CONFIG_PACKAGE_strongswan \
    CONFIG_PACKAGE_strongswan-charon \
    CONFIG_PACKAGE_strongswan-swanctl \
    CONFIG_PACKAGE_strongswan-mod-kernel-netlink \
    CONFIG_PACKAGE_strongswan-mod-socket-default \
    CONFIG_PACKAGE_strongswan-mod-vici \
    CONFIG_PACKAGE_strongswan-mod-aes \
    CONFIG_PACKAGE_strongswan-mod-sha2 \
    CONFIG_PACKAGE_strongswan-mod-hmac \
    CONFIG_PACKAGE_strongswan-mod-kdf \
    CONFIG_PACKAGE_strongswan-mod-random \
    CONFIG_PACKAGE_strongswan-mod-drbg \
    CONFIG_PACKAGE_strongswan-mod-curve25519 \
    CONFIG_PACKAGE_strongswan-mod-gcm \
    CONFIG_PACKAGE_strongswan-mod-gmp \
    CONFIG_PACKAGE_kmod-ipsec \
    CONFIG_PACKAGE_kmod-ipsec4 \
    CONFIG_PACKAGE_kmod-xfrm-interface \
    CONFIG_PACKAGE_kmod-crypto-hw-eip93 \
    CONFIG_PACKAGE_kmod-crypto-gcm \
    CONFIG_PACKAGE_xfrm \
    CONFIG_PACKAGE_ip-full \
    CONFIG_BUSYBOX_CONFIG_FLOCK CONFIG_BUSYBOX_CONFIG_TIMEOUT CONFIG_BUSYBOX_CONFIG_PIDOF \
    CONFIG_IMAGEOPT CONFIG_VERSIONOPT CONFIG_BUSYBOX_CUSTOM \
    CONFIG_BUSYBOX_CONFIG_UDHCPC CONFIG_BUSYBOX_CONFIG_NSLOOKUP CONFIG_BUSYBOX_CONFIG_NTPD; do
    grep -Fxq "$feature=y" .config || die "Required option not enabled: $feature"
done
for feature in \
    CONFIG_TARGET_MULTI_PROFILE CONFIG_TARGET_PER_DEVICE_ROOTFS CONFIG_TARGET_ROOTFS_EXT4FS \
    CONFIG_PACKAGE_dnsmasq CONFIG_PACKAGE_dnsmasq-full CONFIG_PACKAGE_ppp CONFIG_PACKAGE_ppp-mod-pppoe \
    CONFIG_PACKAGE_odhcp6c CONFIG_PACKAGE_odhcpd-ipv6only \
    CONFIG_PACKAGE_kmod-usb3 CONFIG_PACKAGE_kmod-usb-ledtrig-usbport \
    CONFIG_PACKAGE_luci-theme-bootstrap CONFIG_PACKAGE_luci-theme-bootstrap-dark CONFIG_PACKAGE_luci-theme-bootstrap-light \
    CONFIG_PACKAGE_nftables-nojson CONFIG_PACKAGE_luci-theme-airrelay CONFIG_PACKAGE_luci-i18n-airrelay-zh-cn \
    CONFIG_PACKAGE_audit CONFIG_PACKAGE_bluez-utils CONFIG_PACKAGE_libpam CONFIG_PACKAGE_libtirpc \
    CONFIG_PACKAGE_kexec-tools CONFIG_PACKAGE_lldpd CONFIG_PACKAGE_policycoreutils \
    CONFIG_PACKAGE_kmod-tun CONFIG_PACKAGE_kmod-nft-tproxy \
    CONFIG_PACKAGE_strongswan-full \
    CONFIG_PACKAGE_strongswan-default \
    CONFIG_PACKAGE_strongswan-minimal \
    CONFIG_PACKAGE_strongswan-isakmp \
    CONFIG_PACKAGE_strongswan-ipsec \
    CONFIG_PACKAGE_strongswan-mod-stroke \
    CONFIG_PACKAGE_strongswan-mod-updown \
    CONFIG_PACKAGE_strongswan-mod-kernel-libipsec \
    CONFIG_PACKAGE_kmod-ipt-ipsec \
    CONFIG_STRONGSWAN_INCLUDE_INSECURE CONFIG_KERNEL_SWAP CONFIG_KERNEL_MPTCP \
    CONFIG_BUSYBOX_CONFIG_MKSWAP CONFIG_BUSYBOX_CONFIG_SWAPON CONFIG_BUSYBOX_CONFIG_SWAPOFF \
    CONFIG_BUSYBOX_CONFIG_FEATURE_MOUNT_CIFS \
    CONFIG_KERNEL_DEBUG_INFO CONFIG_BUSYBOX_CONFIG_UDHCPD CONFIG_BUSYBOX_CONFIG_DHCPRELAY \
    CONFIG_BUSYBOX_CONFIG_CROND CONFIG_BUSYBOX_CONFIG_CRONTAB CONFIG_BUSYBOX_CONFIG_FEATURE_NTPD_SERVER; do
    if grep -Eq "^$feature=(y|m)$" .config; then die "Unwanted option enabled: $feature"; fi
done
grep -Fxq 'CONFIG_VERSION_DIST="RelayOS"' .config || die "Distribution branding not retained"
# Confirm the native kernel fragment merge before expensive toolchain/kernel builds.
# The final Linux .config is also checked after compilation.
generic=target/linux/generic/config-6.18
sub=target/linux/airoha/$subtarget/config-6.18
[[ -f "$generic" && -f "$sub" ]] || die "Kernel configuration layout changed; review fragment compatibility"
kconfigs=("$generic")
if [[ -f target/linux/airoha/config-6.18 ]]; then kconfigs+=(target/linux/airoha/config-6.18); fi
kconfigs+=("$sub" env/kernel-config)
args=()
for ((i=1;i<${#kconfigs[@]};i++)); do args+=('+'); done
perl scripts/kconfig.pl "${args[@]}" "${kconfigs[@]}" > tmp/relayos-kernel-merged.config
for feature in EXT4_FS MMC USB_SUPPORT PCI "$usb_phy" "$pcie_phy"; do
    grep -Fxq "# CONFIG_$feature is not set" tmp/relayos-kernel-merged.config || die "Kernel fragment did not disable $feature"
done
require_source
printf 'RelayOS %s single-profile configuration verified\n' "$device"
