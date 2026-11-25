#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_source
source "$product_root/scripts/version.sh"
case "$device" in md) pcie_phy=PHY_AIROHA_PCIE ;; mf) pcie_phy=PHY_AIROHA_AN7583_PCIE ;; esac
cd "$ow"
[[ ! -e .config && ! -e files && ! -e env/kernel-config ]] || die "Refusing to overwrite existing build configuration"
[[ -e package/feeds/relayos/luci-theme-relay/Makefile ]] || die "Local product feed not installed"
write_build_identity
cat "$product_root/configs/common.config" "$product_root/configs/$device.config" > .config
printf 'CONFIG_VERSION_NUMBER="%s"\n' "$firmware_version" >> .config
mkdir -p env files
cat "$product_root/configs/kernel/common.config" "$product_root/configs/kernel/$device.config" > env/kernel-config
cp -a "$product_root/overlay/." files/
make defconfig
load_build_identity

# Check resolved OpenWrt metadata, not only the requested config fragments.
for feature in \
    "CONFIG_TARGET_airoha_${subtarget}_DEVICE_$profile" \
    CONFIG_TARGET_ROOTFS_INITRAMFS CONFIG_TARGET_ROOTFS_SQUASHFS \
    CONFIG_PACKAGE_kmod-wireguard CONFIG_PACKAGE_wireguard-tools \
    CONFIG_PACKAGE_firewall4 CONFIG_PACKAGE_kmod-nft-offload \
    CONFIG_PACKAGE_nftables-json CONFIG_PACKAGE_luci-mod-network CONFIG_PACKAGE_luci-mod-system \
    CONFIG_PACKAGE_luci-theme-relay CONFIG_PACKAGE_luci-proto-wireguard \
    CONFIG_LUCI_LANG_zh_Hans CONFIG_PACKAGE_luci-i18n-relay-zh-cn \
    CONFIG_PACKAGE_fitblk CONFIG_PACKAGE_uboot-envtools \
    CONFIG_PACKAGE_uhttpd CONFIG_PACKAGE_uhttpd-mod-ubus \
    CONFIG_IMAGEOPT CONFIG_VERSIONOPT CONFIG_BUSYBOX_CUSTOM \
    CONFIG_BUSYBOX_CONFIG_UDHCPC CONFIG_BUSYBOX_CONFIG_NSLOOKUP CONFIG_BUSYBOX_CONFIG_NTPD; do
    grep -Fxq "$feature=y" .config || die "Required option not enabled: $feature"
done
for feature in \
    CONFIG_TARGET_MULTI_PROFILE CONFIG_TARGET_PER_DEVICE_ROOTFS CONFIG_TARGET_ROOTFS_EXT4FS \
    CONFIG_PACKAGE_dnsmasq CONFIG_PACKAGE_dnsmasq-full CONFIG_PACKAGE_ppp CONFIG_PACKAGE_ppp-mod-pppoe \
    CONFIG_PACKAGE_odhcp6c CONFIG_PACKAGE_odhcpd-ipv6only \
    CONFIG_PACKAGE_kmod-usb3 CONFIG_PACKAGE_kmod-usb-ledtrig-usbport \
    CONFIG_PACKAGE_luci-mod-admin-full CONFIG_PACKAGE_luci-mod-status \
    CONFIG_PACKAGE_luci-theme-bootstrap CONFIG_PACKAGE_luci-theme-bootstrap-dark CONFIG_PACKAGE_luci-theme-bootstrap-light \
    CONFIG_PACKAGE_nftables-nojson CONFIG_PACKAGE_luci-theme-airrelay CONFIG_PACKAGE_luci-i18n-airrelay-zh-cn \
    CONFIG_PACKAGE_audit CONFIG_PACKAGE_bluez-utils CONFIG_PACKAGE_libpam CONFIG_PACKAGE_libtirpc \
    CONFIG_PACKAGE_kexec-tools CONFIG_PACKAGE_lldpd CONFIG_PACKAGE_policycoreutils \
    CONFIG_PACKAGE_kmod-tun CONFIG_PACKAGE_kmod-nft-tproxy \
    CONFIG_KERNEL_SWAP CONFIG_KERNEL_MPTCP \
    CONFIG_BUSYBOX_CONFIG_MKSWAP CONFIG_BUSYBOX_CONFIG_SWAPON CONFIG_BUSYBOX_CONFIG_SWAPOFF \
    CONFIG_BUSYBOX_CONFIG_FEATURE_MOUNT_CIFS \
    CONFIG_KERNEL_DEBUG_INFO CONFIG_BUSYBOX_CONFIG_UDHCPD CONFIG_BUSYBOX_CONFIG_DHCPRELAY \
    CONFIG_BUSYBOX_CONFIG_CROND CONFIG_BUSYBOX_CONFIG_CRONTAB CONFIG_BUSYBOX_CONFIG_FEATURE_NTPD_SERVER; do
    if grep -Eq "^$feature=(y|m)$" .config; then die "Unwanted option enabled: $feature"; fi
done
if grep -E '^CONFIG_PACKAGE_(strongswan(-[^=]*)?|relay-ipsec|kmod-(ipsec[^=]*|ipt-ipsec|xfrm-interface|crypto-hw-eip93|crypto-airoha-armv8|crypto-gcm)|xfrm|ip-full|coreutils-timeout)=(y|m)$' .config; then
    die "Retired VPN packages must not be selected"
fi
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
for feature in EXT4_FS MMC USB_SUPPORT PCI XFRM "$usb_phy" "$pcie_phy"; do
    grep -Fxq "# CONFIG_$feature is not set" tmp/relayos-kernel-merged.config || die "Kernel fragment did not disable $feature"
done
require_source
printf 'RelayOS %s single-profile configuration verified\n' "$device"
