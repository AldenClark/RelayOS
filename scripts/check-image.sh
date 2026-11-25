#!/usr/bin/env bash
# Verify the firmware's package manifest before making images available.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_source
manifest="$target_dir/relayos-airoha-$subtarget.manifest"
if [[ ! -f "$manifest" ]]; then
    shopt -s nullglob
    manifests=("$target_dir"/relayos-airoha-"$subtarget"*.manifest)
    [[ ${#manifests[@]} -eq 1 ]] || {
        echo "Expected exactly one RelayOS manifest under $target_dir" >&2
        exit 1
    }
    manifest="${manifests[0]}"
fi

has_package() {
    awk -v name="$1" '$1 == name { found=1 } END { exit !found }' "$manifest"
}

for name in relay-ipsec \
            strongswan \
            strongswan-charon \
            strongswan-swanctl \
            strongswan-mod-kernel-netlink \
            strongswan-mod-socket-default \
            strongswan-mod-vici \
            strongswan-mod-aes \
            strongswan-mod-sha1 \
            strongswan-mod-sha2 \
            strongswan-mod-hmac \
            strongswan-mod-kdf \
            strongswan-mod-random \
            strongswan-mod-drbg \
            strongswan-mod-curve25519 \
            strongswan-mod-gcm \
            strongswan-mod-gmp \
            kmod-ipsec \
            kmod-ipsec4 \
            kmod-xfrm-interface \
            kmod-crypto-hw-eip93 \
            kmod-crypto-airoha-armv8 \
            kmod-crypto-gcm \
            xfrm \
            ip-full \
            ucode ucode-mod-fs ucode-mod-uci coreutils-timeout \
            kmod-wireguard wireguard-tools firewall4 nftables-json kmod-nft-offload fitblk uboot-envtools luci-mod-admin-full \
            luci-proto-wireguard luci-lib-uqr resolveip \
            luci-theme-relay luci-i18n-relay-zh-cn \
            uhttpd uhttpd-mod-ubus px5g-mbedtls dropbear; do
    if ! has_package "$name"; then
        echo "Required package missing: $name" >&2
        exit 1
    fi
done

for name in nftables-nojson luci-theme-airrelay luci-i18n-airrelay-zh-cn \
            audit bluez-utils libpam libtirpc kexec-tools lldpd policycoreutils \
            luci-theme-bootstrap luci-theme-bootstrap-dark luci-theme-bootstrap-light \
            dnsmasq dnsmasq-full odhcpd-ipv6only ppp ppp-mod-pppoe \
            odhcp6c kmod-tun kmod-nft-tproxy strongswan-full \
            strongswan-default \
            strongswan-minimal \
            strongswan-isakmp \
            strongswan-ipsec \
            strongswan-mod-stroke \
            strongswan-mod-updown \
            strongswan-mod-kernel-libipsec \
            kmod-ipt-ipsec kmod-usb3 kmod-usb-ledtrig-usbport; do
    if has_package "$name"; then
        echo "Unexpected package included: $name" >&2
        exit 1
    fi
done

echo "RelayOS $subtarget package manifest verified."
