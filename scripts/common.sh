#!/usr/bin/env bash
# Shared paths and device identity; source only from RelayOS scripts.
set -euo pipefail
product_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
die() { printf 'RelayOS: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 1 ]] || die "Usage: $0 md|mf"
device="$1"
case "$device" in
    md) subtarget=an7581; usb_phy=PHY_AIROHA_USB ;;
    mf) subtarget=an7583; usb_phy=PHY_AIROHA_AN7583_USB ;;
    *) die "Unsupported device: $device" ;;
esac
board="nokia,xg-040g-${device}-ubi"
profile="nokia_xg-040g-${device}-ubi"
ow="$product_root/work/$device/openwrt"
target_dir="$ow/bin/targets/airoha/$subtarget"
artifact_dir="$product_root/artifacts/$device"
image_prefix="relayos-airoha-$subtarget-$profile"
upstream_patches=(
    "$product_root/patches/001-disable-nokia-pon-pcs.patch"
    "$product_root/patches/002-dropbear-track-bound-device.patch"
)
patched_paths=$'package/network/services/dropbear/files/dropbear.init\ntarget/linux/airoha/dts/an758x-nokia_xg-040g-common.dtsi'
lock_value() {
    local key="$1" value
    value="$(sed -n "s/^$key=//p" "$product_root/upstream.lock")"
    [[ -n "$value" && "$value" != *$'\n'* ]] || die "Invalid lock entry $key"
    printf '%s\n' "$value"
}
source_url="$(lock_value source)"
[[ "$source_url" == https://github.com/openwrt/openwrt.git ]] || die "Only the official OpenWrt source is supported"
source_sha="$(lock_value commit)"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || die "upstream.lock must pin a full Git SHA"
require_official_origin() {
    [[ "$(git -C "$ow" remote get-url origin)" == "$source_url" ]] || die "OpenWrt origin differs from the official source lock"
}
require_source() {
    [[ -d "$ow/.git" ]] || die "Run scripts/prepare.sh $device first"
    require_official_origin
    [[ "$(git -C "$ow" rev-parse HEAD)" == "$source_sha" ]] || die "OpenWrt checkout differs from lock"
    [[ "$(git -C "$ow" diff --name-only HEAD)" == "$patched_paths" ]] || die "Unexpected tracked upstream changes"
    git -C "$ow" apply --reverse --check "${upstream_patches[@]}"
}
