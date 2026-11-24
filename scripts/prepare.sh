#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# OpenWrt build and feeds do not support source paths containing whitespace.
[[ "$product_root" != *[[:space:]]* && "$product_root" != *"'"* ]] || die "Use a checkout path without whitespace or quotes"
[[ ! -e "$ow" ]] || die "Build checkout already exists: $ow; use a fresh work directory"
primary="$(lock_value source)"
fallback="$(lock_value fallback)"
[[ "$primary" == https://github.com/AldenClark/openwrt.git ]] || die "Unexpected source repository"
[[ "$fallback" == https://github.com/openwrt/openwrt.git ]] || die "Unexpected fallback repository"
mkdir -p "$ow"
git -C "$ow" init -q
# The official source is an exact-SHA fallback while the old product fork is retained.
# Never substitute a moving branch or silently change the locked revision.
if ! git -C "$ow" fetch --depth=1 --no-tags "$primary" "$source_sha"; then
    git -C "$ow" fetch --depth=1 --no-tags "$fallback" "$source_sha"
fi
git -C "$ow" checkout --detach "$source_sha"
[[ "$(git -C "$ow" rev-parse HEAD)" == "$source_sha" ]] || die "Wrong upstream revision"
git -C "$ow" apply --check "$product_root/patches/001-disable-nokia-pon-pcs.patch"
git -C "$ow" apply "$product_root/patches/001-disable-nokia-pon-pcs.patch"
require_source
git -C "$ow" diff --check

# Register the product package as an ordinary OpenWrt local feed.
cp "$product_root/feeds.conf" "$ow/feeds.conf"
printf '\nsrc-link relayos %s/packages\n' "$product_root" >> "$ow/feeds.conf"
cd "$ow"
./scripts/feeds update packages luci relayos
for feed in packages luci; do
    expected="$(awk -v f="$feed" '$2 == f { split($3,a,/\^/); print a[2] }' feeds.conf)"
    [[ "$expected" =~ ^[0-9a-f]{40}$ && "$(git -C "feeds/$feed" rev-parse HEAD)" == "$expected" ]] || die "Feed revision mismatch: $feed"
done
./scripts/feeds install -p luci luci-mod-admin-full luci-proto-wireguard
./scripts/feeds install -p relayos luci-theme-airrelay
[[ -e package/feeds/relayos/luci-theme-airrelay/Makefile ]] || die "RelayOS feed package not installed"
require_source
printf 'Prepared %s at %s (%s)\n' "$device" "$ow" "$source_sha"
