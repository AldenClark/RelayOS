#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# OpenWrt build and feeds do not support source paths containing whitespace.
[[ "$product_root" != *[[:space:]]* && "$product_root" != *"'"* ]] || die "Use a checkout path without whitespace or quotes"
[[ ! -e "$ow" ]] || die "Build checkout already exists: $ow; use a fresh work directory"
mkdir -p "$ow"
git -C "$ow" init -q
git -C "$ow" remote add origin "$source_url"
require_official_origin
# Fetch only the reviewed commit from the official repository. Never fall
# back to a fork, a moving branch or another revision if fetching fails.
git -C "$ow" fetch --depth=1 --no-tags origin "$source_sha"
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
# Register optional dependency metadata referenced by upstream base package Makefiles.
# Installing a feed definition is not selecting a package for the firmware.
./scripts/feeds install -p packages libev bluez-utils libpam libtirpc liblzma libzstd libnetsnmp-nossl
./scripts/feeds install -p luci luci-mod-admin-full luci-proto-wireguard
./scripts/feeds install -p relayos luci-theme-relay kmod-crypto-airoha-armv8 relay-ipsec
[[ -e package/feeds/relayos/crypto-airoha-armv8/Makefile ]] || die "Airoha ARMv8 crypto package not installed"
[[ -e package/feeds/relayos/relay-ipsec/Makefile ]] || die "RelayOS IPsec package not installed"
[[ -e package/feeds/relayos/luci-theme-relay/Makefile ]] || die "RelayOS feed package not installed"
require_source
printf 'Prepared %s at %s (%s)\n' "$device" "$ow" "$source_sha"
