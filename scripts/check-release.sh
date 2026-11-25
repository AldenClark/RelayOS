#!/usr/bin/env bash
# Verify that the release input is confined to the expected device and build.
set -euo pipefail
[[ $# -eq 5 ]] || { echo "Usage: $0 DIRECTORY DEVICE VERSION COMMIT BUILD_ID" >&2; exit 2; }
cd "$1"
device="$2"
version="$3"
commit="$4"
build_id="$5"
[[ "$device" == md || "$device" == mf ]]
[[ "$commit" =~ ^[0-9a-f]{40}$ && "$version" =~ ^[0-9]{8}-${commit:0:12}$ ]]
[[ "$build_id" =~ ^[0-9]+\.[0-9]+$ ]]

prefix="relayos-$version-$device"
metadata="relayos-$device.source.buildinfo"
checksums="RELAYOS-$device-SHA256SUMS"
assets=("$prefix-squashfs-sysupgrade.itb" "$prefix-initramfs-recovery.itb")
for suffix in manifest config.buildinfo kernel.config feeds.buildinfo source.buildinfo; do
    assets+=("relayos-$device.$suffix")
done
for asset in "${assets[@]}" "$checksums"; do
    [[ -s "$asset" && ! -L "$asset" ]]
done
# Verify the manifest lists each expected file exactly once before checking its contents.
diff -u <(printf './%s\n' "${assets[@]}" | LC_ALL=C sort) \
    <(awk '{print $2}' "$checksums" | LC_ALL=C sort)
[[ "$(find . -mindepth 1 -maxdepth 1 | wc -l)" -eq "$((${#assets[@]} + 1))" ]]
grep -Fx "firmware_version=$version" "$metadata"
grep -Fx "product_commit=$commit" "$metadata"
grep -Fx "build_id=$build_id" "$metadata"
grep -Fx "source_dirty=0" "$metadata"
grep -Eq '^build_time=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' "$metadata"
grep -Fx "openwrt_source=https://github.com/openwrt/openwrt.git" "$metadata"
grep -Eq '^openwrt_commit=[0-9a-f]{40}$' "$metadata"
grep -Fx "device=$device" "$metadata"
grep -Fx "board=nokia,xg-040g-$device-ubi" "$metadata"
grep -Fx "CONFIG_VERSION_NUMBER=\"$version\"" "relayos-$device.config.buildinfo"
sha256sum -c "$checksums"
