#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_source
source "$product_root/scripts/version.sh"
load_build_identity
# Called only after verify.sh passes.
[[ ! -e "$artifact_dir" ]] || die "Artifact directory already exists"
mkdir -p "$artifact_dir"
shopt -s nullglob
manifests=("$target_dir"/relayos-airoha-"$subtarget"*.manifest)
[[ ${#manifests[@]} -eq 1 ]] || die "Expected exactly one profile manifest"
kconfigs=("$ow"/build_dir/target-*/linux-airoha_"$subtarget"/linux-*/.config)
[[ ${#kconfigs[@]} -eq 1 ]] || die "Expected exactly one kernel config"
for image in squashfs-sysupgrade initramfs-recovery; do
    cp "$target_dir/$image_prefix-$image.itb" "$artifact_dir/relayos-$firmware_version-$device-$image.itb"
done
cp "${manifests[0]}" "$artifact_dir/relayos-$device.manifest"
cp "$ow/.config" "$artifact_dir/relayos-$device.config.buildinfo"
cp "${kconfigs[0]}" "$artifact_dir/relayos-$device.kernel.config"
cp "$product_root/feeds.conf" "$artifact_dir/relayos-$device.feeds.buildinfo"
{
    cat "$identity_file"
    printf 'openwrt_source=%s\n' "$source_url"
    printf 'openwrt_commit=%s\n' "$source_sha"
    printf 'device=%s\nboard=%s\n' "$device" "$board"
    printf 'kernel=%s\n' "$(awk '$1 ~ /^LINUX_VERSION-/ {print $1,$3}' "$ow/target/linux/generic/kernel-6.18")"
    printf 'product_patch_sha256=%s\n' "$(sha256sum "$product_root/patches/001-disable-nokia-pon-pcs.patch" | cut -d' ' -f1)"
} > "$artifact_dir/relayos-$device.source.buildinfo"
(cd "$artifact_dir"; sha256sum ./*.itb ./*.manifest ./*.buildinfo ./*.kernel.config > "RELAYOS-$device-SHA256SUMS")
