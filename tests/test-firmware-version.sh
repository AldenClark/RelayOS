#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
product_root="$tmp/product"
device=md
ow="$product_root/work/$device/openwrt"
mkdir -p "$ow"
git -C "$product_root" init -q
printf '/work/\n' > "$product_root/.gitignore"
git -C "$product_root" add .gitignore
GIT_AUTHOR_DATE='2026-11-25T00:10:00+08:00' GIT_COMMITTER_DATE='2026-11-25T00:10:00+08:00' \
    git -C "$product_root" -c user.name=Test -c user.email=test@example.invalid -c commit.gpgSign=false commit -qm fixture
die() { echo "$*" >&2; exit 1; }
source "$repo/scripts/version.sh"
unset GITHUB_ACTIONS GITHUB_SHA GITHUB_RUN_ID GITHUB_RUN_ATTEMPT
write_build_identity
[[ "$firmware_version" == "20261124-${product_commit:0:12}" ]]
[[ "$build_id" =~ ^local\.[0-9]+$ ]]
printf 'CONFIG_VERSION_NUMBER="%s"\n' "$firmware_version" > "$ow/.config"
load_build_identity

touch "$product_root/dirty"
if (load_build_identity); then die "Clean build accepted changed sources"; fi
write_build_identity
[[ "$firmware_version" == *-dirty && "$source_dirty" == 1 ]]
export GITHUB_ACTIONS=true GITHUB_SHA="$product_commit" GITHUB_RUN_ID=123 GITHUB_RUN_ATTEMPT=2
if (write_build_identity); then die "CI accepted dirty sources"; fi
mv "$product_root/dirty" "$tmp/dirty"
export GITHUB_SHA=0000000000000000000000000000000000000000
if (write_build_identity); then die "CI accepted a mismatched commit"; fi
export GITHUB_SHA="$product_commit"
write_build_identity
[[ "$build_id" == 123.2 ]]
printf 'CONFIG_VERSION_NUMBER="%s"\n' "$firmware_version" > "$ow/.config"
load_build_identity

assets="$tmp/assets"
mkdir "$assets"
for image in squashfs-sysupgrade initramfs-recovery; do
    echo payload > "$assets/relayos-$firmware_version-md-$image.itb"
done
for suffix in manifest kernel.config feeds.buildinfo; do
    echo fixture > "$assets/relayos-md.$suffix"
done
cp "$ow/.config" "$assets/relayos-md.config.buildinfo"
{
    cat "$identity_file"
    echo 'openwrt_source=https://github.com/openwrt/openwrt.git'
    printf 'openwrt_commit=%s\n' "$product_commit"
    echo 'device=md'
    echo 'board=nokia,xg-040g-md-ubi'
} > "$assets/relayos-md.source.buildinfo"
(cd "$assets"; sha256sum ./*.itb ./*buildinfo ./*.manifest ./*.kernel.config > RELAYOS-md-SHA256SUMS)
"$repo/scripts/check-release.sh" "$assets" md "$firmware_version" "$product_commit" "$build_id" >/dev/null
if "$repo/scripts/check-release.sh" "$assets" mf "$firmware_version" "$product_commit" "$build_id"; then
    die "Release accepted images from the other board"
fi
echo tampered >> "$assets/relayos-$firmware_version-md-initramfs-recovery.itb"
if "$repo/scripts/check-release.sh" "$assets" md "$firmware_version" "$product_commit" "$build_id" >/dev/null; then
    die "Release accepted changed recovery bytes"
fi
echo 'Firmware identity and release validation passed'
