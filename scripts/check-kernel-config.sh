#!/usr/bin/env bash
# Fail release builds if removed drivers silently reappear in the kernel.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_source
case "$device" in md) pcie_phy=PHY_AIROHA_PCIE ;; mf) pcie_phy=PHY_AIROHA_AN7583_PCIE ;; esac
shopt -s nullglob
configs=("$ow"/build_dir/target-*/linux-airoha_"$subtarget"/linux-*/.config)
[[ ${#configs[@]} -eq 1 ]] || {
    echo "Expected one final kernel .config for airoha/$subtarget, got ${#configs[@]}" >&2
    exit 1
}
kernel_config="${configs[0]}"

for feature in EXT4_FS MMC USB_SUPPORT USB DEBUG_INFO PCI PCIE_MEDIATEK PCIE_MEDIATEK_GEN3 SWAP MPTCP "$usb_phy" "$pcie_phy"; do
    # Kconfig omits symbols that are unavailable on this target. An absent
    # symbol is disabled, just like "# CONFIG_FOO is not set". Only explicit
    # y/m selections prove an unwanted feature was built.
    if grep -Eq "^CONFIG_${feature}=(y|m)$" "$kernel_config"; then
        grep -E "^CONFIG_${feature}=" "$kernel_config" >&2
        echo "Kernel unexpectedly enables CONFIG_${feature}" >&2
        exit 1
    fi
done
for feature in MTD_UBI UBIFS_FS NET_AIROHA NET_AIROHA_NPU NET_DSA PCS_AIROHA HW_RANDOM_AIROHA; do
    grep -qx "CONFIG_${feature}=y" "$kernel_config" || {
        echo "Kernel is missing critical driver: CONFIG_${feature}" >&2
        exit 1
    }
done
for feature in WIREGUARD XFRM_USER INET_ESP XFRM_INTERFACE CRYPTO_DEV_EIP93; do
    grep -Eq "^CONFIG_${feature}=(y|m)$" "$kernel_config" || die "Kernel missing required data-plane feature: $feature"
done

echo "RelayOS $subtarget optimized kernel config verified."
