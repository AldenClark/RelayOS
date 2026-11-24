#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_source
"$product_root/scripts/check-kernel-config.sh" "$device"
"$product_root/scripts/check-image.sh" "$device"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Check the DTB actually embedded in each FIT, not merely its DTS source.
# FIT subimages are indexed in /images order by dumpimage.
check_fit() {
    local image="$1" config node i index=-1 dtb
    [[ -s "$image" ]] || die "Missing FIT image: $image"
    config="$(fdtget -t s "$image" /configurations default)"
    [[ "$config" == config-1 ]] || die "Unexpected FIT default configuration: $config"
    node="$(fdtget -t s "$image" "/configurations/$config" fdt)"
    [[ "$node" == fdt-1 ]] || die "Unexpected FIT FDT reference: $node"
    mapfile -t nodes < <(fdtget -l "$image" /images)
    for i in "${!nodes[@]}"; do
        [[ "${nodes[i]}" != "$node" ]] || index="$i"
    done
    [[ "$index" -ge 0 ]] || die "FIT is missing its device tree"
    dtb="$tmp/selected.dtb"
    dumpimage -T flat_dt -p "$index" -o "$dtb" "$image" >/dev/null
    [[ "$(fdtget -t s "$dtb" / compatible)" == "$board "* ]] || die "Incorrect board compatible in FIT"
    [[ "$(fdtget -t s "$dtb" /soc/pcs@1fa08000 status)" == disabled ]] || die "PON PCS not disabled"
    [[ "$(fdtget -t s "$dtb" /soc/pcs@1fa09000 status)" == okay ]] || die "Ethernet PCS not enabled"
    # Product supports the copper-only Nokia boards, not PCIe expansion.
    local soc_nodes pci_node
    soc_nodes="$(fdtget -l "$dtb" /soc)" || die "Cannot inspect SoC device tree"
    for pci_node in $soc_nodes; do
        case "$pci_node" in
            pcie@*) [[ "$(fdtget -t s "$dtb" "/soc/$pci_node" status)" == disabled ]] || die "PCIe node unexpectedly enabled: $pci_node" ;;
        esac
    done
    [[ "$(fdtget -t s "$dtb" /soc/crypto@1fb70000 compatible)" == *inside-secure,safexcel-eip93ies* ]] || die "EIP93 device tree node missing"
    [[ "$(fdtget -t s "$dtb" /soc/crypto@1fb70000 status 2>/dev/null || true)" != disabled ]] || die "EIP93 device tree node disabled"
    printf 'Verified FIT board, PCS, PCIe and EIP93 policy: %s\n' "$(basename "$image")"
}
sysupgrade="$target_dir/$image_prefix-squashfs-sysupgrade.itb"
recovery="$target_dir/$image_prefix-initramfs-recovery.itb"
check_fit "$sysupgrade"
check_fit "$recovery"
"$ow/staging_dir/host/bin/fwtool" -q -i "$tmp/metadata.json" "$sysupgrade"
python3 - "$tmp/metadata.json" "$board" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    meta = json.load(f)
assert meta.get("version", {}).get("dist") == "RelayOS", "Incorrect firmware branding"
assert sys.argv[2] in meta.get("supported_devices", []), "Missing board ID"
assert meta.get("compat_version") == "1.0", "UBI upgrade compatibility changed"
PY
printf 'RelayOS %s image and sysupgrade metadata verified\n' "$device"
