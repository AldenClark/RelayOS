#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_source
[[ -s "$ow/.config" ]] || die "Run scripts/configure.sh $device first"
jobs="${RELAYOS_JOBS:-2}"
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die "RELAYOS_JOBS must be a positive integer"
make -C "$ow" download -j"$jobs"
make -C "$ow" -j"$jobs"
"$product_root/scripts/verify.sh" "$device"
"$product_root/scripts/collect.sh" "$device"
