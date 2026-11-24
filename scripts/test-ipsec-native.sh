#!/usr/bin/env bash
# Host-only checks. Never builds firmware or executes commands on a real router.
set -euo pipefail
product_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
: "${UCODE:?Set UCODE to the product-pinned host ucode with fs and uci modules}"
: "${UCI:?Set UCI to the product-pinned host UCI CLI}"
[[ "$UCODE" = /* && -x "$UCODE" && "$UCI" = /* && -x "$UCI" ]] || {
    echo 'UCODE and UCI must name executable absolute paths' >&2
    exit 2
}
export UCODE UCI
"$UCODE" "$product_root/tests/test-ipsec-model.uc"
node "$product_root/tests/test-ipsec-runtime.cjs"
