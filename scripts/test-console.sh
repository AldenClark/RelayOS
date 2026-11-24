#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_source
export OPENWRT_DIR="$ow"
console="$product_root/packages/luci-theme-airrelay"
grep -q 'call BuildPackage' "$console/Makefile"
python3 -m json.tool "$console/root/usr/share/luci/menu.d/airrelay-console.json" >/dev/null
python3 -m json.tool "$console/root/usr/share/rpcd/acl.d/luci-theme-airrelay.json" >/dev/null
for script in "$console/root/etc/uci-defaults/95_luci-theme-airrelay" \
              "$console/root/etc/init.d/airrelay-traffic" \
              "$console/root/usr/libexec/airrelay-traffic" \
              "$console/root/usr/libexec/airrelay-wg-restart" \
              "$product_root/overlay/etc/uci-defaults/99-airrelay-network"; do
    sh -n "$script"
done
for source_file in "$console"/htdocs/luci-static/resources/view/airrelay/*.js \
                   "$console"/htdocs/luci-static/resources/airrelay/*.js; do
    node --check "$source_file"
done
for test_file in "$product_root"/tests/test-console-*.cjs; do node "$test_file"; done
msgfmt --check --output-file=/dev/null "$console/po/zh_Hans/airrelay.po"
if grep -q '/luci-static/bootstrap' "$console/htdocs/luci-static/airrelay/cascade.css"; then
    die "Console must not import an unbundled theme"
fi
printf 'RelayOS console source and regression tests passed\n'
