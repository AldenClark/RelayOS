#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_source
export OPENWRT_DIR="$ow"
console="$product_root/packages/luci-theme-relay"
grep -q 'call BuildPackage' "$console/Makefile"
python3 -m json.tool "$console/root/usr/share/luci/menu.d/relay-console.json" >/dev/null
python3 -m json.tool "$console/root/usr/share/rpcd/acl.d/luci-theme-relay.json" >/dev/null
for script in "$console/root/etc/uci-defaults/95_luci-theme-relay" \
              "$console/root/etc/init.d/relay-traffic" \
              "$console/root/usr/libexec/relay-traffic" \
              "$console/root/usr/libexec/relay-wg-restart" \
              "$product_root/overlay/etc/uci-defaults/99-airrelay-network"; do
    sh -n "$script"
done
for source_file in "$console"/htdocs/luci-static/resources/view/relay/*.js \
                   "$console"/htdocs/luci-static/resources/relay/*.js; do
    node --check "$source_file"
done
for test_file in "$product_root"/tests/test-console-*.cjs; do node "$test_file"; done
msgfmt --check --output-file=/dev/null "$console/po/zh_Hans/relay.po"
if grep -q '/luci-static/bootstrap' "$console/htdocs/luci-static/relay/cascade.css"; then
    die "Console must not import an unbundled theme"
fi
printf 'RelayOS console source and regression tests passed\n'
