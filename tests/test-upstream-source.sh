#!/usr/bin/env bash
# Offline regression for the real preparation script, with a local Git fixture.
# No network access or OpenWrt toolchain is needed.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_AUTHOR_NAME=RelayOS GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export TEST_REAL_GIT="$(command -v git)"
export TEST_FIXTURE="$tmp/upstream" TEST_LOG="$tmp/fetch.log"
export TEST_FAIL_FETCH=0
mkdir -p "$TEST_FIXTURE/scripts" "$tmp/bin"
dts=target/linux/airoha/dts/an758x-nokia_xg-040g-common.dtsi
mkdir -p "$TEST_FIXTURE/$(dirname "$dts")"
# Use the old-side context of the actual product patch to create its preimage.
awk '/^@@ / { h=1; next } h && /^[ -]/ { print substr($0,2) }' \
    "$root/patches/001-disable-nokia-pon-pcs.patch" > "$TEST_FIXTURE/$dts"
cat > "$TEST_FIXTURE/scripts/feeds" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
    update)
        mkdir -p feeds
        for feed in packages luci; do
            "$TEST_REAL_GIT" clone -q --no-hardlinks "$TEST_FIXTURE" "feeds/$feed"
        done
        ;;
    install)
        mkdir -p package/feeds/relayos/luci-theme-relay
        touch package/feeds/relayos/luci-theme-relay/Makefile
        ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$TEST_FIXTURE/scripts/feeds"
"$TEST_REAL_GIT" -C "$TEST_FIXTURE" init -q
"$TEST_REAL_GIT" -C "$TEST_FIXTURE" add .
"$TEST_REAL_GIT" -C "$TEST_FIXTURE" commit -qm fixture
export TEST_SHA="$("$TEST_REAL_GIT" -C "$TEST_FIXTURE" rev-parse HEAD)"

# Intercept only the network fetch and run a real Git fetch of the fixture.
# Every other Git operation, including checkout and patch checks, is real.
cat > "$tmp/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ge 3 && "$1" == -C && "$3" == fetch ]]; then
    printf '%s\n' "$*" >> "$TEST_LOG"
    [[ $# -eq 7 && "$4" == --depth=1 && "$5" == --no-tags &&
       "$6" == origin && "$7" == "$TEST_SHA" ]]
    [[ "$("$TEST_REAL_GIT" -C "$2" remote get-url origin)" == https://github.com/openwrt/openwrt.git ]]
    [[ "$TEST_FAIL_FETCH" == 0 ]] || exit 69
    exec "$TEST_REAL_GIT" -C "$2" fetch --depth=1 --no-tags "file://$TEST_FIXTURE" "$TEST_SHA"
fi
exec "$TEST_REAL_GIT" "$@"
EOF
chmod +x "$tmp/bin/git"
export PATH="$tmp/bin:$PATH"

make_product() {
    local path="$1" url="$2" sha="$3"
    mkdir -p "$path/scripts" "$path/patches" "$path/packages"
    cp "$root/scripts/common.sh" "$root/scripts/prepare.sh" "$path/scripts/"
    cp "$root/patches/001-disable-nokia-pon-pcs.patch" "$path/patches/"
    printf 'source=%s\ncommit=%s\n' "$url" "$sha" > "$path/upstream.lock"
    printf 'src-git packages https://github.com/openwrt/packages.git^%s\nsrc-git luci https://github.com/openwrt/luci.git^%s\n' \
        "$TEST_SHA" "$TEST_SHA" > "$path/feeds.conf"
}
official=https://github.com/openwrt/openwrt.git
: > "$TEST_LOG"
make_product "$tmp/good" "$official" "$TEST_SHA"
for model in md mf; do
    bash "$tmp/good/scripts/prepare.sh" "$model"
    checkout="$tmp/good/work/$model/openwrt"
    [[ "$(git -C "$checkout" rev-parse HEAD)" == "$TEST_SHA" ]]
    [[ "$(git -C "$checkout" remote get-url origin)" == "$official" ]]
    if git -C "$checkout" symbolic-ref -q HEAD; then
        echo "Expected detached HEAD for $model" >&2; exit 1
    fi
    grep -Fq 'status = "disabled";' "$checkout/$dts"
done
[[ "$(wc -l < "$TEST_LOG")" -eq 2 ]]

# A fork URL and a non-SHA lock must be rejected before the first fetch.
make_product "$tmp/fork" https://github.com/example/openwrt.git "$TEST_SHA"
if bash "$tmp/fork/scripts/prepare.sh" md; then
    echo 'Unexpected acceptance of non-official source' >&2; exit 1
fi
make_product "$tmp/floating" "$official" main
if bash "$tmp/floating/scripts/prepare.sh" mf; then
    echo 'Unexpected acceptance of floating ref' >&2; exit 1
fi
[[ "$(wc -l < "$TEST_LOG")" -eq 2 ]]

# A failed upstream fetch must stop, not fall back or fetch again.
make_product "$tmp/fail" "$official" "$TEST_SHA"
export TEST_FAIL_FETCH=1
if bash "$tmp/fail/scripts/prepare.sh" md; then
    echo 'Unexpected success after fetch failure' >&2; exit 1
fi
[[ "$(wc -l < "$TEST_LOG")" -eq 3 ]]
export TEST_FAIL_FETCH=0

# Subsequent build stages must reject an existing checkout whose origin changes.
git -C "$tmp/good/work/md/openwrt" remote set-url origin https://github.com/example/openwrt.git
if bash -c 'source "$1" "$2"; require_source' _ "$tmp/good/scripts/common.sh" md; then
    echo 'Unexpected acceptance of changed origin' >&2; exit 1
fi
echo 'Official-only source policy: both devices, detached exact SHA, invalid URL/ref, fetch failure and origin drift OK'
