#!/usr/bin/env bash
set -euo pipefail
[[ $# -ge 1 && $# -le 2 ]] || { echo "Usage: $0 md|mf [all|download|compile|verify]" >&2; exit 2; }
stage="${2:-all}"
set -- "$1"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_source
[[ -s "$ow/.config" ]] || die "Run scripts/configure.sh $device first"
jobs="${RELAYOS_JOBS:-2}"
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die "RELAYOS_JOBS must be a positive integer"
logs="$product_root/work/$device/build-logs"
mkdir -p "$logs"
monitor_pid=
stop_monitor() {
    if [[ -n "$monitor_pid" ]]; then
        kill "$monitor_pid" 2>/dev/null || :
        wait "$monitor_pid" 2>/dev/null || :
        monitor_pid=
    fi
}
trap stop_monitor EXIT
run_logged() {
    local name="$1" log rc
    shift
    log="$logs/$name.log"
    : > "$log"
    printf 'Starting %s (%s)\n' "$name" "$device"
    df -h "$ow"
    (
        sleeper=
        trap '[[ -z "$sleeper" ]] || kill "$sleeper" 2>/dev/null || :; exit 0' TERM INT
        while :; do
            sleep 120 </dev/null >/dev/null 2>&1 &
            sleeper=$!
            wait "$sleeper" || exit 0
            sleeper=
            printf '\n[%s] %s progress / runner resources:\n' "$(date -u +%FT%TZ)" "$name"
            df -h "$ow" || :
            free -m || :
            tail -n 8 "$log" || :
        done
    ) &
    monitor_pid=$!
    # Preserve the actual compiler/linker output while avoiding a massive
    # Actions console log. The periodic heartbeat keeps progress visible.
    if "$@" >"$log" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    stop_monitor
    printf '%s finished with exit code %s\n' "$name" "$rc"
    tail -n 100 "$log" || :
    df -h "$ow" || :
    return "$rc"
}
verify_and_collect() {
    "$product_root/scripts/verify.sh" "$device" || return
    "$product_root/scripts/collect.sh" "$device"
}
case "$stage" in
    download) run_logged download make -C "$ow" download -j"$jobs" ;;
    compile) run_logged compile make -C "$ow" -j"$jobs" V=s ;;
    verify) run_logged verify verify_and_collect ;;
    all)
        run_logged download make -C "$ow" download -j"$jobs"
        run_logged compile make -C "$ow" -j"$jobs" V=s
        run_logged verify verify_and_collect ;;
    *) die "Unknown build stage: $stage" ;;
esac
