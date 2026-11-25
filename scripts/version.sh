#!/usr/bin/env bash
# Sourced after common.sh by firmware build stages.
identity_file="$product_root/work/$device/firmware.buildinfo"

read_field() {
    local value
    value="$(sed -n "s/^$2=//p" "$1")"
    [[ -n "$value" && "$value" != *$'\n'* ]] || die "Invalid build identity field: $2"
    printf '%s\n' "$value"
}

source_identity() {
    product_commit="$(git -C "$product_root" rev-parse HEAD)"
    [[ "$product_commit" =~ ^[0-9a-f]{40}$ ]] || die "Invalid RelayOS commit"
    local commit_date worktree
    commit_date="$(TZ=UTC git -C "$product_root" show -s --format=%cd --date=format-local:%Y%m%d "$product_commit")"
    [[ "$commit_date" =~ ^[0-9]{8}$ ]] || die "Invalid RelayOS commit date"
    firmware_version="$commit_date-${product_commit:0:12}"
    worktree="$(git -C "$product_root" status --porcelain --untracked-files=normal)"
    source_dirty=0
    if [[ -n "$worktree" ]]; then
        source_dirty=1
        firmware_version="$firmware_version-dirty"
    fi
    if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
        [[ "$source_dirty" == 0 && "$product_commit" == "${GITHUB_SHA:-}" ]] ||
            die "CI requires a clean checkout of GITHUB_SHA"
        [[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]] ||
            die "Invalid GitHub build ID"
    fi
}

write_build_identity() {
    source_identity
    build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
        build_id="$GITHUB_RUN_ID.$GITHUB_RUN_ATTEMPT"
    else
        build_id="local.${build_time//[^0-9]/}"
    fi
    printf 'firmware_version=%s\nproduct_commit=%s\nsource_dirty=%s\nbuild_id=%s\nbuild_time=%s\n' \
        "$firmware_version" "$product_commit" "$source_dirty" "$build_id" "$build_time" > "$identity_file"
}

load_build_identity() {
    [[ -s "$identity_file" ]] || die "Run scripts/configure.sh $device first"
    source_identity
    [[ "$(read_field "$identity_file" product_commit)" == "$product_commit" &&
       "$(read_field "$identity_file" firmware_version)" == "$firmware_version" &&
       "$(read_field "$identity_file" source_dirty)" == "$source_dirty" ]] ||
        die "RelayOS source changed since configuration"
    build_id="$(read_field "$identity_file" build_id)"
    build_time="$(read_field "$identity_file" build_time)"
    if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
        [[ "$build_id" == "$GITHUB_RUN_ID.$GITHUB_RUN_ATTEMPT" ]] || die "Build ID does not match this run"
    fi
    grep -Fxq "CONFIG_VERSION_NUMBER=\"$firmware_version\"" "$ow/.config" ||
        die "OpenWrt configuration does not match the firmware build identity"
}
