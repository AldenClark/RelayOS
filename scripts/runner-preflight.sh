#!/usr/bin/env bash
# Run only on ephemeral GitHub-hosted Linux runners, never on a developer
# machine or a self-hosted runner. Remove only known unused SDK directories.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${RUNNER_OS:-}" == Linux ]] || {
    echo 'RelayOS: skipping hosted-runner SDK cleanup on non-hosted runner'
    exit 0
}
root="${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
target_kib=$((30 * 1024 * 1024))
minimum_kib=$((25 * 1024 * 1024))
available() { df -Pk "$root" | awk 'END { print $4 }'; }
echo 'Disk and memory before build-host cleanup:'
df -h "$root"
free -m
for sdk in /usr/local/lib/android /usr/share/dotnet /opt/ghc \
           /usr/local/share/powershell /opt/hostedtoolcache/CodeQL; do
    (( $(available) < target_kib )) || break
    [[ -d "$sdk" && ! -L "$sdk" ]] || continue
    printf 'Removing unused hosted-runner SDK: %s\n' "$sdk"
    sudo rm -rf -- "$sdk"
    df -h "$root"
done
echo 'Disk space after cleanup:'
df -h "$root"
if (( $(available) < minimum_kib )); then
    echo '::error::Less than 25 GiB free before OpenWrt build. Use a runner with more disk space.'
    exit 1
fi
