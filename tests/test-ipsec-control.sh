#!/usr/bin/env bash
# Exercise the production shell helper in a disposable filesystem fixture.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export MOCK_STATE="$tmp/state" MOCK_START_FAIL=0 MOCK_STOP_FAIL=0
export MOCK_AGENT='{"airroute-agent":{"enabled":false,"running":false}}'
mkdir -p "$tmp/bin" "$tmp/init" "$tmp/etc/config" "$MOCK_STATE"
touch "$tmp/etc/config/ipsec"
printf '0\n' > "$MOCK_STATE/enabled"
printf '0\n' > "$MOCK_STATE/routes"
touch "$MOCK_STATE/pending"
printf 'driver : authenc(hmac(sha256-eip93),cbc(aes-eip93))\n' > "$tmp/crypto"
python3 - "$root/packages/relay-ipsec/files" "$tmp" <<'PY'
import pathlib, sys
src, target = map(pathlib.Path, sys.argv[1:])
mapping = {
    "/etc/init.d/swanctl": str(target/"init/swanctl"),
    "/usr/sbin/swanctl": str(target/"bin/swanctl"),
    "/etc/init.d/relay-ipsec-prepare": str(target/"init/relay-ipsec-prepare"),
    "/etc/init.d/airroute-agent": str(target/"init/airroute-agent"),
    "/etc/config/ipsec": str(target/"etc/config/ipsec"),
    "/etc/swanctl": str(target/"etc/swanctl"),
    "/var/ipsec": str(target/"var/ipsec"),
    "/var/swanctl": str(target/"var/swanctl"),
    "/proc/crypto": str(target/"crypto"),
    "/var/lock": str(target/"var/lock"),
    "PATH=/usr/sbin:/usr/bin:/sbin:/bin": "PATH="+str(target/"bin")+":/usr/bin:/bin",
}
def copy(name, out, guard=False):
    s=(src/name).read_text()
    for old,new in mapping.items():
        s=s.replace(old,new)
    if guard:
        s=s.replace("#!/bin/sh /etc/rc.common", "#!/bin/sh", 1)
        s+='\ncase "$1" in start) start ;; boot) boot ;; *) exit 2 ;; esac\n'
    out.write_text(s)
    out.chmod(0o755)
copy("relay-ipsec", target/"control")
copy("relay-ipsec-prepare", target/"init/relay-ipsec-prepare", True)
PY
cat > "$tmp/bin/uci" <<'EOF'
#!/bin/sh
[ "$1" != -q ] || shift
case "$1 $2" in
    "get ipsec.globals") echo globals ;;
    "get ipsec.globals.enabled") cat "$MOCK_STATE/enabled" ;;
    "get ipsec.globals.rtinstall_enabled") cat "$MOCK_STATE/routes" ;;
    "get ipsec.@ipsec[0]") exit 1 ;;
    "changes ipsec") cat "$MOCK_STATE/pending" ;;
    "set ipsec.globals.enabled=0"|"set ipsec.globals.enabled=1")
        printf '%s\n' "${2##*=}" > "$MOCK_STATE/enabled" ;;
    "commit ipsec"|"revert ipsec.globals.enabled") : ;;
    *) exit 2 ;;
esac
EOF
cat > "$tmp/bin/swanctl" <<'EOF'
#!/bin/sh
[ -f "$MOCK_STATE/running" ] || exit 1
case "$1" in
    --stats) echo ready ;;
    --list-conns) [ ! -f "$MOCK_STATE/loaded" ] || echo 'test: IKEv2' ;;
    *) exit 2 ;;
esac
EOF
cat > "$tmp/init/swanctl" <<'EOF'
#!/bin/sh
case "$1" in
    enable) : ;;
    start)
        [ "$MOCK_START_FAIL" = 0 ] || exit 1
        [ "$(cat "$MOCK_STATE/enabled")" = 1 ] || exit 1
        touch "$MOCK_STATE/running" ;;
    stop)
        [ "$MOCK_STOP_FAIL" = 0 ] || exit 1
        rm -f "$MOCK_STATE/running" "$MOCK_STATE/loaded" ;;
    *) exit 2 ;;
esac
EOF
cat > "$tmp/bin/pidof" <<'EOF'
#!/bin/sh
[ "$1" = charon ] && [ -f "$MOCK_STATE/running" ]
EOF
cat > "$tmp/bin/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$tmp/bin/ubus" <<'EOF'
#!/bin/sh
printf '%s\n' "$MOCK_AGENT"
EOF
cat > "$tmp/bin/jsonfilter" <<'EOF'
#!/usr/bin/env python3
import json, sys
try:
    value=json.load(sys.stdin)["airroute-agent"][sys.argv[2].rsplit(".",1)[1]]
    assert type(value) is bool
    print(json.dumps(value))
except (ValueError, KeyError, AssertionError, IndexError):
    sys.exit(1)
EOF
chmod +x "$tmp/bin/"* "$tmp/init/swanctl"
check() {
    local expected="$1" action="${2:-status}"
    "$tmp/control" "$action" | python3 -c 'import json,sys; assert json.load(sys.stdin)==json.loads(sys.argv[1])' "$expected"
}
reject() {
    if "$tmp/control" "$@" >"$tmp/stdout" 2>"$tmp/stderr"; then
        echo "Unexpected success: $*" >&2; exit 1
    fi
}
off='{"enabled":false,"ready":false,"loaded":false,"eip93":true,"manual":true}'
on='{"enabled":true,"ready":true,"loaded":false,"eip93":true,"manual":true}'
check "$off"
reject invalid
reject enable extra
printf '1\n' > "$MOCK_STATE/routes"
reject enable
check "$off"
printf '0\n' > "$MOCK_STATE/routes"
printf 'pending change\n' > "$MOCK_STATE/pending"
reject enable
: > "$MOCK_STATE/pending"

check "$on" enable
# Root-only configuration directories/files, with no peer secrets returned.
test "$(stat -c '%a' "$tmp/etc/config/ipsec")" = 600
for dir in "$tmp/etc/swanctl" "$tmp/var/ipsec" "$tmp/var/swanctl"; do
    test "$(stat -c '%a' "$dir")" = 700
done
touch "$MOCK_STATE/loaded"
check '{"enabled":true,"ready":true,"loaded":true,"eip93":true,"manual":true}'
check "$off" disable
export MOCK_START_FAIL=1
reject enable
check "$off"
export MOCK_START_FAIL=0

# An Agent with an unknown or managed state must block both mutations.
touch "$tmp/init/airroute-agent"; chmod +x "$tmp/init/airroute-agent"
export MOCK_AGENT='{"airroute-agent":{"enabled":true,"running":false}}'
reject enable
reject disable
export MOCK_AGENT='{}'
reject enable
export MOCK_AGENT='{"airroute-agent":{"enabled":false,"running":false}}'
check "$on" enable
export MOCK_STOP_FAIL=1
reject disable
test "$(cat "$MOCK_STATE/enabled")" = 0
export MOCK_STOP_FAIL=0
check "$off" disable
# Lock serializes requests without waiting on an arbitrary user input.
exec 8>"$tmp/var/lock/relay-ipsec.lock"
flock -n 8
reject enable
flock -u 8
check "$off"
echo 'RelayOS IPsec: default off, bounded start/stop, rollback, ownership, route guard, permissions and lock OK'
