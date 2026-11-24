#!/usr/bin/env bash
# Exercise copies of the production shell bridge, rpcd plugin and boot helper.
# No real ucode worker, UCI configuration, init service, network or device is used.
# Bash, Node and flock are already used by the default console CI tests.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
fixture="$(mktemp -d -t relay-ipsec-control.XXXXXXXX)"
trap 'rm -rf -- "$fixture"' EXIT
export RELAY_IPSEC_TEST_STATE="$fixture/state"
export RELAY_IPSEC_TEST_OUTCOME=ok RELAY_IPSEC_TEST_UCI_FAIL=none

node - "$root" "$fixture" <<'NODE'
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const [ root, fixture ] = process.argv.slice(2);
for (const dir of [ 'bin', 'state', 'share', 'etc/config', 'var/lock' ])
  fs.mkdirSync(path.join(fixture, dir), { recursive: true });
const files = path.join(root, 'packages/relay-ipsec/files');
function copy(source, destination, replacements) {
  let contents = fs.readFileSync(path.join(files, source), 'utf8');
  for (const [ before, after ] of replacements) {
    assert.ok(contents.includes(before), 'Fixture path replacement must match production: ' + before);
    contents = contents.replaceAll(before, after);
  }
  fs.writeFileSync(path.join(fixture, destination), contents, { mode: 0o755 });
}
copy('relay-ipsec', 'control', [
  [ 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'PATH=' + fixture + '/bin:/usr/bin:/bin' ],
  [ '/usr/bin/ucode', fixture + '/bin/ucode' ],
  [ '/usr/share/relay-ipsec/worker.uc', fixture + '/share/worker.uc' ],
  [ '/var/lock', fixture + '/var/lock' ]
]);
copy('relay.ipsec', 'rpcd-plugin', [ [ '/usr/libexec/relay-ipsec', fixture + '/control' ] ]);
copy('relay-ipsec-prepare', 'prepare', [
  [ '#!/bin/sh /etc/rc.common', '#!/bin/sh' ],
  [ '/etc/config/ipsec', fixture + '/etc/config/ipsec' ],
  [ '/etc/config/relay_ipsec', fixture + '/etc/config/relay_ipsec' ],
  [ '/etc/swanctl', fixture + '/etc/swanctl' ],
  [ '/var/swanctl', fixture + '/var/swanctl' ],
  [ '/var/ipsec', fixture + '/var/ipsec' ]
]);
// rc.common would dispatch these functions on the device. Dispatch only the
// two intended functions in this private test copy, without sourcing rc.common.
fs.appendFileSync(path.join(fixture, 'prepare'), '\n[ "$#" -eq 1 ] || exit 2\ncase "$1" in start) start ;; boot) boot ;; *) exit 2 ;; esac\n');
assert.match(fs.readFileSync(path.join(files, 'relay-ipsec-prepare'), 'utf8'), /^START=89$/m);
for (const name of [ 'ipsec', 'relay_ipsec' ]) {
  const content = fs.readFileSync(path.join(root, 'overlay/etc/config', name), 'utf8');
  assert.match(content, /option enabled '0'/, 'Fresh images must default to disabled');
  fs.writeFileSync(path.join(fixture, 'etc/config', name), content);
  fs.chmodSync(path.join(fixture, 'etc/config', name), 0o666);
}
fs.writeFileSync(path.join(fixture, 'share/worker.uc'), '// No real worker runs in this shell test.\n');
for (const name of [ 'calls', 'uci-calls' ]) fs.writeFileSync(path.join(fixture, 'state', name), '');
// Deliberate whitespace, UTF-8 and shell metacharacters must arrive byte-for-byte
// on stdin, never be interpolated, and never appear in argv or diagnostics.
fs.writeFileSync(path.join(fixture, 'input'), '  ' + JSON.stringify({ config: {
  revision: 'fixture-r1', enabled: false, peers: [{ psk: 'synthetic-key-密钥-"-$()-;\\' }]
} }, null, 2) + '\n\n');
function stub(name, lines) {
  fs.writeFileSync(path.join(fixture, 'bin', name), lines.join('\n') + '\n', { mode: 0o755 });
}
stub('ucode', [
  '#!/bin/sh', 'set -eu',
  '[ "$#" -eq 2 ] || exit 91',
  'printf "%s\\n" "$@" > "$RELAY_IPSEC_TEST_STATE/argv"',
  'printf "called\\n" >> "$RELAY_IPSEC_TEST_STATE/calls"',
  'umask > "$RELAY_IPSEC_TEST_STATE/umask"',
  'cat > "$RELAY_IPSEC_TEST_STATE/stdin"',
  'printf "synthetic-private-key diagnostic must not escape\\n" >&2',
  'case "$RELAY_IPSEC_TEST_OUTCOME" in',
  '  ok) printf \'{"ok":true,"action":"%s"}\\n\' "$2" ;;',
  '  error) printf \'{"ok":false,"error":"invalid_config"}\\n\' ;;',
  '  exit) exit 17 ;;',
  '  *) exit 92 ;;',
  'esac'
]);
stub('uci', [
  '#!/bin/sh', 'set -eu', '[ "$1" != -q ] || shift',
  'printf "%s\\n" "$*" >> "$RELAY_IPSEC_TEST_STATE/uci-calls"',
  '[ "$1" != "$RELAY_IPSEC_TEST_UCI_FAIL" ] || exit 1',
  'case "$1 $2" in',
  '  "get ipsec.globals.enabled") [ -f "$RELAY_IPSEC_TEST_STATE/enabled" ] || exit 1; cat "$RELAY_IPSEC_TEST_STATE/enabled" ;;',
  '  "set ipsec.globals=globals") printf "globals\\n" > "$RELAY_IPSEC_TEST_STATE/globals" ;;',
  '  "set ipsec.globals.enabled=0") printf "0\\n" > "$RELAY_IPSEC_TEST_STATE/enabled" ;;',
  '  "set ipsec.globals.rtinstall_enabled=0") printf "0\\n" > "$RELAY_IPSEC_TEST_STATE/routes" ;;',
  '  "commit ipsec") printf "committed\\n" > "$RELAY_IPSEC_TEST_STATE/committed" ;;',
  '  *) exit 93 ;;',
  'esac'
]);
NODE

run() {
    if "$@" < "$fixture/input" > "$fixture/stdout" 2> "$fixture/stderr"; then
        result=0
    else
        result=$?
    fi
}
calls() { wc -l < "$fixture/state/calls"; }
assert_json() {
    [[ "$result" -eq 0 ]]
    node - "$fixture/stdout" "$1" <<'NODE'
const assert = require('node:assert/strict');
const fs = require('node:fs');
assert.deepEqual(JSON.parse(fs.readFileSync(process.argv[2], 'utf8')), JSON.parse(process.argv[3]));
NODE
}
assert_worker() {
    node - "$fixture" "$1" <<'NODE'
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const [ fixture, action ] = process.argv.slice(2);
assert.deepEqual(fs.readFileSync(path.join(fixture, 'state/argv'), 'utf8').trim().split('\n'),
  [ path.join(fixture, 'share/worker.uc'), action ]);
assert.match(fs.readFileSync(path.join(fixture, 'state/umask'), 'utf8').trim(), /^0*77$/);
assert.equal(fs.readFileSync(path.join(fixture, 'stderr'), 'utf8'), '', 'Worker stderr must not leak');
assert.deepEqual(fs.readFileSync(path.join(fixture, 'state/stdin')), fs.readFileSync(path.join(fixture, 'input')));
NODE
}
reject() {
    local before
    before="$(calls)"
    run "$@"
    [[ "$result" -ne 0 && ! -s "$fixture/stdout" ]]
    [[ "$(calls)" -eq "$before" ]]
}
check_modes() {
    node - "$fixture" <<'NODE'
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const fixture = process.argv[2];
for (const name of [ 'etc/config/ipsec', 'etc/config/relay_ipsec' ])
  assert.equal(fs.statSync(path.join(fixture, name)).mode & 0o777, 0o600, name);
for (const name of [ 'var/ipsec', 'var/swanctl', 'etc/swanctl' ])
  assert.equal(fs.statSync(path.join(fixture, name)).mode & 0o777, 0o700, name);
NODE
}

# Only the fixed bridge actions are accepted. status is a get compatibility alias.
for action in get status apply; do
    run "$fixture/control" "$action"
    expected="$action"
    [[ "$action" != status ]] || expected=get
    assert_json "{\"ok\":true,\"action\":\"$expected\"}"
    assert_worker "$expected"
done
reject "$fixture/control"
for action in enable disable invalid 'apply;reboot'; do reject "$fixture/control" "$action"; done
reject "$fixture/control" apply extra
reject "$fixture/control" get extra

# Errors emitted by the worker remain structured; stderr and abnormal process
# termination never expose its diagnostic text or synthesize a false success.
export RELAY_IPSEC_TEST_OUTCOME=error
run "$fixture/control" apply
assert_json '{"ok":false,"error":"invalid_config"}'
assert_worker apply
export RELAY_IPSEC_TEST_OUTCOME=exit
run "$fixture/control" apply
[[ "$result" -eq 17 && ! -s "$fixture/stdout" && ! -s "$fixture/stderr" ]]
export RELAY_IPSEC_TEST_OUTCOME=ok

# Real flock contention is nonblocking and returns the same safe JSON for reads
# and writes. Holding fd 8 avoids the bridge's own fd 9.
before="$(calls)"
exec 8>"$fixture/var/lock/relay-ipsec.lock"
flock -n 8
for action in get status apply; do
    run "$fixture/control" "$action"
    assert_json '{"ok":false,"error":"busy"}'
done
[[ "$(calls)" -eq "$before" ]]
flock -u 8
exec 8>&-
run "$fixture/control" get
assert_json '{"ok":true,"action":"get"}'

# The bridge must safely reject an absent or nonexecutable interpreter and an
# absent worker. These changes affect only this fixture, not production paths.
before="$(calls)"
chmod 644 "$fixture/bin/ucode"
run "$fixture/control" get
assert_json '{"ok":false,"error":"unavailable"}'
chmod 755 "$fixture/bin/ucode"
mv "$fixture/bin/ucode" "$fixture/bin/ucode.saved"
run "$fixture/control" apply
assert_json '{"ok":false,"error":"unavailable"}'
mv "$fixture/bin/ucode.saved" "$fixture/bin/ucode"
mv "$fixture/share/worker.uc" "$fixture/share/worker.saved"
run "$fixture/control" get
assert_json '{"ok":false,"error":"unavailable"}'
mv "$fixture/share/worker.saved" "$fixture/share/worker.uc"
[[ "$(calls)" -eq "$before" ]]

# rpcd advertises a table/object config, not a string or arbitrary shell command.
run "$fixture/rpcd-plugin" list
assert_json '{"get":{},"apply":{"config":{}}}'
for action in get apply; do
    run "$fixture/rpcd-plugin" call "$action"
    assert_json "{\"ok\":true,\"action\":\"$action\"}"
    assert_worker "$action"
done
reject "$fixture/rpcd-plugin"
reject "$fixture/rpcd-plugin" list extra
reject "$fixture/rpcd-plugin" call
reject "$fixture/rpcd-plugin" call status
reject "$fixture/rpcd-plugin" call enable
reject "$fixture/rpcd-plugin" call invalid
reject "$fixture/rpcd-plugin" call apply extra

# Boot prepare runs before swanctl and protects private files/directories. start
# itself must not edit configuration, launch a worker, or change the network.
before="$(calls)"
run env "PATH=$fixture/bin:$PATH" "$fixture/prepare" start
[[ "$result" -eq 0 && ! -s "$fixture/state/uci-calls" ]]
check_modes
run env "PATH=$fixture/bin:$PATH" "$fixture/prepare" boot
[[ "$result" -eq 0 ]]
[[ "$(<"$fixture/state/globals")" == globals ]]
[[ "$(<"$fixture/state/enabled")" == 0 && "$(<"$fixture/state/routes")" == 0 ]]
[[ "$(<"$fixture/state/committed")" == committed ]]
check_modes

# An explicit saved enable flag survives boot; only an absent/empty flag falls
# back to disabled. No unconditional rewrite or implicit daemon start is allowed.
for enabled in 1 0; do
    printf '%s\n' "$enabled" > "$fixture/state/enabled"
    : > "$fixture/state/uci-calls"
    run env "PATH=$fixture/bin:$PATH" "$fixture/prepare" boot
    [[ "$result" -eq 0 && "$(<"$fixture/state/enabled")" == "$enabled" ]]
    [[ "$(<"$fixture/state/uci-calls")" == 'get ipsec.globals.enabled' ]]
done
: > "$fixture/state/enabled"
export RELAY_IPSEC_TEST_UCI_FAIL=commit
run env "PATH=$fixture/bin:$PATH" "$fixture/prepare" boot
[[ "$result" -ne 0 ]]
export RELAY_IPSEC_TEST_UCI_FAIL=none

for name in ipsec relay_ipsec; do
    : > "$fixture/state/uci-calls"
    mv "$fixture/etc/config/$name" "$fixture/etc/config/$name.saved"
    run env "PATH=$fixture/bin:$PATH" "$fixture/prepare" boot
    [[ "$result" -ne 0 && ! -s "$fixture/state/uci-calls" ]]
    mv "$fixture/etc/config/$name.saved" "$fixture/etc/config/$name"
done
[[ "$(calls)" -eq "$before" ]]
printf '%s\n' 'RelayOS IPsec shell: fixed get/status/apply, stdin, typed rpcd plugin, lock, dependency failures, stderr redaction, private modes and default-off boot OK'
