// SPDX-License-Identifier: Apache-2.0
// Invoked only by the locked, fixed-action helper. Credentials arrive on stdin.
import * as fs from 'fs';
import { cursor } from 'uci';
import { owner, errors, ipv4, subnet, overlap, validate, plan, publicConfig, changedPeers, credentialInventory }
    from '/usr/share/relay-ipsec/model.uc';

// Fixed production paths; regression tests rewrite a copy into an isolated tree.
const paths = { config: '/etc/config', runtime: '/var/run', crypto: '/proc/crypto',
    agent: '/etc/init.d/airroute-agent', extra: '/etc/swanctl/conf.d',
    swan_config: '/etc/swanctl/swanctl.conf', strong_config: '/etc/strongswan.conf',
    rpcd: '/var/run/rpcd' };
const cmd = { timeout: '/usr/libexec/timeout-coreutils', swan: '/usr/sbin/swanctl',
    init: '/etc/init.d/swanctl', network: '/etc/init.d/network',
    firewall: '/etc/init.d/firewall', fw4: '/sbin/fw4', ip: '/sbin/ip',
    ubus: '/bin/ubus', uci: '/sbin/uci', sha256: '/usr/bin/sha256sum',
    sleep: '/bin/sleep', pidof: '/bin/pidof' };
const packages = [ 'relay_ipsec', 'ipsec', 'network', 'firewall' ];
// NTP/manual clock corrections must not extend a transaction beyond rpcd's
// request timeout or consume the reserved rollback window.
function now() { return clock(true)[0]; }
let deadline = now() + 6;
let diagnostics = fs.mkstemp(paths.runtime + '/relay-ipsec-diagnostics');
if (diagnostics) fs.dup2(diagnostics.fileno(), 2);

function fail(code) { die(code); }
function run(args, seconds) {
    let remaining = deadline - now();
    if (remaining <= 0) fail('apply_failed');
    if (!diagnostics) fail('unavailable');
    diagnostics.seek(0, 2);
    let errorStart = diagnostics.tell();
    let process = fs.popen([ cmd.timeout, '-k', '1', '' + min(seconds || 2, remaining), ...args ], 'r');
    if (!process) fail('unavailable');
    let output = process.read(262145);
    let code = process.close();
    diagnostics.seek(errorStart);
    let error = diagnostics.read(262145) || '';
    if (length(output || '') > 262144) fail('unavailable');
    if (length(error) > 262144) fail('unavailable');
    return { code, output: output || '', error };
}
function requireRun(args, seconds) {
    let result = run(args, seconds);
    if (result.code != 0) fail('apply_failed');
    return result.output;
}
function list(value) { return type(value) == 'array' ? value : value ? [ value ] : []; }
function native() { return cursor(paths.config); }
function sections(c, package) {
    let result = [];
    if (!c.foreach(package, null, (s) => { push(result, s); })) fail('unavailable');
    return result;
}
function readConfig(c) {
    let result = { enabled: c.get('relay_ipsec', 'globals', 'enabled') == '1', peers: [] };
    for (let s in sections(c, 'relay_ipsec')) {
        if (s['.type'] != 'peer') continue;
        push(result.peers, { id: s['.name'], name: s.name || '', enabled: s.enabled == '1',
            remote: s.remote || '', local_id: s.local_id || '', remote_id: s.remote_id || '',
            psk: s.psk || '', local_address: s.local_address || '',
            remote_subnets: list(s.remote_subnets), ike: s.ike || '', esp: s.esp || '',
            dpd_delay: int(s.dpd_delay), mtu: int(s.mtu) });
    }
    return result;
}
function revision() {
    let result = run([ cmd.sha256, ...map(packages, (p) => paths.config + '/' + p) ], 1);
    if (result.code != 0) fail('unavailable');
    let lines = filter(split(result.output, '\n'), (l) => length(l));
    if (length(lines) != length(packages)) fail('unavailable');
    let rev = '';
    for (let l in lines) {
        if (!match(l, /^[0-9a-f]{64} /)) fail('unavailable');
        // Four 64-bit truncated file digests: CAS includes all affected files.
        rev += substr(l, 0, 16);
    }
    return rev;
}
function manual() {
    if (!fs.access(paths.agent, 'x')) return true;
    let result = run([ cmd.ubus, '-t', '2', 'call', 'rc', 'list', '{"name":"airroute-agent"}' ], 2);
    if (result.code != 0) return false;
    try {
        let agent = json(result.output)['airroute-agent'];
        return agent.enabled === false && agent.running === false;
    } catch (e) { return false; }
}
function ready() { return run([ cmd.swan, '--stats' ], 1).code == 0; }
function sas() { return requireRun([ cmd.swan, '--list-sas' ], 2); }
function hasSA(text, id) {
    return !!length(filter(split(text, '\n'), (l) =>
        match(l, regexp('^rp_' + substr(id, 1) + ': #[0-9]+,'))));
}
function peerState(text, p, enabled) {
    if (!enabled || !p.enabled) return 'disabled';
    let name = 'rp_' + substr(p.id, 1), current = false, established = false;
    for (let line in split(text, '\n')) {
        if (match(line, /^[^ ]/)) {
            current = substr(line, 0, length(name) + 2) == name + ': ';
            established = current && index(line, ', ESTABLISHED,') >= 0;
        }
        if (established && index(line, '  ' + name + '_child: #') == 0 &&
            (index(line, ', INSTALLED,') >= 0 || index(line, ', REKEYING,') >= 0)) return 'established';
    }
    return hasSA(text, p.id) ? 'connecting' : 'down';
}
function status() {
    let c = native(), config = readConfig(c), allowed = manual();
    let up = ready(), text = '';
    if (up) {
        let result = run([ cmd.swan, '--list-sas' ], 1);
        if (result.code != 0) fail('unavailable');
        text = result.output;
    } else if (run([ cmd.pidof, 'charon' ], 1).code == 0) fail('unavailable');
    let output = publicConfig(config);
    output.ok = true;
    output.revision = revision();
    output.manual = allowed;
    output.ready = up;
    output.eip93 = !!length(filter(split(fs.readfile(paths.crypto) || '', '\n'),
        (l) => match(l, /^driver[[:space:]]*:.*eip93/i)));
    for (let p in output.peers) p.state = peerState(text, p, config.enabled);
    return output;
}

function ownedName(package, name) {
    if (package == 'ipsec') return !!match(name, /^rp_[0-9a-f]{8}(_(local|remote|child|ike|esp|key))?$/);
    if (package == 'network') return !!match(name, /^rp[xa]_[0-9a-f]{8}$/) ||
        !!match(name, /^rp[rb]_[0-9a-f]{8}_[0-9]+$/);
    return index([ 'relay_ipsec_zone', 'relay_ipsec_forward', 'relay_ipsec_ike',
        'relay_ipsec_esp', 'relay_ipsec_ping' ], name) >= 0;
}
function normalizeIfId(value) {
    if (type(value) == 'int' && value >= 0 && value <= 4294967295) return value;
    if (type(value) != 'string') return null;
    if (match(value, /^0x[0-9a-f]{1,8}$/i)) return int(substr(value, 2), 16);
    if (match(value, /^(0|[1-9][0-9]{0,9})$/) && int(value) <= 4294967295) return int(value);
    return null;
}
function pendingSessions() {
    let root = fs.lstat(paths.rpcd);
    if (!root) return;
    if (root.type != 'directory') fail('pending_changes');
    let entries = fs.lsdir(paths.rpcd);
    if (!entries) fail('pending_changes');
    for (let name in entries) {
        let snapshot = name == 'snapshot-files' || name == 'snapshot-delta';
        if (!snapshot && index(name, 'uci-') != 0) continue;
        let directory = paths.rpcd + '/' + name, st = fs.lstat(directory);
        if (!st || st.type != 'directory') fail('pending_changes');
        // Inspect only the four affected packages. Session names, contents and
        // unrelated settings never enter API responses or diagnostics.
        for (let package in packages) {
            let delta = fs.lstat(directory + '/' + package);
            if (delta && (delta.type != 'file' || snapshot || delta.size > 0))
                fail('pending_changes');
        }
    }
}
function preflight(c, generated) {
    pendingSessions();
    let changes = run([ cmd.uci, '-q', 'changes' ], 1);
    if (changes.code != 0) fail('unavailable');
    for (let line in split(changes.output, '\n'))
        if (match(line, /^-?(relay_ipsec|ipsec|network|firewall)\./)) fail('pending_changes');
    for (let package in [ 'ipsec', 'network', 'firewall' ]) {
        for (let s in sections(c, package)) {
            if (s.relay_owner == owner && !ownedName(package, s['.name'])) fail('name_conflict');
            if (generated[package][s['.name']] && s.relay_owner != owner) fail('name_conflict');
            if (package == 'ipsec' && s.relay_owner != owner &&
                s['.type'] != 'globals' && s['.type'] != 'syslog') fail('unmanaged_config');
            if (package == 'network' && s.relay_owner != owner && s.proto == 'xfrm') {
                for (let name, wanted in generated.network)
                    if (wanted.options.ifid && normalizeIfId(wanted.options.ifid) == normalizeIfId(s.ifid))
                        fail('name_conflict');
            }
        }
    }
    // Native swanctl loads all included definitions. Do not silently remove or
    // restart an operator's connections or apply a global-off switch to them.
    if (length(fs.glob(paths.extra + '/*.conf') || [])) fail('unmanaged_config');
    function defaultIncludes(file, allowed) {
        let contents = fs.readfile(file);
        if (contents === null) fail('unavailable');
        let actual = [];
        for (let line in split(contents, '\n')) {
            line = trim(line);
            if (!line || substr(line, 0, 1) == '#') continue;
            if (index(allowed, line) < 0) fail('unmanaged_config');
            push(actual, line);
        }
        if (index(actual, allowed[0]) < 0) fail('unmanaged_config');
    }
    defaultIncludes(paths.swan_config, [ 'include /var/swanctl/swanctl.conf', 'include conf.d/*.conf' ]);
    let strong = fs.readfile(paths.strong_config);
    if (strong === null) fail('unavailable');
    strong = join('', map(filter(split(strong, '\n'), (l) => substr(trim(l), 0, 1) != '#'),
        (l) => replace(l, /[[:space:]]+/g, '')));
    // Exact active statements of the pinned template plus OpenWrt's include.
    let expectedStrong = 'charon{load_modular=yesplugins{includestrongswan.d/charon/*.conf}}' +
        'includestrongswan.d/*.confinclude/var/ipsec/strongswan.conf';
    if (strong != expectedStrong) fail('unmanaged_config');
    if (c.get('ipsec', 'globals') != 'globals' ||
        c.get('ipsec', 'globals', 'rtinstall_enabled') != '0') fail('unmanaged_config');
    if (ready()) {
        let loaded = requireRun([ cmd.swan, '--list-conns' ], 1);
        for (let line in split(loaded, '\n')) {
            if (!line || substr(line, 0, 1) == ' ') continue;
            let m = match(line, /^(rp_[0-7][0-9a-f]{7}): /);
            if (!m || c.get('ipsec', m[1]) != 'connection' ||
                c.get('ipsec', m[1], 'relay_owner') != owner) fail('unmanaged_config');
        }
    } else if (run([ cmd.pidof, 'charon' ], 1).code == 0) fail('unavailable');
    let links;
    try { links = json(requireRun([ cmd.ip, '-j', '-d', 'link', 'show', 'type', 'xfrm' ], 1)); }
    catch (e) { fail('unavailable'); }
    for (let link in links)
        for (let name, wanted in generated.network)
            if (wanted.options.ifid && normalizeIfId(wanted.options.ifid) == normalizeIfId(link.linkinfo?.info_data?.if_id) &&
                (name != link.ifname || c.get('network', name, 'relay_owner') != owner))
                fail('name_conflict');
}
function environment(c) {
    let env = { routes: [], addresses: [] };
    let ownDevices = {}, ownRoutes = {};
    for (let s in sections(c, 'network')) {
        if (s.relay_owner != owner) continue;
        if (s['.type'] == 'interface') ownDevices[s['.name']] = true;
        if (s['.type'] == 'route' && subnet(s.target)) ownRoutes[subnet(s.target).text] = true;
    }
    function prefix(mask) {
        let value = ipv4(mask), count = 0, zero = false;
        if (value === null) fail('route_conflict');
        for (let offset = 0; offset < 32; offset++) {
            let one = !!(value & (2 ** (31 - offset)));
            if (one && zero) fail('route_conflict');
            if (one) count++; else zero = true;
        }
        return count;
    }
    for (let s in sections(c, 'network')) {
        if (s.relay_owner == owner) continue;
        for (let value in list(s.addresses)) push(env.addresses, index(value, '/') >= 0 ? value : value + '/32');
        for (let value in list(s.ipaddr)) {
            let bits = s.netmask ? prefix(s.netmask) : 32;
            push(env.addresses, index(value, '/') >= 0 ? value : value + '/' + bits);
        }
        for (let value in list(s.allowed_ips)) push(env.routes, index(value, '/') >= 0 ? value : value + '/32');
        if (s['.type'] == 'route' && s.target && s.target != '0.0.0.0' && s.target != 'default')
            push(env.routes, index(s.target, '/') >= 0 ? s.target : s.target + '/' + (s.netmask ? prefix(s.netmask) : 32));
    }
    let addr = run([ cmd.ip, '-j', '-4', 'addr', 'show' ], 1);
    if (addr.code != 0) fail('unavailable');
    try {
        for (let iface in json(addr.output)) {
            if (ownDevices[iface.ifname]) continue;
            for (let address in iface.addr_info || [])
                if (address.family == 'inet') push(env.addresses, address.local + '/' + address.prefixlen);
        }
    } catch (e) { fail('unavailable'); }
    let routes;
    try { routes = json(requireRun([ cmd.ip, '-N', '-j', '-4', 'route', 'show', 'table', 'main' ], 1)); }
    catch (e) { fail('unavailable'); }
    for (let route in routes) {
        if (!route.dst || route.dst == 'default') continue;
        let prefix = subnet(index(route.dst, '/') >= 0 ? route.dst : route.dst + '/32');
        if (!prefix) fail('route_conflict');
        if (ownRoutes[prefix.text] &&
            ((route.metric == 50 && ownDevices[route.dev]) ||
             (route.type == 'unreachable' && (route.metric == 42760 ||
                (route.metric == 42759 && '' + route.protocol == '242'))))) continue;
        push(env.routes, prefix.text);
    }
    return env;
}
function uplink(c) {
    let zones = filter(sections(c, 'firewall'), (s) => s['.type'] == 'zone' && index(list(s.network), 'lan') >= 0);
    if (length(zones) != 1 || zones[0].masq != '1' ||
        !match(zones[0].name || '', /^[A-Za-z][A-Za-z0-9_]{0,10}$/)) fail('unmanaged_config');
    for (let s in sections(c, 'firewall'))
        if (s['.type'] == 'zone' && s.name == 'relay_ipsec' && s.relay_owner != owner) fail('name_conflict');
    return zones[0].name;
}
function snapshot() {
    let files = {};
    for (let package in packages) {
        let file = paths.config + '/' + package, st = fs.lstat(file);
        if (!st || st.type != 'file' || st.size > 1048576) fail('unavailable');
        let data = fs.readfile(file);
        if (data === null) fail('unavailable');
        files[package] = { data, mode: st.mode & 511 };
    }
    return files;
}
function secureWrite(file, data, mode) {
    let handle = fs.open(file, 'wx', mode);
    if (!handle) fail('apply_failed');
    let written = handle.write(data), closed = handle.close();
    if (written != length(data) || !closed || !fs.chmod(file, mode)) fail('apply_failed');
}
function set(c, package, section, value) {
    if (!c.set(package, section, value.type)) fail('apply_failed');
    for (let option, data in value.options)
        if (!c.set(package, section, option, data)) fail('apply_failed');
}
function stageConfig(stage, files, config, generated) {
    for (let package in packages) secureWrite(stage + '/' + package, files[package].data, 384);
    if (!fs.mkdir(stage + '/deltas', 448)) fail('apply_failed');
    let c = cursor(stage, stage + '/deltas', '');
    for (let package in [ 'ipsec', 'network', 'firewall' ]) {
        for (let s in sections(c, package))
            if (s.relay_owner == owner && !c.delete(package, s['.name'])) fail('apply_failed');
        for (let name, value in generated[package]) set(c, package, name, value);
    }
    if (!c.set('ipsec', 'globals', 'enabled', config.enabled ? '1' : '0') ||
        !c.set('ipsec', 'globals', 'rtinstall_enabled', '0')) fail('apply_failed');
    for (let s in sections(c, 'relay_ipsec'))
        if (!c.delete('relay_ipsec', s['.name'])) fail('apply_failed');
    set(c, 'relay_ipsec', 'globals', { type: 'globals', options: { enabled: config.enabled ? '1' : '0' } });
    for (let p in config.peers) {
        let opts = { ...p, enabled: p.enabled ? '1' : '0', dpd_delay: '' + p.dpd_delay, mtu: '' + p.mtu };
        delete opts.id;
        set(c, 'relay_ipsec', p.id, { type: 'peer', options: opts });
    }
    for (let package in packages)
        if (!c.commit(package) || !fs.chmod(stage + '/' + package,
            package == 'ipsec' || package == 'relay_ipsec' ? 384 : files[package].mode)) fail('apply_failed');
}
function guards(config) {
    let result = [];
    for (let p in config.peers)
        for (let route in p.remote_subnets)
            if (index(result, route) < 0) push(result, route);
    return result;
}
function verifyGuards(routes, metric) {
    let current;
    try { current = json(requireRun([ cmd.ip, '-N', '-j', '-4', 'route', 'show', 'table', 'main' ], 1)); }
    catch (e) { fail('apply_failed'); }
    for (let route in routes)
        if (!length(filter(current, (r) => r.type == 'unreachable' && r.metric == metric &&
            (r.dst == route || r.dst + '/32' == route)))) fail('apply_failed');
}
function routeBatch(stage, file, operation, routes) {
    let data = join('\n', map(routes, (r) => 'route ' + operation + ' unreachable ' + r +
        ' metric 42759 proto 242')) + '\n';
    if (!length(routes)) return;
    let filename = stage + '/' + file;
    fs.unlink(filename);
    secureWrite(filename, data, 384);
    let result = run([ cmd.ip, '-4', '-force', '-batch', filename ], 2);
    if (operation != 'del' && result.code != 0) fail('apply_failed');
}
function guardPreflight(routes, previous) {
    let current = requireRun([ cmd.ip, '-N', '-j', '-4', 'route', 'show', 'table', 'main' ], 1);
    let found;
    try { found = json(current); } catch (e) { fail('unavailable'); }
    // Validate every collision before installing the first guard.
    for (let route in routes)
        for (let existing in found)
            if ((existing.dst == route || existing.dst + '/32' == route) && existing.metric == 42759 &&
                (index(previous, route) < 0 || existing.type != 'unreachable' ||
                 '' + existing.protocol != '242')) fail('name_conflict');
}
function releaseGuards(stage, routes) {
    routeBatch(stage, '.guards-release', 'del', routes);
    let current;
    try { current = json(requireRun([ cmd.ip, '-N', '-j', '-4', 'route', 'show', 'table', 'main' ], 1)); }
    catch (e) { fail('apply_failed'); }
    for (let route in routes)
        if (length(filter(current, (r) => r.type == 'unreachable' && r.metric == 42759 &&
            '' + r.protocol == '242' && (r.dst == route || r.dst + '/32' == route)))) fail('apply_failed');
}
function terminate(ids) {
    if (!length(ids)) return;
    if (!ready()) {
        if (run([ cmd.pidof, 'charon' ], 1).code == 0) fail('apply_failed');
        return;
    }
    // Negative VICI timeout removes the completion callback; no peer ACK wait.
    // A single aggregate list query below verifies all matching/rekeyed IKE SAs.
    for (let id in ids)
        run([ cmd.swan, '--terminate', '--ike', 'rp_' + substr(id, 1),
            '--force', '--timeout', '-1', '--loglevel', '-1' ], 1);
    for (let attempt = 0; attempt < 3; attempt++) {
        let text = sas();
        if (!length(filter(ids, (id) => hasSA(text, id)))) return;
        requireRun([ cmd.sleep, '0.2' ], 1);
    }
    fail('apply_failed');
}
function stop() {
    requireRun([ cmd.init, 'stop' ], 2);
    if (ready() || run([ cmd.pidof, 'charon' ], 1).code == 0) fail('apply_failed');
}
function load(config) {
    if (!config.enabled) { stop(); return; }
    requireRun([ cmd.init, 'enable' ], 1);
    requireRun([ cmd.init, 'reload' ], 3);
    for (let attempt = 0; !ready(); attempt++) {
        if (attempt == 4) fail('apply_failed');
        requireRun([ cmd.sleep, '0.2' ], 1);
    }
    // Native reload may mask load-all errors; verify independently. Credentials
    // return success even for individual failures, so require each success line.
    let credentials = run([ cmd.swan, '--load-creds', '--noprompt' ], 2);
    if (credentials.code != 0 || trim(credentials.error)) fail('apply_failed');
    let keys = credentials.output, expectedKeys = [];
    for (let p in config.peers)
        if (p.enabled) {
            let key = 'ike-rp_' + substr(p.id, 1) + '_key';
            push(expectedKeys, key);
            if (index(split(keys, '\n'), "loaded ike secret '" + key + "'") < 0) fail('apply_failed');
        }
    // The normal loader also ignores enumeration/unload errors. A second raw
    // pass must begin with exactly the intended inventory and acknowledge every
    // subsequent load. These private response frames contain IDs, not secrets.
    let inventory = run([ cmd.swan, '--load-creds', '--raw', '--noprompt' ], 2);
    if (inventory.code != 0 || trim(inventory.error) ||
        !credentialInventory(inventory.output, expectedKeys)) fail('apply_failed');
    requireRun([ cmd.swan, '--load-conns' ], 2);
    let loaded = requireRun([ cmd.swan, '--list-conns' ], 1);
    let expected = filter(config.peers, (p) => p.enabled);
    for (let p in expected)
        if (!length(filter(split(loaded, '\n'), (l) =>
            match(l, regexp('^rp_' + substr(p.id, 1) + ': IKEv2,'))))) fail('apply_failed');
    for (let line in split(loaded, '\n')) {
        if (!line || substr(line, 0, 1) == ' ') continue;
        let m = match(line, /^(rp_[0-9a-f]{8}): /);
        if (!m || !length(filter(expected, (p) => m[1] == 'rp_' + substr(p.id, 1)))) fail('apply_failed');
    }
}
function clean(stage) {
    if (!stage) return;
    for (let name in fs.lsdir(stage + '/deltas') || []) fs.unlink(stage + '/deltas/' + name);
    fs.rmdir(stage + '/deltas');
    for (let name in fs.lsdir(stage) || []) fs.unlink(stage + '/' + name);
    fs.rmdir(stage);
}
function quiesce(config, ids, files, written, zone) {
    if (!length(ids)) return;
    if (!ready()) {
        if (run([ cmd.pidof, 'charon' ], 1).code == 0) fail('apply_failed');
        return;
    }
    let quiet = { enabled: config.enabled, peers: map(config.peers, (p) => ({
        ...p, enabled: index(ids, p.id) >= 0 ? false : p.enabled
    })) };
    let stage = fs.mkdtemp(paths.config + '/.relay-ipsec-quiet-XXXXXX');
    if (!stage) fail('apply_failed');
    try {
        secureWrite(stage + '/ipsec', files.ipsec.data, 384);
        if (!fs.mkdir(stage + '/deltas', 448)) fail('apply_failed');
        let c = cursor(stage, stage + '/deltas', '');
        for (let s in sections(c, 'ipsec'))
            if (s.relay_owner == owner && !c.delete('ipsec', s['.name'])) fail('apply_failed');
        for (let name, definition in plan(quiet, zone).ipsec) set(c, 'ipsec', name, definition);
        if (!c.set('ipsec', 'globals', 'enabled', quiet.enabled ? '1' : '0') ||
            !c.commit('ipsec') || !fs.chmod(stage + '/ipsec', 384)) fail('apply_failed');
        if (!fs.rename(stage + '/ipsec', paths.config + '/ipsec')) fail('apply_failed');
        written.ipsec = fs.readfile(paths.config + '/ipsec');
        // Remove affected definitions FIRST so a remote cannot reauthenticate
        // with the old PSK between SA termination and final credential reload.
        // Reloading the complete quiet aggregate retains all unchanged peers.
        load(quiet);
        terminate(ids);
    } catch (error) { clean(stage); throw error; }
    clean(stage);
}
function verifyNetwork(config) {
    for (let attempt = 0; attempt < 4; attempt++) {
        let links, addresses, routes, dump;
        try {
            links = json(requireRun([ cmd.ip, '-j', '-d', 'link', 'show', 'type', 'xfrm' ], 1));
            addresses = json(requireRun([ cmd.ip, '-j', '-4', 'addr', 'show' ], 1));
            routes = json(requireRun([ cmd.ip, '-N', '-j', '-4', 'route', 'show', 'table', 'main' ], 1));
            dump = json(requireRun([ cmd.ubus, '-t', '1', 'call', 'network.interface', 'dump' ], 1));
        } catch (e) { fail('apply_failed'); }
        let complete = true;
        for (let p in config.peers) {
            let suffix = substr(p.id, 1), name = 'rpx_' + suffix, address = 'rpa_' + suffix;
            if (!length(filter(links, (l) => l.ifname == name && index(l.flags || [], 'UP') >= 0 &&
                normalizeIfId(l.linkinfo?.info_data?.if_id) == int(suffix, 16)))) complete = false;
            if (!length(filter(dump.interface || [], (i) => i.interface == address &&
                i.up === true && i.l3_device == name))) complete = false;
            let kernel = filter(addresses, (i) => i.ifname == name);
            if (!length(kernel) || !length(filter(kernel[0].addr_info || [], (a) =>
                a.family == 'inet' && a.local + '/' + a.prefixlen == p.local_address))) complete = false;
            for (let target in p.remote_subnets)
                if (!length(filter(routes, (r) => (!r.type || r.type == 'unicast') &&
                    (r.dst == target || r.dst + '/32' == target) && r.dev == name && r.metric == 50)))
                    complete = false;
        }
        if (complete) return;
        requireRun([ cmd.sleep, '0.2' ], 1);
    }
    fail('apply_failed');
}
function apply(request) {
    deadline = now() + 18;
    if (!manual()) fail('managed');
    if (type(request) != 'object' || type(request.config) != 'object') fail('invalid_config');
    let currentRevision = revision();
    if (request.config.revision != currentRevision) fail('stale_revision');
    let c = native(), previous = readConfig(c), target = validate(request.config, previous, environment(c));
    let zone = uplink(c), generated = plan(target, zone);
    preflight(c, generated);
    // Same filesystem as /etc/config, so publishing each file uses atomic rename.
    let files = snapshot(), stage = fs.mkdtemp(paths.config + '/.relay-ipsec-XXXXXX');
    if (!stage) fail('unavailable');
    let written = {}, beforeGuards = guards(previous), afterGuards = guards(target);
    let union = [...beforeGuards], guarded = false;
    for (let route in afterGuards) if (index(union, route) < 0) push(union, route);
    let affected = changedPeers(previous, target);
    try {
        stageConfig(stage, files, target, generated);
        if (!manual()) fail('managed');
        pendingSessions();
        if (revision() != currentRevision) fail('stale_revision');
        guardPreflight(union, beforeGuards);
        guarded = true;
        routeBatch(stage, '.guards-add', 'replace', union);
        verifyGuards(union, 42759);
        quiesce(previous, affected, files, written, zone);
        for (let package in packages) {
            if (!fs.rename(stage + '/' + package, paths.config + '/' + package)) fail('apply_failed');
            written[package] = fs.readfile(paths.config + '/' + package);
        }
        requireRun([ cmd.fw4, 'check' ], 2);
        requireRun([ cmd.network, 'reload' ], 3);
        verifyGuards(afterGuards, 42760);
        verifyNetwork(target);
        requireRun([ cmd.firewall, 'reload' ], 3);
        load(target);
        let inactive = filter(affected, (id) => !target.enabled ||
            !length(filter(target.peers, (p) => p.id == id && p.enabled)));
        terminate(inactive);
        // Configured-but-disabled routes stay protected. Temporary guards also
        // cover removed prefixes until all application/postcondition checks pass.
        let response = status();
        releaseGuards(stage, union);
        clean(stage);
        return response;
    } catch (error) {
        let code = index(errors, error.message) >= 0 ? error.message : 'apply_failed';
        if (!length(keys(written))) {
            deadline = now() + 3;
            try { if (guarded) releaseGuards(stage, union); }
            catch (e) { clean(stage); fail('rollback_failed'); }
            clean(stage);
            fail(code);
        }
        deadline = now() + 8;
        try {
            // Refuse to overwrite a concurrent configuration writer on rollback.
            for (let package in packages)
                if (fs.readfile(paths.config + '/' + package) !=
                    (written[package] ?? files[package].data)) fail('rollback_failed');
            let reverse = changedPeers(target, previous);
            quiesce(target, reverse, files, written, zone);
            for (let package in packages) {
                fs.unlink(stage + '/' + package);
                secureWrite(stage + '/' + package, files[package].data, files[package].mode);
                if (!fs.rename(stage + '/' + package, paths.config + '/' + package)) fail('rollback_failed');
            }
            requireRun([ cmd.network, 'reload' ], 2);
            requireRun([ cmd.firewall, 'reload' ], 2);
            load(previous);
            verifyGuards(beforeGuards, 42760);
            verifyNetwork(previous);
            if (guarded) releaseGuards(stage, union);
        } catch (rollback) {
            // Preserve union guards on failed recovery; do not fall back to
            // plaintext or flush unrelated kernel/WireGuard state.
            clean(stage);
            fail('rollback_failed');
        }
        clean(stage);
        fail(code);
    }
}

try {
    let action = ARGV[0], result;
    if (action == 'get') result = status();
    else if (action == 'apply') {
        let body = fs.stdin.read(131073);
        if (length(body || '') > 131072) fail('invalid_config');
        let request;
        try { request = json(body); } catch (e) { fail('invalid_config'); }
        result = apply(request);
    } else fail('invalid_config');
    printf('%J\n', result);
} catch (error) {
    printf('%J\n', { ok: false, error: index(errors, error.message) >= 0 ? error.message : 'unavailable' });
}
