// SPDX-License-Identifier: Apache-2.0
// Pure policy and native-UCI planning; never executes commands or exposes keys.
export const owner = 'relay-ipsec-v1';
export const errors = [ 'invalid_config', 'route_conflict', 'identity_conflict', 'port_conflict',
    'key_required', 'stale_revision', 'busy', 'managed', 'unmanaged_config',
    'pending_changes', 'name_conflict', 'unavailable', 'apply_failed', 'rollback_failed' ];

function reject(code) { die(code); }
function string(value, max) {
    return type(value) == 'string' && length(value) > 0 && length(value) <= max;
}
function boolean(value) { return value === true || value === false; }
function controls(value) {
    for (let i = 0; i < length(value); i++)
        if (ord(value, i) < 32 || ord(value, i) == 127) return true;
    return false;
}
function integer(value, low, high) {
    return (type(value) == 'int' || type(value) == 'double') &&
        value == int(value) && value >= low && value <= high;
}

export function ipv4(value) {
    if (!string(value, 15) || controls(value) || !match(value, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/))
        return null;
    let n = 0;
    for (let octet in split(value, '.')) {
        if (length(octet) > 1 && substr(octet, 0, 1) == '0') return null;
        let o = int(octet);
        if (o > 255) return null;
        n = n * 256 + o;
    }
    return n;
}

export function subnet(value) {
    if (!string(value, 18) || controls(value)) return null;
    let parts = split(value, '/');
    if (length(parts) != 2 || !match(parts[1], /^(0|[1-9][0-9]?)$/)) return null;
    let n = ipv4(parts[0]), prefix = int(parts[1]);
    if (n === null || prefix > 32) return null;
    let size = 2 ** (32 - prefix), first = int(n / size) * size;
    return { first, last: first + size - 1, prefix,
        text: sprintf('%d.%d.%d.%d/%d', int(first / 16777216),
            int(first / 65536) % 256, int(first / 256) % 256, first % 256, prefix) };
}

export function overlap(a, b) {
    return a && b && a.first <= b.last && b.first <= a.last;
}

function endpoint(value) {
    if (!string(value, 253) || controls(value)) return false;
    let address = ipv4(value);
    if (address !== null) return address >= 16777216 && address < 3758096384 &&
        int(address / 16777216) != 127 && int(address / 65536) != 43518;
    if (match(value, /^[0-9.]+$/)) return false;
    for (let label in split(value, '.'))
        if (!string(label, 63) || !match(label, /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/))
            return false;
    return true;
}

function identity(value) {
    // IDs enter both quoted auth IDs and unquoted secret IDs in upstream UCI.
    // No wildcards, quotes, separators, whitespace, braces or percent IDs.
    if (!string(value, 128) || controls(value) || value == '0.0.0.0' ||
        !match(value, /^@?[A-Za-z0-9][A-Za-z0-9_.@-]*$/)) return false;
    // Bare IPv4 ranges are non-exact strongSwan IDs, not DNS names. Their
    // membership matching would bypass the distinct remote-only PSK owners.
    if (match(value, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/))
        return false;
    return true;
}
function normalizedIdentity(value) {
    return lc(substr(value, 0, 1) == '@' ? substr(value, 1) : value);
}

function encodedKey(value) {
    let encoded = '0x';
    for (let i = 0; i < length(value); i++) encoded += sprintf('%02x', ord(value, i));
    return encoded;
}

export function validate(input, previous, environment) {
    if (type(input) != 'object' || !boolean(input.enabled) ||
        type(input.peers) != 'array' || length(input.peers) > 64)
        reject('invalid_config');
    // Charon binds both IKE and NAT-T sockets while globally enabled, even
    // when no peer is enabled. Do not replace a working WireGuard listener.
    if (input.enabled)
        for (let port in environment.wireguard_ports || [])
            if (port == 500 || port == 4500) reject('port_conflict');
    let old = {}, ids = {}, identityPairs = {}, remoteIds = {}, localIPs = {}, networks = [], totalRoutes = 0;
    for (let p in previous.peers || []) old[p.id] = p;
    let result = { enabled: input.enabled, peers: [] };
    for (let p in input.peers) {
        if (type(p) != 'object' || !string(p.id, 9) || !match(p.id, /^p[0-7][0-9a-f]{7}$/) || p.id == 'p00000000' || ids[p.id] ||
            !string(p.name, 64) || controls(p.name) || !boolean(p.enabled) ||
            !endpoint(p.remote) || !identity(p.local_id) || !identity(p.remote_id) ||
            type(p.remote_subnets) != 'array' || !length(p.remote_subnets) || length(p.remote_subnets) > 32 ||
            !integer(p.dpd_delay, 10, 3600) || !integer(p.mtu, 576, 1500) ||
            index([ 'aes128-sha256-modp2048', 'aes256-sha256-modp2048' ], p.ike) < 0 ||
            index([ 'aes128-sha256-noesn', 'aes256-sha256-noesn', 'aes128gcm16-noesn' ], p.esp) < 0)
            reject('invalid_config');
        // Bound generated UCI/routing snapshots and validation cost on the
        // target's low-resource CPU. Disabled peers retain routes and count too.
        totalRoutes += length(p.remote_subnets);
        if (totalRoutes > 256) reject('invalid_config');
        ids[p.id] = true;
        let remoteIdentity = normalizedIdentity(p.remote_id);
        if (identityPairs[p.local_id + '|' + p.remote_id] || remoteIds[remoteIdentity])
            reject('identity_conflict');
        identityPairs[p.local_id + '|' + p.remote_id] = true;
        remoteIds[remoteIdentity] = true;
        if (!string(p.local_address, 18)) reject('route_conflict');
        let local = split(p.local_address, '/');
        let address = ipv4(local[0]);
        if (address === null || address < 16777216 || address >= 3758096384 ||
            int(address / 16777216) == 127 || int(address / 65536) == 43518 || length(local) > 2 ||
            (length(local) == 2 && local[1] != '32') || localIPs[local[0]])
            reject('route_conflict');
        localIPs[local[0]] = true;
        let key = p.psk;
        if (key === null || key === '') key = old[p.id]?.psk;
        if (!string(key, 128) || length(key) < 16 || controls(key))
            reject('key_required');
        let next = { id: p.id, name: p.name, enabled: p.enabled, remote: lc(p.remote),
            local_id: p.local_id, remote_id: p.remote_id, psk: key,
            local_address: local[0] + '/32', remote_subnets: [],
            ike: p.ike, esp: p.esp, dpd_delay: int(p.dpd_delay), mtu: int(p.mtu) };
        for (let route in p.remote_subnets) {
            let net = subnet(route);
            if (!net || net.prefix == 0 || net.first < 16777216 || net.last >= 3758096384 ||
                overlap(net, subnet('127.0.0.0/8')) || overlap(net, subnet('169.254.0.0/16')))
                reject('route_conflict');
            for (let existing in networks)
                if (overlap(net, existing)) reject('route_conflict');
            push(networks, net);
            push(next.remote_subnets, net.text);
        }
        sort(next.remote_subnets);
        push(result.peers, next);
    }
    for (let p in result.peers) {
        // strongSwan considers a shared-key candidate if either identity
        // matches. A local ID must never select another peer's remote-only key.
        if (remoteIds[normalizedIdentity(p.local_id)]) reject('identity_conflict');
        let local = subnet(p.local_address), outer = ipv4(p.remote);
        if (outer !== null && localIPs[p.remote]) reject('route_conflict');
        for (let net in networks)
            if (overlap(net, local) || (outer !== null && net.first <= outer && outer <= net.last))
                reject('route_conflict');
        for (let route in environment.routes || []) {
            let existing = subnet(route);
            if (!existing || !existing.prefix) continue;
            if (overlap(local, existing)) reject('route_conflict');
            for (let net in networks)
                if (overlap(net, existing)) reject('route_conflict');
        }
        for (let addr in environment.addresses || []) {
            let existing = subnet(addr);
            if (overlap(local, existing)) reject('route_conflict');
            for (let net in networks)
                if (overlap(net, existing)) reject('route_conflict');
        }
    }
    return result;
}

export function publicConfig(config) {
    return { enabled: config.enabled, peers: map(config.peers, (p) => ({
        id: p.id, name: p.name, enabled: p.enabled, remote: p.remote,
        local_id: p.local_id, remote_id: p.remote_id, psk_set: !!p.psk,
        local_address: p.local_address, remote_subnets: p.remote_subnets,
        ike: p.ike, esp: p.esp, dpd_delay: p.dpd_delay, mtu: p.mtu
    })) };
}

function effective(config, peer) {
    if (!config.enabled || !peer.enabled) return null;
    // Cosmetic names do not change an IKE identity or interrupt an existing SA.
    return { remote: peer.remote, local_id: peer.local_id, remote_id: peer.remote_id,
        psk: peer.psk, local_address: peer.local_address, remote_subnets: peer.remote_subnets,
        ike: peer.ike, esp: peer.esp, dpd_delay: peer.dpd_delay, mtu: peer.mtu };
}

export function changedPeers(before, after) {
    let next = {}, changed = [];
    for (let p in after.peers) next[p.id] = p;
    for (let p in before.peers) {
        let prev = effective(before, p), now = next[p.id] ? effective(after, next[p.id]) : null;
        if (prev && sprintf('%J', prev) != sprintf('%J', now)) push(changed, p.id);
    }
    return changed;
}

// Parse only the credential IDs and success flags returned by VICI, never key
// material. --raw exit status is not sufficient; every expected reply is checked.
export function credentialInventory(output, expected) {
    let inventories = [], loads = 0;
    for (let line in split(output, '\n')) {
        if (index(line, 'get-shared ') == 0) {
            let m = match(line, /^get-shared reply \{keys=\[([^]]*)\]\}$/);
            if (!m) return false;
            let keys = trim(m[1]) ? split(trim(m[1]), /[[:space:]]+/) : [];
            push(inventories, sort(keys));
        } else if (index(line, 'load-shared ') == 0) {
            if (line != 'load-shared reply {success=yes}') return false;
            loads++;
        } else if (index(line, 'unload-shared ') == 0) return false;
    }
    return length(inventories) == 1 && loads == length(expected) &&
        join('\n', inventories[0]) == join('\n', sort([...expected]));
}

export function plan(config, uplink) {
    let output = { ipsec: {}, network: {}, firewall: {} };
    function add(package, name, section, options) {
        output[package][name] = { type: section, options: { ...options, relay_owner: owner } };
    }
    let interfaces = [], active = false;
    for (let p in config.peers) {
        let suffix = substr(p.id, 1), base = 'rp_' + suffix;
        let xfrm = 'rpx_' + suffix, address = 'rpa_' + suffix;
        // The native jshn/blobmsg/netifd chain accepts positive INT32 if_id.
        // Stable IDs therefore use 31 bits, not bounded SOE table slots.
        let ifid = int(suffix, 16);
        let enabled = config.enabled && p.enabled;
        active = active || enabled;
        push(interfaces, address);
        add('network', xfrm, 'interface', { proto: 'xfrm', ifid: '' + ifid,
            mtu: '' + p.mtu, multicast: '0', auto: '1' });
        add('network', address, 'interface', { proto: 'static', device: '@' + xfrm,
            ipaddr: p.local_address, delegate: '0', auto: '1' });
        for (let i = 0; i < length(p.remote_subnets); i++) {
            add('network', 'rpr_' + suffix + '_' + i, 'route', { interface: address,
                target: p.remote_subnets[i], metric: '50' });
            // Retained even while disabled: loss of XFRM must not fall through
            // to the management default route and send tunnel traffic in clear.
            add('network', 'rpb_' + suffix + '_' + i, 'route', { type: 'unreachable',
                target: p.remote_subnets[i], metric: '42760' });
        }
        add('ipsec', base, 'connection', { enabled: enabled ? '1' : '0', keyexchange: 'ikev2',
            local_addrs: [ '0.0.0.0' ], remote_addrs: [ p.remote ], local: [ base + '_local' ], remote: [ base + '_remote' ],
            child: [ base + '_child' ], crypto_proposal: [ base + '_ike' ],
            dpd_delay: '' + p.dpd_delay, encap: '0', mobike: '0', fragmentation: 'yes',
            keyingtries: '0', unique: 'replace', reauth_time: '0', send_certreq: '0' });
        add('ipsec', base + '_local', 'local', { auth: 'psk', id: p.local_id });
        add('ipsec', base + '_remote', 'remote', { auth: 'psk', id: p.remote_id });
        add('ipsec', base + '_child', 'child', { mode: 'tunnel', if_id: '' + ifid,
            local_ts: [ '0.0.0.0/0' ], remote_ts: p.remote_subnets, start_action: 'start',
            dpd_action: 'restart', close_action: 'start', hw_offload: 'no',
            crypto_proposal: [ base + '_esp' ] });
        add('ipsec', base + '_ike', 'proposal', { use_custom_proposal: '1', custom_proposal: p.ike });
        add('ipsec', base + '_esp', 'proposal', { use_custom_proposal: '1', custom_proposal: p.esp });
        if (enabled) add('ipsec', base + '_key', 'secret', {
            // Binding the common local ID would make every peer PSK a usable
            // candidate during responder authentication. Scope to remote only.
            type: 'ike', secret: encodedKey(p.psk), id: [ p.remote_id ] });
    }
    if (length(interfaces)) {
        add('firewall', 'relay_ipsec_zone', 'zone', { name: 'relay_ipsec', network: interfaces,
            input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' });
        add('firewall', 'relay_ipsec_forward', 'forwarding', { src: 'relay_ipsec', dest: uplink });
        add('firewall', 'relay_ipsec_ike', 'rule', { name: 'RelayOS IPsec IKE', src: uplink,
            family: 'ipv4', proto: 'udp', dest_port: '500 4500', target: 'ACCEPT', enabled: active ? '1' : '0' });
        add('firewall', 'relay_ipsec_esp', 'rule', { name: 'RelayOS IPsec ESP', src: uplink,
            family: 'ipv4', proto: 'esp', target: 'ACCEPT', enabled: active ? '1' : '0' });
        add('firewall', 'relay_ipsec_ping', 'rule', { name: 'RelayOS IPsec tunnel ping', src: 'relay_ipsec',
            family: 'ipv4', proto: 'icmp', icmp_type: [ 'echo-request' ], target: 'ACCEPT' });
        let enabledPeers = filter(config.peers, (p) => config.enabled && p.enabled);
        if (length(enabledPeers) && !length(filter(enabledPeers, (p) => ipv4(p.remote) === null))) {
            // fw4 does not resolve arbitrary hostname src_ip values. Scope
            // literal endpoints; FQDN endpoints still require IKE authentication.
            let sources = map(enabledPeers, (p) => p.remote);
            output.firewall.relay_ipsec_ike.options.src_ip = sources;
            output.firewall.relay_ipsec_esp.options.src_ip = sources;
        }
    }
    return output;
}
