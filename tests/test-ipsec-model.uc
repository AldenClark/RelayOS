// SPDX-License-Identifier: Apache-2.0
// Run with the pinned native ucode; pure model, no router/filesystem changes.
import { ipv4, subnet, overlap, validate, plan, publicConfig, changedPeers, credentialInventory }
    from '../packages/relay-ipsec/files/relay-ipsec-model.uc';

let assertions = 0;
function assert(value, message) {
    assertions++;
    if (!value) die('Assertion failed: ' + message);
}
function same(actual, expected, message) {
    assert(sprintf('%J', actual) == sprintf('%J', expected), message);
}
function clone(value) { return json(sprintf('%J', value)); }
function peer(index) {
    return { id: sprintf('p%08x', index), name: 'Cloud ' + index, enabled: true,
        remote: '198.51.100.' + index, local_id: 'relay-' + index,
        remote_id: 'cloud-' + index, psk: 'synthetic-test-secret-' + index,
        local_address: '10.78.' + index + '.2/32', remote_subnets: [ '10.78.' + index + '.1/32' ],
        ike: 'aes128-sha256-modp2048', esp: 'aes128-sha256-noesn', dpd_delay: 30, mtu: 1400 };
}
function valid(input, previous, environment) {
    return validate(input, previous || { enabled: false, peers: [] },
        environment || { routes: [], addresses: [] });
}
function reject(input, expected, environment, previous) {
    let error = null;
    try { valid(input, previous, environment); } catch (e) { error = e.message; }
    same(error, expected, 'Reject ' + expected);
}
function one(options) { return { enabled: true, peers: [ { ...peer(1), ...options } ] }; }

same(ipv4('10.0.0.1'), 167772161, 'IPv4 arithmetic');
same(ipv4('10.00.0.1'), null, 'Reject ambiguous leading-zero IPv4');
same(ipv4('256.1.1.1'), null, 'Reject oversized IPv4 component');
same(subnet('10.20.30.77/24').text, '10.20.30.0/24', 'Canonical CIDR');
same(subnet('10.20.30.77/33'), null, 'Reject bad prefix');
assert(overlap(subnet('10.20.30.0/24'), subnet('10.20.30.77/32')), 'Prefix overlap');
assert(!overlap(subnet('10.20.30.0/24'), subnet('10.20.31.0/24')), 'Disjoint prefixes');

let two = valid({ enabled: true, peers: [ peer(1), peer(2) ] });
same(length(two.peers), 2, 'Two independent peers');
let native = plan(two, 'uplink');
same(native.network.rpx_00000001.options.ifid, '1', 'Stable peer XFRM ID');
same(native.network.rpx_00000002.options.ifid, '2', 'Distinct peer XFRM ID');
same(native.network.rpa_00000001.options.device, '@rpx_00000001', 'Native static address alias');
same(native.network.rpa_00000001.options.ipaddr, '10.78.1.2/32', 'No implicit connected subnet');
same(native.ipsec.rp_00000001.options.local_addrs, [ '0.0.0.0' ], 'IPv4 outer transport pinned');
same(native.ipsec.rp_00000001_child.options.local_ts, [ '0.0.0.0/0' ], 'Exit-node traffic selector');
same(native.ipsec.rp_00000001_child.options.remote_ts, [ '10.78.1.1/32' ], 'Cloud traffic selector');
same(native.ipsec.rp_00000001_child.options.start_action, 'start', 'Native initiate');
same(native.ipsec.rp_00000001_child.options.close_action, 'start', 'Remote DELETE reconnect');
same(native.ipsec.rp_00000001_child.options.dpd_action, 'restart', 'Dead-peer reconnect');
same(native.ipsec.rp_00000001_key.options.id, [ 'cloud-1' ], 'PSK bound to its remote identity only');
same(native.ipsec.rp_00000002_key.options.id, [ 'cloud-2' ], 'Peer PSK identities remain disjoint');
same(native.firewall.relay_ipsec_ike.options.src_ip, [ '198.51.100.1', '198.51.100.2' ], 'Literal endpoint IKE ACL');
same(native.firewall.relay_ipsec_esp.options.src_ip, [ '198.51.100.1', '198.51.100.2' ], 'Literal endpoint ESP ACL');
same(native.firewall.relay_ipsec_forward.options.dest, 'uplink', 'Reuse existing NAT uplink zone');
same(native.firewall.relay_ipsec_zone.options.input, 'REJECT', 'No automatic management exposure');

let visible = publicConfig(two);
assert(index(sprintf('%J', visible), 'synthetic-test-secret') < 0, 'No PSK disclosure');
assert(visible.peers[0].psk_set && visible.peers[1].psk_set, 'PSK presence only');
same(valid(visible, two).peers[0].psk, two.peers[0].psk, 'Omitted key preserves stored literal');
let emptyKey = clone(visible); emptyKey.peers[0].psk = '';
same(valid(emptyKey, two).peers[0].psk, two.peers[0].psk, 'Empty replacement preserves stored literal');
reject(one({ psk: '' }), 'key_required');
reject(one({ psk: 'short' }), 'key_required');
reject(one({ psk: 'secret-with-control\n' }), 'key_required');
let literal = valid(one({ psk: '0xliteral-secret-value' }));
same(plan(literal, 'uplink').ipsec.rp_00000001_key.options.secret,
    '0x30786c69746572616c2d7365637265742d76616c7565', '0x-prefixed PSK is literal UTF-8, not input hex');
let unicode = valid(one({ psk: '密钥密钥密钥密钥' }));
same(plan(unicode, 'uplink').ipsec.rp_00000001_key.options.secret,
    '0xe5af86e992a5e5af86e992a5e5af86e992a5e5af86e992a5', 'UTF-8 bytes preserved');

let renamed = clone(two); renamed.peers[0].name = 'Cosmetic rename';
same(changedPeers(two, renamed), [], 'Cosmetic update does not revoke SAs');
let rotated = clone(two); rotated.peers[0].psk = 'different-synthetic-key';
same(changedPeers(two, rotated), [ 'p00000001' ], 'PSK rotation revokes only affected peer');
let removed = clone(two); pop(removed.peers);
same(changedPeers(two, removed), [ 'p00000002' ], 'Deletion revokes only removed peer');
let disabled = clone(two); disabled.peers[0].enabled = false;
same(changedPeers(two, disabled), [ 'p00000001' ], 'Per-peer disable is isolated');
let off = clone(two); off.enabled = false;
same(changedPeers(two, off), [ 'p00000001', 'p00000002' ], 'Global disable revokes all managed peers');
let offPlan = plan(off, 'uplink');
assert(!!offPlan.network.rpx_00000001 && !!offPlan.network.rpb_00000001_0, 'Disabled routes stay protected');
same(offPlan.network.rpb_00000001_0.options.type, 'unreachable', 'Permanent fail-closed fallback');
same(offPlan.network.rpb_00000001_0.options.metric, '42760', 'Fallback less preferred than XFRM');
same(offPlan.ipsec.rp_00000001_key, null, 'Global-off does not load any PSK');
same(offPlan.firewall.relay_ipsec_ike.options.enabled, '0', 'Global-off closes inbound IKE ACL');

same(valid(one({ local_address: '10.78.1.2' })).peers[0].local_address, '10.78.1.2/32', 'Bare local IP normalized');
same(valid(one({ remote_subnets: [ '10.79.3.77/24' ] })).peers[0].remote_subnets,
    [ '10.79.3.0/24' ], 'Remote prefix canonicalized');
same(valid(one({ id: 'p7fffffff' })).peers[0].id, 'p7fffffff', 'INT32 maximum accepted');
same(plan(valid(one({ id: 'p7fffffff' })), 'uplink').network.rpx_7fffffff.options.ifid,
    '2147483647', 'Native if_id does not become INT64');
for (let id in [ 'p00000000', 'p80000000', 'pffffffff', 'pABCDEF01', 'rp_00001' ])
    reject(one({ id }), 'invalid_config');
for (let remote in [ '0.0.0.1', '127.0.0.1', '169.254.1.1', '224.0.0.1', '255.255.255.255',
    '192.168.001.1', '2001:db8::1', 'host.invalid\n}', '-host.invalid', 'host..invalid' ])
    reject(one({ remote }), 'invalid_config');
for (let address in [ '0.0.0.1/32', '127.0.0.1/32', '169.254.1.1/32', '224.0.0.1/32',
    '10.78.1.2/24', '10.78.1.2/32/32', '2001:db8::1/128' ])
    reject(one({ local_address: address }), 'route_conflict');
for (let identity in [ '0.0.0.0', '%any', '*', '"quoted"', 'host\nsecret', 'host }', 'host;value',
    '192.0.2.1-192.0.2.10' ]) {
    reject(one({ local_id: identity }), 'invalid_config');
    reject(one({ remote_id: identity }), 'invalid_config');
}
for (let route in [ '0.0.0.0/0', '0.0.0.1/32', '127.1.2.3/32', '169.254.1.2/32',
    '224.0.0.0/4', '10.78.1.2/32', '198.51.100.1/32', '10.0.0.0/33' ])
    reject(one({ remote_subnets: [ route ] }), 'route_conflict');
let identityConflict = { enabled: true, peers: [ peer(1), { ...peer(2), remote_id: '@CLOUD-1' } ] };
reject(identityConflict, 'identity_conflict');
reject(one({ local_id: '@CLOUD-1' }), 'identity_conflict');
reject({ enabled: true, peers: [ peer(1), { ...peer(2), local_id: '@CLOUD-1' } ] }, 'identity_conflict');
let sharedLocal = valid({ enabled: true, peers: [ { ...peer(1), local_id: 'relay' },
    { ...peer(2), local_id: 'relay' } ] });
same(length(sharedLocal.peers), 2, 'Peers may share one local identity');
same(plan(sharedLocal, 'uplink').ipsec.rp_00000002_key.options.id, [ 'cloud-2' ],
    'Shared local identity never enters another peer key owners');
same(valid(one({ remote_id: '@192.0.2.1-192.0.2.10' })).peers[0].remote_id,
    '@192.0.2.1-192.0.2.10', 'Explicit FQDN remains exact, not an IPv4 range');
reject({ enabled: true, peers: [ peer(1), { ...peer(2), local_address: '10.78.1.2/32' } ] }, 'route_conflict');
reject({ enabled: true, peers: [ peer(1), { ...peer(2), remote_subnets: [ '10.78.1.0/24' ] } ] }, 'route_conflict');
reject(one({ remote_subnets: [ '10.79.0.0/24', '10.79.0.1/32' ] }), 'route_conflict');
reject(one({}), 'route_conflict', { routes: [ '10.78.1.0/24' ] });
reject(one({}), 'route_conflict', { addresses: [ '10.78.1.200/24' ] });
reject(one({ local_address: '192.168.10.200/32' }), 'route_conflict', { addresses: [ '192.168.10.1/24' ] });
reject(one({ name: 'bad\nname' }), 'invalid_config');
reject(one({ mtu: 575 }), 'invalid_config');
reject(one({ mtu: 1501 }), 'invalid_config');
reject(one({ dpd_delay: 0 }), 'invalid_config');
reject(one({ dpd_delay: 30.5 }), 'invalid_config');
reject(one({ esp: 'unsafe;proposal' }), 'invalid_config');
for (let port in [ 500, 4500 ]) {
    reject(one({}), 'port_conflict', { wireguard_ports: [ port ] });
    reject({ enabled: true, peers: [] }, 'port_conflict', { wireguard_ports: [ port ] });
    same(valid({ enabled: false, peers: [ peer(1) ] }, null,
        { wireguard_ports: [ port ] }).enabled, false, 'Global off permits existing WG IKE port');
}
same(valid(one({}), null, { wireguard_ports: [ 51820 ] }).enabled, true,
    'Distinct WireGuard and IKE ports coexist');

let dnsPlan = plan(valid(one({ remote: 'CLOUD.Example.COM' })), 'uplink');
same(dnsPlan.ipsec.rp_00000001.options.remote_addrs, [ 'cloud.example.com' ], 'DNS endpoint normalized');
same(dnsPlan.firewall.relay_ipsec_ike.options.src_ip, null, 'Do not pass unsupported DNS src_ip to fw4');

let maximum = { enabled: true, peers: [] };
for (let i = 1; i <= 64; i++) {
    let routes = [];
    for (let r = 1; r <= 4; r++) push(routes, '10.90.' + i + '.' + r + '/32');
    push(maximum.peers, { ...peer(i), remote_subnets: routes });
}
same(length(valid(maximum).peers), 64, '64 peers / 256 total prefixes accepted');
let excessive = clone(maximum);
push(excessive.peers[0].remote_subnets, '10.90.1.5/32');
reject(excessive, 'invalid_config');
excessive.enabled = false;
for (let p in excessive.peers) p.enabled = false;
reject(excessive, 'invalid_config');
push(maximum.peers, peer(65));
reject(maximum, 'invalid_config');

let ids = [ 'ike-rp_00000001_key', 'ike-rp_00000002_key' ];
let inventory = 'get-shared reply {keys=[ike-rp_00000002_key ike-rp_00000001_key]}\n' +
    'load-shared reply {success=yes}\nload-shared reply {success=yes}\n';
assert(credentialInventory(inventory, ids), 'Exact private inventory with every load acknowledged');
assert(credentialInventory('get-shared reply {keys=[]}\n', []), 'Empty credentials acknowledged');
assert(!credentialInventory('', []), 'Missing enumeration not success');
assert(!credentialInventory('load-shared reply {success=yes}\n', [ ids[0] ]), 'Loads without inventory fail');
assert(!credentialInventory(inventory, [ ids[0] ]), 'Unexpected stale key fails');
assert(!credentialInventory(inventory + 'unload-shared reply {success=yes}\n', ids), 'Second pass must not need stale unload');
assert(!credentialInventory(inventory + 'load-shared reply {success=no}\n', ids), 'Individual failure cannot hide behind zero exit code');
assert(!credentialInventory(inventory + 'get-shared reply {keys=[]}\n', ids), 'Ambiguous duplicate inventory fails');
assert(!credentialInventory(replace(inventory, 'success=yes', 'success=no'), ids), 'Negative load acknowledgment fails');
assert(!credentialInventory(replace(inventory, 'keys=[', 'keys = ['), ids), 'Malformed inventory fails closed');

printf('IPsec pure model: %d assertions passed\n', assertions);
