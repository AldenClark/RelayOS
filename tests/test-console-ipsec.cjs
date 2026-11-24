#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'packages/luci-theme-relay/htdocs/luci-static/resources/relay/ipsec.js'), 'utf8');
const peer = { id: 'p00000001', name: 'Cloud 1', enabled: true, remote: '203.0.113.1',
  local_id: 'relay-1', remote_id: 'cloud-1', psk_set: true, local_address: '10.78.0.2/32',
  remote_subnets: [ '10.78.0.1/32' ], ike: 'aes128-sha256-modp2048', esp: 'aes128-sha256-noesn',
  dpd_delay: 30, mtu: 1400, state: 'established' };
const initial = { ok: true, revision: 'revision-1', enabled: true, ready: true, eip93: true, manual: true, peers: [ peer ], can_apply: true };
let current, agent, allowed, calls, nextError, applyWait, statusError, applyAllowed, accessError, accessCalls, randomValues = [];
const rpcOwners = {};
const clone = value => structuredClone(value);
const random = { getRandomValues(bytes) {
  if (randomValues.length) bytes.set(randomValues.shift());
  else webcrypto.getRandomValues(bytes);
  return bytes;
} };
const rpc = { declare(spec) {
  if (spec.object === 'session') {
    assert.equal(spec.method, 'access');
    assert.deepEqual(spec.params, [ 'scope', 'object', 'function' ]);
    assert.deepEqual(spec.expect, { access: false });
    return async (...args) => {
      assert.deepEqual(args, [ 'ubus', 'relay.ipsec', 'apply' ]);
      accessCalls.push(args);
      if (accessError) throw accessError;
      return applyAllowed;
    };
  }
  assert.equal(spec.object, 'relay.ipsec');
  rpcOwners[spec.method] = this;
  assert.ok([ 'get', 'apply' ].includes(spec.method));
  if (spec.method === 'apply') assert.deepEqual(spec.params, [ 'config' ]);
  return async config => {
    calls.push({ method: spec.method, config: clone(config) });
    if (spec.method === 'get') {
      if (statusError) throw statusError;
      return clone(current);
    }
    if (applyWait) await applyWait;
    if (nextError) return { ok: false, error: nextError };
    current = { ...current, enabled: config.enabled, revision: 'revision-2',
      peers: config.peers.map(p => {
        const clean = { ...p }; delete clean.psk;
        return { ...clean, psk_set: true, state: p.enabled && config.enabled ? 'down' : 'disabled' };
      }) };
    return clone(current);
  };
} };
class Node {
  constructor(tag, attrs = {}, children = []) {
    this.tag = tag; this.attrs = attrs; this.children = [];
    this.value = attrs.value ?? ''; this.checked = attrs.checked != null;
    this.disabled = !!attrs.disabled;
    for (const item of (Array.isArray(children) ? children : [ children ])) if (item != null) this.children.push(item);
  }
  appendChild(child) { this.children.push(child); return child; }
  setAttribute(key, value) { this.attrs[key] = value; }
  getAttribute(key) { return this.attrs[key]; }
  get textContent() { return this.children.map(c => c instanceof Node ? c.textContent : c).join(''); }
  set textContent(value) { this.children = [ value ]; }
  querySelectorAll(selector) {
    const result = [];
    for (const child of this.children) {
      if (!(child instanceof Node)) continue;
      const attribute = /^\[([^\]]+)\]$/.exec(selector)?.[1];
      if (attribute && attribute in child.attrs) result.push(child);
      result.push(...child.querySelectorAll(selector));
    }
    return result;
  }
}
const E = (tag, attrs, children) => new Node(tag, attrs, children);
const L = { hasViewPermission: () => allowed,
  dom: { content(node, children) { node.children = Array.isArray(children) ? children : [ children ]; } } };
const transports = [];
const request = { post: async (...args) => { transports.push(args); return 'transport result'; } };
rpc.getBaseURL = () => '/ubus/';
const mod = new Function('baseclass', 'rpc', 'request', 'agentState', 'E', 'L', '_', 'crypto', source)(
  { extend: value => value }, rpc, request, { status: async () => clone(agent) }, E, L, s => s, random);
function reset() {
  current = clone(initial); agent = { managed: false }; allowed = true;
  calls = []; nextError = null; applyWait = null; statusError = null;
  applyAllowed = true; accessError = null; accessCalls = []; randomValues = [];
}
function flat(node) { return [ node, ...node.children.flatMap(c => c instanceof Node ? flat(c) : []) ]; }
function cfg(peers = [ peer ]) { return { enabled: true, revision: initial.revision, peers: clone(peers) }; }
function requestPeer(p = peer) { const value = clone(p); delete value.state; delete value.psk_set; return value; }

async function run() {
  reset();
  assert.equal(rpcOwners.get, rpc);
  assert.notEqual(rpcOwners.apply, rpc);
  assert.equal(Object.getPrototypeOf(rpcOwners.apply), rpc);
  assert.equal(await rpcOwners.apply.call({ method: 'call' }, value => value), 'transport result');
  assert.deepEqual(transports, [ [ '/ubus/', { method: 'call' }, { timeout: 30000, nobatch: true, credentials: true } ] ]);
  assert.equal(Object.prototype.hasOwnProperty.call(rpc, 'call'), false);
  assert.deepEqual(await mod.status(), initial);
  assert.equal(accessCalls.length, 1);
  assert.equal(mod.decode({ ...initial, can_apply: true }).can_apply, undefined,
    'Backend data must not be trusted to grant session permissions');
  for (const permission of [ false, null, {}, 'true', 1 ]) {
    applyAllowed = permission;
    assert.equal((await mod.status()).can_apply, false);
  }
  accessError = new Error('private RPC detail');
  assert.equal((await mod.status()).can_apply, false);
  accessError = null; applyAllowed = true;
  assert.throws(() => mod.decode({ ok: false, error: 'unavailable' }), /unavailable/);
  for (const state of [ null, {}, { ...initial, manual: 1 }, { ...initial, revision: '' },
    { ...initial, peers: [ { ...peer, psk: 'must-not-be-returned' } ] },
    { ...initial, peers: [ peer, peer ] },
    ...[ 'p00000000', 'p80000000', 'pffffffff', 'p00000001\n', 'p00000001\u2028' ].map(id => ({ ...initial, peers: [ { ...peer, id } ] })) ])
    assert.throws(() => mod.decode(state));
  assert.equal(mod.decode({ ...initial, peers: [ { ...peer, id: 'p7fffffff' } ] }).peers[0].id, 'p7fffffff');
  const unexpected = mod.decode({ ...initial, secret: 'not allowed', peers: [ { ...peer, secret: 'not allowed' } ] });
  assert.equal(unexpected.secret, undefined); assert.equal(unexpected.peers[0].secret, undefined);
  assert.equal(mod.canChange(initial, agent, false), true);
  for (const [ state, owner, readonly ] of [ [ null, agent, false ], [ initial, null, false ],
    [ initial, {}, false ], [ initial, { managed: true }, false ], [ { ...initial, manual: false }, agent, false ],
    [ { ...initial, can_apply: false }, agent, false ], [ { ...initial, can_apply: undefined }, agent, false ],
    [ initial, agent, true ] ]) assert.equal(mod.canChange(state, owner, readonly), false);

  assert.equal(mod.validateConfig(cfg(), initial.peers), null);
  assert.equal(mod.validateConfig({ enabled: false, peers: [] }), null);
  const invalid = [
    [ 'id', 'p00000000', /identifiers/ ], [ 'id', 'p80000000', /identifiers/ ], [ 'id', 'pffffffff', /identifiers/ ],
    [ 'id', 'p00000001\n', /identifiers/ ], [ 'id', 'p00000001\u2029', /identifiers/ ],
    [ 'name', '', /name/ ], [ 'remote', '203.0.113.500', /hostname/ ],
    [ 'remote', '203.0.113.1\n', /hostname/ ], [ 'remote', 'cloud.example\n', /hostname/ ],
    [ 'remote', 'cloud.example\u2028', /hostname/ ], [ 'remote', 'clo\u007fud.example', /hostname/ ],
    [ 'remote', 'https://example.com', /hostname/ ], [ 'local_id', 'bad"\nsecrets {', /identities/ ],
    [ 'local_id', 'relay-1\n', /identities/ ], [ 'remote_id', 'cloud-1\r\n', /identities/ ],
    [ 'remote_id', 'cloud-1\u2029', /identities/ ],
    [ 'local_id', '0.0.0.0', /identities/ ], [ 'remote_id', '0.0.0.0', /identities/ ],
    [ 'local_id', '192.0.2.1-192.0.2.10', /identities/ ],
    [ 'remote_id', '192.0.2.1-192.0.2.10', /identities/ ],
    [ 'local_address', '10.78.0.2/24', /\/32/ ], [ 'remote_subnets', [], /1 to 32/ ],
    [ 'local_address', '10.78.0.2\n', /\/32/ ], [ 'local_address', '10.78.0.2/32\n', /\/32/ ],
    [ 'remote_subnets', [ '10.78.0.1/32\n' ], /CIDRs/ ],
    [ 'remote_subnets', [ '0.0.0.0/0' ], /default route/ ], [ 'remote_subnets', [ '::\/0' ], /CIDRs/ ],
    [ 'remote_subnets', [ '10.78.0.2/32' ], /local tunnel/ ],
    [ 'remote_subnets', [ '203.0.113.0/24' ], /endpoint/ ],
    [ 'remote_subnets', [ '10.79.0.0/24', '10.79.0.1/32' ], /overlap/ ],
    [ 'psk', 'short', /16 to 128/ ], [ 'psk', 'x'.repeat(129), /16 to 128/ ],
    [ 'ike', 'aes128-sha1-modp1024', /supported/ ], [ 'esp', 'invalid', /supported/ ],
    [ 'dpd_delay', 1, /DPD/ ], [ 'dpd_delay', 10.1, /DPD/ ], [ 'mtu', 575, /MTU/ ], [ 'mtu', 1501, /MTU/ ],
    [ 'remote', '0.1.2.3', /hostname/ ], [ 'remote', '127.0.0.1', /hostname/ ],
    [ 'local_address', '169.254.1.2/32', /\/32/ ], [ 'name', '密'.repeat(22), /64 UTF-8/ ]
  ];
  for (const [ key, value, pattern ] of invalid) assert.match(mod.validateConfig(cfg([ { ...peer, [key]: value } ]), initial.peers), pattern);
  assert.match(mod.validateConfig(cfg(), []), /new peer requires/);
  assert.equal(mod.validateConfig(cfg([ { ...peer, psk: '密钥'.repeat(4) } ]), []), null);
  const maxPeer = { ...peer, id: 'p7fffffff' };
  assert.equal(mod.validateConfig(cfg([ maxPeer ]), [ maxPeer ]), null);
  const second = { ...peer, id: 'p00000002', name: 'Cloud 2', local_id: 'relay-2', remote_id: 'cloud-2',
    remote: 'cloud2.example.com', local_address: '10.79.0.2/32', remote_subnets: [ '10.79.0.1/32' ],
    psk: 'test-key-0123456789abcdef' };
  assert.equal(mod.validateConfig(cfg([ peer, second ]), initial.peers), null);
  assert.match(mod.validateConfig(cfg([ peer, { ...second, remote_subnets: peer.remote_subnets } ]), initial.peers), /overlap/);
  assert.match(mod.validateConfig(cfg([ peer, { ...second, local_address: peer.local_address } ]), initial.peers), /different/);
  assert.match(mod.validateConfig(cfg([ peer, { ...second, remote_id: '@CLOUD-1' } ]), initial.peers), /remote IKE identity/);
  assert.match(mod.validateConfig(cfg([ { ...peer, local_address: peer.remote + '/32' } ]), initial.peers), /endpoint/);
  for (const conflictingPeers of [
    [ { ...peer, local_id: peer.remote_id } ],
    [ { ...peer, local_id: '@CLOUD-1' } ],
    [ { ...peer, local_id: second.remote_id }, second ],
    [ { ...peer, local_id: '@CLOUD-2' }, second ],
    [ peer, { ...second, local_id: '@CLOUD-1', enabled: false } ],
    [ { ...peer, remote_id: '@CLOUD-1' }, { ...second, local_id: 'cloud-1' } ]
  ]) assert.match(mod.validateConfig(cfg(conflictingPeers), initial.peers), /IKE identities conflict/);
  assert.equal(mod.validateConfig(cfg([ peer, { ...second, local_id: peer.local_id } ]), initial.peers), null,
    'Peers may share a local ID when no remote ID uses it');
  assert.equal(mod.validateConfig(cfg([ peer, { ...second, local_id: '@RELAY-1' } ]), initial.peers), null);
  for (const field of [ 'local_id', 'remote_id' ])
    assert.equal(mod.validateConfig(cfg([ { ...peer, [field]: '@192.0.2.1-192.0.2.10' } ]), initial.peers), null,
      '@ forces an exact FQDN identity rather than a strongSwan IPv4 range');

  const prefixBudgetPeers = Array.from({ length: 64 }, (_, i) => ({ ...peer,
    id: 'p' + (i + 1).toString(16).padStart(8, '0'), name: 'Cloud ' + i, enabled: i % 2 !== 0,
    remote: '192.0.2.' + (i + 1), local_id: 'relay-' + i, remote_id: 'cloud-' + i,
    local_address: '10.250.0.' + (i + 1) + '/32', psk: 'synthetic-prefix-budget-key',
    remote_subnets: Array.from({ length: 4 }, (_, j) => '10.128.' + i + '.' + (j + 1) + '/32') }));
  assert.equal(mod.validateConfig(cfg(prefixBudgetPeers)), null, '64 peers x 4 prefixes fits the resource budget');
  assert.equal(mod.validateConfig({ ...cfg(prefixBudgetPeers), enabled: false }), null);
  prefixBudgetPeers[0].remote_subnets.push('10.128.0.5/32');
  assert.equal(prefixBudgetPeers[0].enabled, false);
  assert.match(mod.validateConfig(cfg(prefixBudgetPeers)), /At most 256/,
    'Disabled peers must count toward the aggregate prefix budget');
  assert.match(mod.validateConfig({ ...cfg(prefixBudgetPeers), enabled: false }), /At most 256/);

  reset();
  const editor = mod.createEditor(initial, agent, false);
  assert.equal(editor.draft.peers[0].psk, '');
  editor.add(); editor.add();
  assert.equal(editor.draft.peers.length, 3);
  assert.equal(new Set(editor.draft.peers.map(p => p.id)).size, 3);
  assert.ok(editor.draft.peers.every(p => /^p[0-7][0-9a-f]{7}$/.test(p.id) && p.id !== 'p00000000'));
  assert.equal(calls.length, 0); // Draft operations must never mutate the device.
  editor.remove(editor.draft.peers[2].id); editor.remove(editor.draft.peers[1].id);
  editor.draft.peers[0].name = 'Renamed'; editor.change();
  assert.equal(await editor.apply(), true);
  assert.deepEqual(calls.map(c => c.method), [ 'get', 'apply' ]);
  const submitted = calls.at(-1).config;
  assert.equal(submitted.peers[0].psk, undefined);
  assert.equal(submitted.peers[0].psk_set, undefined);
  assert.equal(submitted.peers[0].state, undefined);
  assert.equal(editor.draft.peers[0].psk, '');
  assert.equal(editor.dirty, false);
  assert.equal(current.peers[0].name, 'Renamed');
  assert.equal(editor.writable(), true, 'Successful apply retains separately checked session permissions');
  assert.equal(accessCalls.length, 2, 'Apply checks method access before and after the transaction');

  reset();
  const boundedIds = mod.createEditor(initial, agent, false);
  randomValues = [ [ 0x80, 0, 0, 0 ], [ 0xff, 0xff, 0xff, 0xff ] ];
  boundedIds.add();
  assert.equal(boundedIds.draft.peers[1].id, 'p7fffffff', 'The high bit is cleared and zero is retried');
  randomValues = [ [ 0xff, 0xff, 0xff, 0xff ], [ 0x80, 0, 0, 1 ], [ 0x80, 0, 0, 2 ] ];
  boundedIds.add();
  assert.equal(boundedIds.draft.peers[2].id, 'p00000002', 'Collisions after high-bit masking are retried');
  assert.equal(randomValues.length, 0);

  reset();
  const rotate = mod.createEditor(initial, agent, false);
  rotate.draft.peers[0].psk = 'rotation-test-key-0123456789'; rotate.change();
  assert.equal(await rotate.apply(), true);
  assert.equal(calls.at(-1).config.peers[0].psk, 'rotation-test-key-0123456789');
  assert.equal(rotate.draft.peers[0].psk, '');
  assert.ok(!rotate.message.includes('rotation-test'));

  reset();
  const guarded = mod.createEditor(initial, agent, false);
  guarded.draft.enabled = false; guarded.change();
  agent = { managed: true };
  assert.equal(await guarded.apply(), false);
  assert.deepEqual(calls.map(c => c.method), [ 'get' ]);
  assert.equal(guarded.dirty, true); assert.match(guarded.message, /managed/);
  assert.equal(guarded.writable(), false);

  reset();
  const stale = mod.createEditor(initial, agent, false);
  stale.draft.peers[0].name = 'My unsaved draft'; stale.change();
  current.revision = 'another-writer'; current.peers[0].name = 'External change';
  assert.equal(await stale.refresh(), true);
  assert.equal(stale.draft.peers[0].name, 'My unsaved draft');
  assert.equal(stale.draft.revision, initial.revision);
  assert.equal(await stale.apply(), false);
  assert.ok(calls.every(c => c.method === 'get')); assert.match(stale.message, /changed elsewhere/);
  assert.equal(await stale.refresh(true), true);
  assert.equal(stale.draft.peers[0].name, 'External change'); assert.equal(stale.dirty, false);

  reset();
  const failing = mod.createEditor(initial, agent, false);
  failing.draft.peers[0].name = 'Retain me'; failing.change();
  nextError = 'route_conflict';
  assert.equal(await failing.apply(), false); assert.equal(failing.dirty, true);
  assert.equal(failing.draft.peers[0].name, 'Retain me'); assert.match(failing.message, /conflict/);
  nextError = 'port_conflict';
  assert.equal(await failing.apply(), false);
  assert.equal(failing.message, 'WireGuard and IPsec cannot use the same UDP listen ports (500 and 4500).');
  assert.equal(failing.draft.peers[0].name, 'Retain me'); assert.equal(failing.dirty, true);
  nextError = 'port_conflict: private backend diagnostic';
  assert.equal(await failing.apply(), false);
  assert.ok(!failing.message.includes('private backend diagnostic'));
  nextError = 'unexpected secret-value from server';
  await failing.apply(); assert.ok(!failing.message.includes('secret-value'));
  statusError = new Error('rpc leaked secret-value');
  await failing.apply(); assert.ok(!failing.message.includes('secret-value'));
  assert.equal(failing.busy, false);
  assert.equal(failing.writable(), false);
  assert.equal(failing.draft.peers[0].name, 'Retain me');
  statusError = null; await failing.refresh(); assert.equal(failing.writable(), true);

  reset();
  const concurrent = mod.createEditor(initial, agent, false);
  concurrent.draft.enabled = false; concurrent.change();
  let release;
  applyWait = new Promise(resolve => { release = resolve; });
  const first = concurrent.apply();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(concurrent.busy, true);
  assert.equal(await concurrent.apply(), false);
  concurrent.add(); assert.equal(concurrent.draft.peers.length, 1);
  release(); assert.equal(await first, true);
  assert.equal(calls.filter(c => c.method === 'apply').length, 1);

  reset();
  let networkBusy = true, gateEntries = 0;
  const coordination = { async run(operation) {
    if (networkBusy) throw Object.assign(new Error('Another network operation is in progress.'), { ipsecSafe: true });
    networkBusy = true; gateEntries++;
    try { return await operation(); }
    finally { networkBusy = false; }
  } };
  const coordinated = mod.createEditor(initial, agent, false, coordination);
  coordinated.draft.peers[0].name = 'Keep while network is busy'; coordinated.change();
  assert.equal(await coordinated.apply(), false);
  assert.deepEqual(calls, [], 'A competing network transaction blocks even the pre-apply status read');
  assert.match(coordinated.message, /Another network operation/);
  assert.equal(coordinated.busy, false); assert.equal(coordinated.dirty, true);
  assert.equal(coordinated.draft.peers[0].name, 'Keep while network is busy');
  assert.equal(await coordinated.refresh(), true, 'Read-only refresh does not acquire the network gate');
  assert.equal(gateEntries, 0); assert.equal(networkBusy, true);
  networkBusy = false; calls = [];
  let releaseGate;
  applyWait = new Promise(resolve => { releaseGate = resolve; });
  const gatedApply = coordinated.apply();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(networkBusy, true);
  assert.deepEqual(calls.map(call => call.method), [ 'get', 'apply' ]);
  await assert.rejects(coordination.run(async () => assert.fail('Network gate must remain held')), /Another network operation/);
  releaseGate(); assert.equal(await gatedApply, true); applyWait = null;
  assert.equal(networkBusy, false); assert.equal(gateEntries, 1);
  assert.equal(coordinated.dirty, false);
  coordinated.draft.peers[0].name = 'Retain after rejected application'; coordinated.change();
  nextError = 'route_conflict';
  assert.equal(await coordinated.apply(), false);
  assert.equal(networkBusy, false, 'Rejected applications also release the shared gate');
  assert.equal(coordinated.dirty, true);

  reset(); allowed = false;
  const readonly = mod.createEditor(initial, agent, false);
  readonly.add(); readonly.remove(peer.id); readonly.change();
  assert.equal(readonly.draft.peers.length, 1);
  assert.equal(await readonly.apply(), false); assert.equal(calls.length, 0);

  reset(); applyAllowed = false;
  const mixed = mod.createEditor(await mod.status(), agent, false);
  assert.equal(allowed, true, 'Other menu dependencies may grant page-wide write access');
  assert.equal(mixed.writable(), false);
  mixed.add(); mixed.remove(peer.id); mixed.change();
  assert.equal(mixed.draft.peers.length, 1);
  assert.equal(await mixed.apply(), false);
  assert.ok(calls.every(call => call.method === 'get'));
  applyAllowed = true; await mixed.refresh();
  assert.equal(mixed.writable(), true);
  mixed.draft.peers[0].name = 'Keep on access revocation'; mixed.change();
  applyAllowed = false;
  assert.equal(await mixed.apply(), false);
  assert.equal(mixed.writable(), false);
  assert.equal(mixed.draft.peers[0].name, 'Keep on access revocation');
  assert.match(mixed.message, /read-only/);
  assert.ok(calls.every(call => call.method === 'get'));
  applyAllowed = true; await mixed.refresh();
  accessError = new Error('unknown permission'); await mixed.refresh();
  assert.equal(mixed.writable(), false);
  assert.equal(mixed.draft.peers[0].name, 'Keep on access revocation');

  reset();
  const panel = mod.render(initial, agent, false);
  let nodes = flat(panel);
  assert.equal(nodes.filter(n => n.tag === 'input' && n.attrs.type === 'checkbox').length, 2);
  assert.ok(!nodes.some(n => n.tag === 'button' && /^(Enable|Disable) IPsec$/.test(n.textContent)));
  const secret = nodes.find(n => n.tag === 'input' && n.attrs.type === 'password');
  assert.equal(secret.value, ''); assert.equal(secret.attrs.autocomplete, 'new-password');
  assert.equal(nodes.find(n => n.tag === 'textarea').textContent, peer.remote_subnets[0]);
  assert.equal(nodes.find(n => n.attrs.type === 'submit').disabled, true);
  nodes.find(n => n.tag === 'button' && n.textContent === 'Add peer').attrs.click();
  nodes = flat(panel);
  assert.equal(nodes.filter(n => n.attrs['data-peer-id']).length, 2);
  assert.equal(nodes.find(n => n.attrs.type === 'submit').disabled, false);
  assert.equal(calls.length, 0);
  const noStatus = mod.render(null, null, false);
  assert.ok(noStatus.querySelectorAll('[data-ipsec-edit]').every(n => n.disabled));
  const escaped = mod.render({ ...initial, peers: [ { ...peer, name: '<img src=x onerror=alert(1)>' } ] }, agent, false);
  const heading = flat(escaped).find(n => n.tag === 'h3');
  assert.deepEqual(heading.children, [ '<img src=x onerror=alert(1)>' ]);
  assert.match(source, /E\('h3', \{ 'data-ipsec-name': peer\.id \}, \[ peer\.name/);

  const acl = JSON.parse(fs.readFileSync(path.join(root, 'packages/luci-theme-relay/root/usr/share/rpcd/acl.d/luci-theme-relay.json')));
  assert.deepEqual(acl['luci-relay-ipsec'].read, { ubus: { 'relay.ipsec': [ 'get' ] } });
  assert.deepEqual(acl['luci-relay-ipsec'].write, { ubus: { 'relay.ipsec': [ 'apply' ] } });
  assert.ok(!source.includes('ui.changes.apply'));
  assert.ok(!source.includes('fs.exec'));
  console.log('RelayOS IPsec UI: multi-peer drafts, toggles, redaction, validation, isolated RPC, stale/Agent/per-method ACL guards and retry preservation OK');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
