#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../packages/luci-theme-relay/htdocs/luci-static/resources');
let db, calls, permissions, modal, current, statusError, managed, prepareError, captured, pending;
let readonlyView = false;
const document = { body: { classList: { contains: name => name === 'modal-overlay-active' && modal } } };
const L = { hasViewPermission: () => !readonlyView };
const E = (tag, attrs, children) => ({ tag, attrs, children });
const rpc = { declare: spec => async (_scope, object) => spec.object === 'session' ? permissions[object] : [] };
const uci = {
  load: async () => {},
  changes: async () => pending,
  get: (config, id, key) => key == null ? db[config]?.[id] : db[config]?.[id]?.[key],
  sections: (config, type) => Object.entries(db[config] || {}).filter(([, value]) => !type || value['.type'] === type)
    .map(([id, value]) => ({ ...value, '.name': id })),
  save: async () => { calls.push('uci.save'); }
};
const agentState = { status: async () => ({ managed }), assertManual: async () => {
  if (managed) throw new Error('Agent owns WireGuard');
} };
function load(file, dependencies) {
  return new Function(...Object.keys(dependencies), fs.readFileSync(path.join(root, file), 'utf8'))(...Object.values(dependencies));
}
const wg = load('relay/wg-config.js', { baseclass: { extend: value => value }, form: {}, uci, ui: {}, rpc,
  agentState, L, E, _: value => value });
const wgConfig = {
  subnet: wg.subnet,
  async render(options) {
    captured.wg = options;
    const map = new Map('network');
    map.kind = 'wireguard'; map.readonly = !permissions.network || !permissions.firewall;
    options.onMap(map);
    return E('section');
  },
  async prepare(map, routes, ports) {
    calls.push('wireguard.prepare'); captured.routes = routes; captured.ports = ports;
    await agentState.assertManual();
    if (!permissions.network || !permissions.firewall) throw new Error('WireGuard settings are read-only.');
    if (prepareError) throw prepareError;
  }
};
class Map {
  constructor() { this.kind = 'network'; }
  section() { return { option: () => ({ value() {}, depends() {} }) }; }
  checkDepends() { calls.push(this.kind + '.depends'); }
  async parse() { calls.push(this.kind + '.parse'); if (this.parseError) throw this.parseError; }
  async load() { calls.push(this.kind + '.load'); }
  async renderContents() { calls.push(this.kind + '.render'); return E('div'); }
  async render() { return E('div'); }
}
const ipsec = {
  async status() { calls.push('ipsec.status'); if (statusError) throw statusError; return current; },
  render(_state, _agent, _readonly, coordination) { captured.ipsec = coordination; return E('section'); }
};
const ui = {
  // The actual pinned LuCI apply API shows a synchronous modal and returns
  // undefined; it does not return its internal apply/confirmation promise.
  changes: { apply(checked) { assert.equal(checked, true); calls.push('native.apply'); modal = true; } },
  createHandlerFn: (context, method) => () => context[method]()
};
const settings = load('view/relay/settings.js', { view: { extend: value => value }, form: { Map }, uci, ui, rpc,
  systemManager: { render: () => E('section') }, agentState, wgConfig, ipsec, L, E, document, _: value => value });

async function reset() {
  db = { network: { lan: { '.type': 'interface', proto: 'dhcp' } } };
  calls = []; captured = {}; pending = {}; permissions = { network: true, firewall: true };
  modal = false; statusError = null; prepareError = null; managed = false; readonlyView = false;
  current = { enabled: false, peers: [] }; settings._networkBusy = false;
  const data = await settings.load(); await settings.render(data); calls = [];
}
async function noSave(operation, pattern) {
  await assert.rejects(operation, pattern);
  assert.ok(!calls.includes('uci.save'));
  assert.ok(!calls.includes('native.apply'));
}

async function run() {
  await reset();
  assert.equal(captured.wg.coordination, captured.ipsec, 'Every mutating editor must share the same gate');
  current = { enabled: true, peers: [ { enabled: false, local_address: '10.78.1.2/32', remote_subnets: [ '10.78.1.1/32' ] } ] };
  await captured.wg.onApply();
  assert.deepEqual(calls, [ 'network.depends', 'network.parse', 'wireguard.depends', 'wireguard.parse',
    'ipsec.status', 'wireguard.prepare', 'uci.save', 'network.load', 'network.render',
    'wireguard.load', 'wireguard.render', 'native.apply' ]);
  assert.deepEqual(captured.routes, [ '10.78.1.2/32', '10.78.1.1/32' ], 'Include disabled IPsec protected routes');
  assert.deepEqual(captured.ports, [ 500, 4500 ]);
  assert.equal(settings._networkBusy, false);
  await assert.rejects(captured.ipsec.run(async () => { throw new Error('Must not start during native apply'); }), /Another network operation/);
  modal = false;
  assert.equal(await captured.ipsec.run(async () => 'after cancel or completion'), 'after cancel or completion');

  await reset();
  settings._wireguardMap.parseError = new Error('Incomplete peer draft');
  await noSave(settings.handleApply(), /Incomplete peer draft/);
  assert.ok(calls.includes('network.parse') && calls.includes('wireguard.parse'), 'LAN button validates WG draft');
  await reset();
  settings._networkMap.parseError = new Error('Invalid LAN address');
  await noSave(captured.wg.onApply(), /Invalid LAN address/);
  await reset(); prepareError = new Error('Route conflict');
  await noSave(settings.handleApply(), /Route conflict/);
  await reset(); managed = true;
  await noSave(settings.handleApply(), /Agent owns WireGuard/);

  await reset(); permissions.network = false;
  await noSave(settings.handleApply(), /Network settings are read-only/);
  assert.ok(!calls.includes('network.parse'), 'Revoked ACL is checked before parsing or staging');
  const data = await settings.load(); await settings.render(data);
  assert.equal(settings._networkMap.readonly, true, 'Other page write ACLs cannot unlock network fields');
  assert.equal(settings.renderApplyButton().attrs.disabled, true);

  await reset(); managed = true;
  await settings.render(await settings.load()); calls = [];
  assert.equal(settings._wireguardMap, null);
  pending = { network: [ [ 'remove', 'old_wireguard_peer' ] ] };
  await noSave(settings.handleApply(), /Discard pending network and firewall changes/);
  assert.ok(!calls.includes('network.parse'), 'Hidden staged peers are blocked before LAN parsing');
  pending = {}; await settings.handleApply();
  assert.ok(calls.includes('native.apply'), 'An Agent does not prohibit clean LAN-only edits');
  await reset(); settings._wireguardMap.readonly = true;
  pending = { firewall: [ [ 'set', 'airrelay_wg_wg0', 'dest_port', '500' ] ] };
  await noSave(settings.handleApply(), /Discard pending network and firewall changes/);

  await reset();
  let release;
  const waiting = captured.ipsec.run(() => new Promise(resolve => { release = resolve; }));
  await noSave(settings.handleApply(), /Another network operation/);
  await assert.rejects(captured.wg.coordination.run(async () => { throw new Error('Must not add a peer'); }), /Another network operation/);
  release(); await waiting;
  assert.equal(settings._networkBusy, false);
  await assert.rejects(captured.ipsec.run(async () => { throw new Error('Failed IPsec apply'); }), /Failed IPsec apply/);
  assert.equal(settings._networkBusy, false, 'Failed operations release the gate');

  await reset(); statusError = new Error('Current IPsec status unavailable');
  await noSave(settings.handleApply(), /Current IPsec status unavailable/);
  await reset();
  db.network.lan = { '.type': 'interface', proto: 'static', ipaddr: '10.78.1.200', netmask: '255.255.255.0' };
  current.peers = [ { enabled: false, local_address: '10.78.1.2/32', remote_subnets: [ '10.78.1.1/32' ] } ];
  await noSave(settings.handleApply(), /management subnet conflicts/);
  await reset();
  db.network.lan = { '.type': 'interface', proto: 'static', ipaddr: '10.77.0.200', netmask: '255.255.255.0' };
  db.network.wg0 = { '.type': 'interface', proto: 'wireguard', addresses: [ '10.77.0.2/32' ] };
  await noSave(settings.handleApply(), /management subnet conflicts/);
  await reset();
  db.network.lan = { '.type': 'interface', proto: 'static', ipaddr: '10.90.0.200', netmask: '255.255.255.0' };
  db.network.wg0 = { '.type': 'interface', proto: 'wireguard', addresses: [ '10.77.0.2/32' ] };
  db.network.peer = { '.type': 'wireguard_wg0', allowed_ips: [ '10.90.0.1/32' ] };
  await noSave(settings.handleApply(), /management subnet conflicts/);
  await reset();
  db.network.lan = { '.type': 'interface', proto: 'static', ipaddr: '192.168.1.20', netmask: '255.0.255.0' };
  await noSave(settings.handleApply(), /contiguous subnet mask/);
  await reset();
  db.network.lan = { '.type': 'interface', proto: 'static', ipaddr: '192.168.1.20', netmask: '255.255.255.0' };
  await settings.handleApply();
  assert.ok(calls.includes('native.apply'));
  assert.deepEqual(captured.ports, [], 'Disabled IPsec does not reserve listener ports');
  console.log('RelayOS Settings: shared form validation, fresh tunnel conflicts, ACL and native apply modal coordination OK');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
