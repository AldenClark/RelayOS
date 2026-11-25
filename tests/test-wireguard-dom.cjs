#!/usr/bin/env node
'use strict';
// Native pinned LuCI form/UI/validation/UCI regression with disposable RPC data.
// Not a router or a browser/layout test; run explicitly with the same extra
// JSDOM_MODULE and LUCI_DIR dependencies as test-settings-dom.cjs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
assert.ok(process.env.JSDOM_MODULE, 'Set JSDOM_MODULE to the installed jsdom module');
assert.ok(process.env.LUCI_DIR, 'Set LUCI_DIR to the exact product-pinned LuCI checkout');
const { JSDOM, VirtualConsole } = require(process.env.JSDOM_MODULE);
const luciRoot = process.env.LUCI_DIR;
const pinned = /^src-git luci .*\^([0-9a-f]{40})$/m.exec(fs.readFileSync(path.join(root, 'feeds.conf'), 'utf8'))[1];
assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: luciRoot, encoding: 'utf8' }).trim(), pinned);
const upstream = ['luci', 'cbi', 'form', 'ui', 'validation', 'uci', 'rpc'].map(name => 'modules/luci-base/htdocs/luci-static/resources/' + name + '.js');
assert.equal(execFileSync('git', ['diff', 'HEAD', '--', ...upstream], { cwd: luciRoot, encoding: 'utf8' }), '');
const luci = path.join(luciRoot, 'modules/luci-base/htdocs/luci-static/resources');
const errors = [], keyCalls = [], applies = [], notices = [], unhandled = [];
const onUnhandled = error => unhandled.push(error);
process.on('unhandledRejection', onUnhandled);
const dom = new JSDOM('<!doctype html><html><head><title>RelayOS WireGuard form regression</title></head><body><main id="mount"></main></body></html>', {
  url: 'http://relayos.test/cgi-bin/luci/admin/relay/settings', runScripts: 'outside-only',
  virtualConsole: new VirtualConsole().on('jsdomError', error => errors.push(error.message))
});
const { window } = dom, { document } = window;
window.eval(fs.readFileSync(path.join(luci, 'luci.js'), 'utf8'));
window.eval(fs.readFileSync(path.join(luci, 'cbi.js'), 'utf8'));
window._ = text => text;
window.L = Object.create(window.LuCI.prototype);
window.L.hasViewPermission = () => true;
window.E = (...args) => window.L.dom.create(...args);
let writeAllowed = true, managed = false, busy = false, serial = 0, saves = 0, failWrites = true;
let wgInstances = {}, updateStatus;
const writes = [];
const db = { network: { lan: { '.name': 'lan', '.type': 'interface', '.index': 0, proto: 'dhcp' } },
  firewall: { up: { '.name': 'up', '.type': 'zone', '.index': 0, name: 'uplink', network: ['lan'], input: 'REJECT' } }, luci: {} };
const modules = {
  baseclass: window.LuCI.extend({ __init__() {} }), dom: window.L.dom,
  rpc: { declare: spec => async (...args) => {
    if (spec.object === 'session') return writeAllowed;
    if (spec.object === 'network.interface') return routeRpc.declare(spec)(...args);
    if (spec.method === 'getWgInstances') return wgInstances;
    if (spec.object === 'luci.wireguard') { keyCalls.push(args[0]); return { pub: 'PUBLIC:' + args[0] }; }
    if (spec.object === 'uci') {
      const [config, id, values, options] = args;
      if (spec.method === 'get') return structuredClone(db[config] || {});
      if (spec.method === 'changes') return {};
      writes.push({ method: spec.method, args: structuredClone(args) });
      if (failWrites) throw new Error('Injected remote UCI write failure');
      if (spec.method === 'add') {
        const name = values || 'cfg' + (++serial);
        assert.equal(db[config][name], undefined, 'Remote section must not be created twice');
        db[config][name] = { ...structuredClone(options), '.name': name, '.type': id, '.index': Object.keys(db[config]).length };
        return name;
      }
      if (spec.method === 'set') Object.assign(db[config][id], structuredClone(values));
      if (spec.method === 'delete') {
        if (values) values.forEach(option => { delete db[config][id][option]; });
        else delete db[config][id];
      }
      return 0;
    }
    return {};
  } },
  request: {}, session: { getLocalData: () => null, setLocalData() {} },
  poll: { add(fn) { updateStatus = fn; }, remove() {} }, fs: {},
  agentState: { assertManual: async () => { if (managed) throw new Error('Agent managed'); } }
};
function load(name, dir = luci) {
  const names = Object.keys(modules);
  const Class = new window.Function(...names, fs.readFileSync(path.join(dir, name + '.js'), 'utf8'))(...names.map(name => modules[name]));
  return new Class();
}
modules.request.post = async (_url, message) => {
  assert.deepEqual(Array.from(message.params.slice(1, 3)), ['network.interface', 'dump']);
  const reply = { jsonrpc: '2.0', id: message.id, result: [0, { interface: [
    { interface: 'lan', 'ipv4-address': [{ address: '192.168.1.3', mask: 24 }] }
  ] }] };
  return { ok: true, json: () => window.JSON.parse(JSON.stringify(reply)) };
};
const routeRpc = load('rpc');
modules.validation = load('validation');
modules.uci = load('uci');
const nativeSave = modules.uci.save;
modules.uci.save = function() { saves++; return nativeSave.call(this); };
modules.ui = load('ui');
const nativeNotice = modules.ui.addNotification;
modules.ui.addNotification = function(title, content, ...args) {
  notices.push(content.textContent);
  return nativeNotice.call(this, title, content, ...args);
};
window.L.ui = modules.ui;
window.L.require = async name => {
  assert.equal(name, 'ui');
  return modules.ui;
};
modules.form = load('form');
modules.ui.changes.apply = async confirmed => { applies.push(confirmed); };
const wg = load('wg-config', path.join(root, 'packages/luci-theme-relay/htdocs/luci-static/resources/relay'));
const tick = () => new Promise(resolve => setImmediate(resolve));
async function flush() {
  for (let i = 0; i < 8; i++) await tick();
  await new Promise(resolve => window.requestAnimationFrame(resolve));
}
async function draftFailure(operation, message) {
  const count = notices.length;
  assert.equal(await operation(), false);
  assert.equal(notices.length, count + 1);
  assert.match(notices.at(-1), message);
}
function button(title) {
  const matches = [...document.querySelectorAll('button')].filter(node => node.textContent === title);
  assert.equal(matches.length, 1, title);
  return matches[0];
}
function input(id, option) { return document.getElementById('widget.cbid.network.' + id + '.' + option); }
function fill(id, option, value) {
  const node = input(id, option);
  assert.ok(node, id + '.' + option);
  node.value = value;
  node.dispatchEvent(new window.Event('change', { bubbles: true }));
  node.dispatchEvent(new window.Event('blur', { bubbles: true }));
}
let map;
async function mount() {
  const node = await wg.render({ onMap: value => { map = value; }, coordination: {
    run: async operation => { if (busy) throw new Error('Another operation is busy'); return operation(); }
  } });
  document.querySelector('#mount').replaceChildren(node);
}
async function run() {
  try {
    await modules.uci.load(['network', 'firewall']);
    modules.uci.set('network', 'lan', 'hostname', 'unsaved-management-name');
    await mount();
    assert.equal(document.title, 'RelayOS WireGuard form regression');
    assert.equal(document.location.pathname, '/cgi-bin/luci/admin/relay/settings');
    assert.equal(button('Add interface').disabled, false);
    button('Add interface').click();
    await flush();
    assert.equal(saves, 0, 'Creation must remain local even when remote UCI writes would fail');
    assert.equal(modules.uci.get('network', 'wg0', 'listen_port'), '51820', 'Native parse must not erase creation defaults');
    assert.equal(db.network.wg0, undefined, 'Creating an incomplete tunnel cannot flush it or unrelated changes to UCI');
    assert.equal(db.network.lan.hostname, undefined);
    assert.equal(modules.uci.get('network', 'lan', 'hostname'), 'unsaved-management-name');
    assert.equal(input('wg0', 'listen_port').value, '51820');
    assert.equal(document.querySelector('#cbi-relay-wireguard > .cbi-section > h3'), null);
    assert.equal(button('Delete interface').disabled, false);
    assert.equal(button('Delete interface').closest('.ar-wg-heading').querySelector('h2').textContent, 'WireGuard');
    assert.equal(input('wg0', 'private_key').type, 'password');
    const section = map.children[0], peers = section.getOption('_peers').subsection;
    button('Add peer').click();
    await flush();
    assert.match(notices.at(-1), /invalid input value/);
    assert.deepEqual(unhandled, [], 'Invalid native Add click must show an error without unhandled rejection');
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 0, 'Failed form validation must not leave an invisible peer');
    const privateKey = Buffer.alloc(32, 1).toString('base64');
    fill('wg0', 'private_key', privateKey);
    await flush();
    assert.equal(keyCalls.at(-1), privateKey, 'Native onchange argument order must send the actual key');
    assert.equal(input('wg0', '_public_key').value, 'PUBLIC:' + privateKey);
    fill('wg0', 'private_key', '');
    await flush();
    assert.equal(input('wg0', '_public_key').value, '');
    fill('wg0', 'private_key', privateKey);
    fill('wg0', 'addresses', '010.077.000.002/255.255.255.0');
    await peers.handleAdd();
    assert.equal(modules.uci.get('network', 'wg0', 'addresses')[0], '10.77.0.2/24');
    const first = modules.uci.sections('network', 'wireguard_wg0')[0]['.name'];
    assert.equal(modules.uci.get('network', first, 'route_allowed_ips'), '1');
    assert.equal(modules.uci.get('network', first, 'persistent_keepalive'), '25');
    assert.equal(document.querySelectorAll('.cbi-value[data-name="_peers"] .cbi-section-remove').length, 0);
    await draftFailure(() => peers.handleAdd(), /invalid input value/);
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 1);
    fill(first, 'public_key', Buffer.alloc(32, 2).toString('base64'));
    fill(first, 'allowed_ips', '010.077.000.001/255.255.255.255');
    fill(first, 'endpoint_host', '192.000.002.001');
    fill(first, 'endpoint_port', '0');
    await draftFailure(() => peers.handleAdd(), /invalid input value/);
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 1, 'Port zero must not silently remove the endpoint at runtime');
    fill(first, 'endpoint_port', '51820');
    busy = true;
    const before = JSON.stringify(modules.uci.state);
    await draftFailure(() => peers.handleAdd(), /busy/);
    assert.equal(JSON.stringify(modules.uci.state), before);
    busy = false;
    await peers.handleAdd();
    assert.equal(modules.uci.get('network', first, 'allowed_ips')[0], '10.77.0.1/32');
    assert.equal(modules.uci.get('network', first, 'endpoint_host'), '192.0.2.1');
    assert.equal(modules.uci.get('network', 'lan', 'hostname'), 'unsaved-management-name');
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 2);
    const second = modules.uci.sections('network', 'wireguard_wg0').find(peer => peer['.name'] !== first)['.name'];
    const peerTitle = id => document.getElementById('cbi-network-' + id).querySelector('h4');
    assert.equal(peerTitle(first).textContent, 'Peer 1');
    assert.equal(peerTitle(second).textContent, 'Peer 2');
    assert.ok(peerTitle(first).parentElement.querySelector('button[data-section-id="' + first + '"]'));
    assert.ok(peerTitle(second).parentElement.querySelector('button[data-section-id="' + second + '"]'));
    fill(first, 'description', 's1');
    assert.equal(peerTitle(first).textContent, 's1');
    fill(first, 'description', '');
    assert.equal(peerTitle(first).textContent, 'Peer 1');
    const peerBadge = id => document.querySelector(`[data-wg-peer="${id}"]`);
    wgInstances = { wg0: { peers: [{
      public_key: modules.uci.get('network', first, 'public_key'),
      latest_handshake: String(Math.floor(Date.now() / 1000) - 2)
    }] } };
    await updateStatus();
    assert.equal(peerBadge(first).textContent, 'Recent handshake');
    assert.ok(peerBadge(first).classList.contains('is-up'));
    assert.equal(peerBadge(second).textContent, 'Peer not active');
    wgInstances.wg0.peers[0].latest_handshake = '0';
    await updateStatus();
    assert.equal(peerBadge(first).textContent, 'No handshake yet');
    assert.ok(!peerBadge(first).classList.contains('is-up'));
    wgInstances.wg0.peers[0].latest_handshake = String(Math.floor(Date.now() / 1000) - 181);
    await updateStatus();
    assert.equal(peerBadge(first).textContent, 'No recent handshake');
    wgInstances = null;
    await updateStatus();
    assert.equal(peerBadge(first).textContent, 'Status unavailable');
    fill('wg0', 'private_key', 'invalid-key');
    const beforeRejectedRemoval = JSON.stringify(modules.uci.state);
    await draftFailure(() => peers.handleRemove(second), /invalid input value/);
    assert.equal(JSON.stringify(modules.uci.state), beforeRejectedRemoval, 'Rejected removal must leave the target peer in the draft');
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 2);
    fill('wg0', 'private_key', privateKey);
    // The removed peer itself is incomplete and must not block deletion.
    await peers.handleRemove(second);
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 1);
    await draftFailure(() => peers.handleRemove(first), /at least one peer/);
    assert.equal(saves, 0);
    assert.deepEqual(writes, [], 'Local structural edits must never trigger native global UCI save');
    for (const [id, field, invalid] of [
      ['wg0', 'addresses', 'invalid-address'],
      [first, 'allowed_ips', '0.0.0.0/0'],
      [first, 'allowed_ips', '10.78.0.0/255.0.255.0']
    ]) {
      fill(id, field, invalid);
      await assert.rejects(map.parse(), /invalid input value/);
      await draftFailure(() => peers.handleAdd(), /invalid input value/);
      assert.match(notices.at(-1), invalid === '0.0.0.0/0' ? /default route/ : /valid IPv4 address or prefix/);
      assert.equal(input(id, field).value, invalid, 'An invalid pending list item must remain visible for correction');
      assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 1);
      fill(id, field, '');
    }
    await map.parse();
    const enabled = section.getOption('_peers').subsection.getOption('disabled').getUIElement(first);
    assert.equal(enabled.getValue(), '0');
    enabled.setValue('1');
    await map.parse();
    assert.throws(() => wg.validate(['wg0']), /at least one enabled peer/);
    enabled.setValue('0');
    await map.parse();
    wg.validate(['wg0']);
    // The explicit full save still submits the local creation and canonical
    // values exactly once, and preserves the unrelated management draft.
    fill(first, 'endpoint_host', 'peer.example.com');
    failWrites = false;
    await map.save(() => wg.prepare(map));
    assert.equal(saves, 1);
    assert.equal(db.network.wg0.addresses[0], '10.77.0.2/24');
    assert.equal(Object.values(db.network).find(peer => peer['.type'] === 'wireguard_wg0').endpoint_host, 'peer.example.com');
    assert.equal(db.network.lan.hostname, 'unsaved-management-name');
    assert.equal(Object.values(db.network).filter(peer => peer['.type'] === 'wireguard_wg0').length, 1);
    assert.equal(input('wg0', 'private_key').value, privateKey);
    const persisted = modules.uci.sections('network', 'wireguard_wg0')[0]['.name'];
    await peers.handleAdd();
    const replacement = modules.uci.sections('network', 'wireguard_wg0').find(peer => peer['.name'] !== persisted)['.name'];
    fill(replacement, 'public_key', Buffer.alloc(32, 3).toString('base64'));
    fill(replacement, 'allowed_ips', '10.77.0.3/32');
    await map.save(() => wg.prepare(map));
    const beforeDeletionWrites = writes.length;
    modules.uci.set('network', 'lan', 'hostname', 'preserve-through-local-deletion');
    failWrites = true;
    fill('wg0', 'addresses', 'invalid-address');
    await draftFailure(() => peers.handleRemove(persisted), /invalid input value/);
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 2);
    assert.equal(input('wg0', 'addresses').value, 'invalid-address');
    fill('wg0', 'addresses', '');
    await peers.handleRemove(persisted);
    assert.equal(modules.uci.sections('network', 'wireguard_wg0').length, 1);
    assert.ok(db.network[persisted], 'Deleting a persisted peer is local until Save & Apply');
    assert.equal(writes.length, beforeDeletionWrites);
    assert.equal(modules.uci.get('network', 'lan', 'hostname'), 'preserve-through-local-deletion');
    failWrites = false;
    await map.save(() => wg.prepare(map));
    assert.equal(db.network[persisted], undefined, 'The explicit save submits the pending deletion');
    assert.equal(Object.values(db.network).filter(peer => peer['.type'] === 'wireguard_wg0').length, 1);
    assert.equal(db.network.lan.hostname, 'preserve-through-local-deletion');
    assert.deepEqual(applies, [], 'Editing the draft must not apply it');
    managed = true;
    button('Add peer').click();
    await flush();
    assert.match(notices.at(-1), /Agent managed/);
    assert.deepEqual(unhandled, [], 'Denied native Add click must not produce an unhandled rejection');
    managed = false;
    const guard = modules.agentState.assertManual;
    const hostileError = '<img data-wg-error="injected" src="missing">';
    modules.agentState.assertManual = async () => { throw new Error(hostileError); };
    await draftFailure(() => peers.handleAdd(), /data-wg-error/);
    assert.equal(document.querySelector('img[data-wg-error]'), null, 'Draft errors must render as text');
    assert.ok(document.body.textContent.includes(hostileError));
    modules.agentState.assertManual = guard;
    const finalPeer = modules.uci.sections('network', 'wireguard_wg0')[0]['.name'];
    modules.uci.set('network', finalPeer, 'disabled', 'true');
    await mount();
    const finalPeers = map.children[0].getOption('_peers').subsection;
    assert.equal(finalPeers.getOption('disabled').getUIElement(finalPeer).getValue(), '0', 'WireGuard only treats peer disabled=1 as disabled');
    await map.parse();
    assert.equal(modules.uci.get('network', finalPeer, 'disabled'), '0', 'Rendering disabled=true must not silently disable a working peer');
    wg.validate(['wg0']);
    const tunnel = map.children[0];
    const tunnelToggle = tunnel.getOption('disabled').getUIElement('wg0').node.querySelector('input[type=checkbox]');
    const key = input('wg0', 'private_key').value;
    const endpoint = modules.uci.get('network', finalPeer, 'endpoint_host');
    fill(finalPeer, 'public_key', 'invalid-draft-key');
    tunnelToggle.click();
    await flush();
    for (const name of ['private_key', '_public_key', 'addresses', 'listen_port', '_peers'])
      assert.equal(tunnel.getOption(name).isActive('wg0'), false, name);
    assert.equal(button('Save & Apply').disabled, false);
    await map.parse();
    assert.equal(modules.uci.get('network', 'wg0', 'private_key'), key);
    assert.equal(modules.uci.get('network', finalPeer, 'endpoint_host'), endpoint);
    tunnelToggle.click();
    await flush();
    assert.equal(tunnel.getOption('_peers').isActive('wg0'), true);
    assert.equal(input(finalPeer, 'public_key').value, 'invalid-draft-key');
    await assert.rejects(map.parse(), /invalid input value/);
    modules.uci.set('network', 'wg0', 'disabled', 'true');
    await mount();
    assert.equal(map.children[0].getOption('disabled').getUIElement('wg0').getValue(), '1', 'netifd disabled=true must render as disabled');
    assert.equal(map.children[0].getOption('_peers').isActive('wg0'), false);
    await map.parse();
    assert.equal(modules.uci.get('network', 'wg0', 'disabled'), '1', 'An unrelated edit must keep a disabled=true tunnel disabled');
    // Add a distinct interface on a populated device. An unrelated UCI
    // section occupying wg1 must not be changed or adopted as a tunnel.
    modules.uci.add('network', 'interface', 'wg1');
    modules.uci.set('network', 'wg1', 'proto', 'static');
    const writesBeforeInterface = writes.length;
    button('Add interface').click();
    await flush();
    assert.equal(writes.length, writesBeforeInterface);
    assert.equal(db.network.wg2, undefined);
    assert.equal(modules.uci.get('network', 'wg1', 'proto'), 'static');
    assert.equal(input('wg2', 'listen_port').value, '', 'An additional interface must not inherit port 51820');
    assert.equal(input('wg2', 'private_key').value, '');
    assert.equal(input('wg0', 'private_key').value, privateKey);
    assert.deepEqual([...document.querySelectorAll('#cbi-relay-wireguard > .cbi-section > .ar-wg-heading > h3')].map(h => h.textContent), ['wg0', 'wg2']);
    const nextKey = Buffer.alloc(32, 4).toString('base64');
    fill('wg2', 'private_key', nextKey);
    fill('wg2', 'addresses', '10.76.0.2/32');
    await map.children[1].getOption('_peers').subsection.handleAdd();
    const nextPeer = modules.uci.sections('network', 'wireguard_wg2')[0]['.name'];
    fill(nextPeer, 'public_key', Buffer.alloc(32, 5).toString('base64'));
    fill(nextPeer, 'allowed_ips', '10.76.0.1/32');
    fill(nextPeer, 'endpoint_host', 'second.example.com');
    await map.save(() => wg.prepare(map));
    assert.equal(db.network.wg2.private_key, nextKey);
    assert.equal(db.network.wg0.private_key, privateKey);
    assert.equal(Object.values(db.network).find(peer => peer['.type'] === 'wireguard_wg2').endpoint_host, 'second.example.com');
    assert.ok(Object.values(db.firewall).some(zone => zone['.type'] === 'zone' && zone.network.includes('wg2')));
    const removeButton = id => {
      const card = document.getElementById('cbi-network-' + id).parentElement;
      return (card.querySelector(':scope > .ar-wg-heading') ?? map.root.querySelector(':scope > .ar-wg-heading'))
        .querySelector('.cbi-section-remove button');
    };
    assert.equal(removeButton('wg2').closest('.ar-wg-heading').querySelector('h3').textContent, 'wg2');
    const removeWG2 = () => removeButton('wg2').click();
    const confirmDelete = () => [...document.querySelectorAll('#modal_overlay button')]
      .find(node => node.textContent === 'Delete interface').click();
    removeWG2();
    assert.match(document.querySelector('#modal_overlay').textContent, /wg2 and its peers/);
    button('Cancel').click();
    assert.ok(modules.uci.get('network', 'wg2'));

    map.children[0].getOption('disabled').getUIElement('wg0').node.querySelector('input[type=checkbox]').click();
    await flush();
    const beforeDelete = writes.length;
    fill('wg0', 'private_key', 'invalid-other-key');
    removeWG2();
    confirmDelete();
    await flush();
    assert.match(notices.at(-1), /invalid input value/);
    assert.ok(modules.uci.get('network', 'wg2'), 'Invalid edits on another interface must prevent deletion');
    assert.equal(writes.length, beforeDelete);
    fill('wg0', 'private_key', privateKey);
    fill('wg2', 'private_key', 'invalid-removed-key');
    modules.uci.add('firewall', 'rule', 'airrelay_wg_wg2');
    modules.uci.set('firewall', 'airrelay_wg_wg2', 'name', 'AirRelay WireGuard wg2');
    modules.uci.add('firewall', 'rule', 'custom_wg2');
    modules.uci.set('firewall', 'custom_wg2', 'name', 'Manual rule');
    removeWG2();
    confirmDelete();
    await flush();
    assert.equal(modules.uci.get('network', 'wg2'), null);
    assert.equal(modules.uci.sections('network', 'wireguard_wg2').length, 0);
    assert.equal(modules.uci.get('firewall', 'airrelay_wg_wg2'), null);
    assert.ok(modules.uci.get('firewall', 'custom_wg2'));
    assert.ok(db.network.wg2);
    assert.equal(writes.length, beforeDelete, 'Interface deletion remains local until Save & Apply');
    await map.save(() => wg.prepare(map));
    assert.equal(db.network.wg2, undefined);
    assert.equal(Object.values(db.network).filter(peer => peer['.type'] === 'wireguard_wg2').length, 0);
    assert.ok(db.firewall.custom_wg2);
    assert.ok(Object.values(db.firewall).some(zone => zone['.type'] === 'zone' && zone.network?.includes('wg0')));
    assert.ok(!Object.values(db.firewall).some(zone => zone['.type'] === 'zone' && zone.network?.includes('wg2')));
    writeAllowed = false;
    await mount();
    assert.equal(input('wg0', 'private_key').disabled, true);
    assert.ok([...document.querySelectorAll('button')].filter(node => node.textContent === 'Add peer').every(node => node.disabled));
    assert.equal(button('Add interface').disabled, true);
    assert.equal(button('Save & Apply').disabled, true);
    assert.equal(removeButton('wg0').disabled, true);
    writeAllowed = true;
    await mount();
    removeButton('wg0').click();
    confirmDelete();
    await flush();
    assert.equal(map.children.length, 0);
    assert.ok(db.network.wg0);
    button('Save & Apply').click();
    await flush();
    assert.equal(db.network.wg0, undefined);
    assert.deepEqual(applies, [true]);
    assert.deepEqual(errors, []);
    console.log('RelayOS native WireGuard form/UCI: local drafts, canonical addresses, ports, enabled peers, validation, key derivation, gate and ACL passed');
  } finally { window.close(); process.off('unhandledRejection', onUnhandled); }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
